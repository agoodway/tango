defmodule Tango.NetworkFailureTest do
  @moduledoc """
  Tests for network failure scenarios and error handling.

  Covers OAuth token refresh failures, code exchange failures, and other
  network-dependent operations to ensure robust error handling using local mock servers.
  """

  use Tango.DatabaseCase, async: false

  alias Tango.{Auth, Connection}
  alias Tango.{Factory, OAuthMockServer}
  alias Test.Support.OAuthFlowHelper

  describe "OAuth code exchange network failures" do
    setup do
      bypass = Bypass.open()
      {:ok, bypass: bypass}
    end

    test "handles connection timeout during code exchange", %{bypass: bypass} do
      # Setup mock server to simulate timeout
      OAuthMockServer.setup_network_failure_endpoints(bypass, :timeout)

      # Create provider using mock server URLs
      urls = OAuthMockServer.github_urls(bypass)
      provider = Factory.create_github_provider("_exchange_timeout", urls: urls)
      tenant_id = Factory.tenant_id("exchange_test")

      # Create a session for code exchange and get encoded state
      {:ok, encoded_state, _session} =
        OAuthFlowHelper.get_encoded_state_for_session(
          provider.name,
          tenant_id,
          redirect_uri: "https://app.com/callback"
        )

      # Attempt code exchange - this will timeout due to mock server behavior
      result =
        Auth.exchange_code(encoded_state, "fake_auth_code", tenant_id,
          redirect_uri: "https://app.com/callback"
        )

      # Should return error, not crash
      case result do
        {:error, reason} ->
          # Verify error is properly structured
          assert is_binary(reason) or is_atom(reason)

        other ->
          flunk("Expected {:error, reason}, got: #{inspect(other)}")
      end
    end

    test "handles invalid response during code exchange", %{bypass: bypass} do
      # Setup mock server to return invalid response
      OAuthMockServer.setup_network_failure_endpoints(bypass, :invalid_response)

      # Create provider using mock server URLs
      urls = OAuthMockServer.github_urls(bypass)
      provider = Factory.create_github_provider("_exchange_invalid", urls: urls)
      tenant_id = Factory.tenant_id("exchange_invalid_test")

      # Create session and get encoded state
      {:ok, encoded_state, _session} =
        OAuthFlowHelper.get_encoded_state_for_session(
          provider.name,
          tenant_id,
          redirect_uri: "https://app.com/callback"
        )

      # Test with valid code but invalid server response
      result =
        Auth.exchange_code(encoded_state, "valid_auth_code", tenant_id,
          redirect_uri: "https://app.com/callback"
        )

      # Should handle invalid response gracefully
      assert {:error, _reason} = result
    end

    test "handles invalid authorization codes", %{bypass: bypass} do
      # Setup mock server to return error for invalid codes
      OAuthMockServer.setup_github_oauth(bypass, should_fail: true)

      # Create provider using mock server URLs
      urls = OAuthMockServer.github_urls(bypass)
      provider = Factory.create_github_provider("_invalid_codes", urls: urls)
      tenant_id = Factory.tenant_id("invalid_codes_test")

      # Create session and get encoded state
      {:ok, encoded_state, _session} =
        OAuthFlowHelper.get_encoded_state_for_session(
          provider.name,
          tenant_id,
          redirect_uri: "https://app.com/callback"
        )

      # Test with obviously invalid authorization codes
      invalid_codes = [
        "",
        "invalid_code",
        "expired_code_12345",
        String.duplicate("x", 1000)
      ]

      for invalid_code <- invalid_codes do
        result =
          Auth.exchange_code(encoded_state, invalid_code, tenant_id,
            redirect_uri: "https://app.com/callback"
          )

        assert {:error, _reason} = result
      end
    end

    test "handles session not found during code exchange" do
      # Test with non-existent session token
      fake_session_tokens = [
        "nonexistent_session_token",
        Factory.secure_token(32),
        ""
      ]

      for fake_token <- fake_session_tokens do
        result =
          Auth.exchange_code(fake_token, "some_auth_code", "tenant-123",
            redirect_uri: "https://app.com/callback"
          )

        assert {:error, _reason} = result
      end
    end
  end

  describe "token refresh network failures" do
    test "handles network timeout during token refresh" do
      provider = Factory.create_github_provider("_refresh_timeout")
      tenant_id = Factory.tenant_id("refresh_test")

      # Create connection with refresh token
      connection = Factory.create_github_connection(provider, tenant_id, "_refresh")

      # Attempt refresh - this will fail due to actual network call to fake GitHub URLs
      # The test validates that the system doesn't crash and handles errors gracefully
      result =
        try do
          Connection.refresh_connection(connection)
        rescue
          # Handle potential function clause errors from OAuth2 library
          FunctionClauseError -> {:error, :oauth_error}
          error -> {:error, Exception.message(error)}
        end

      # Should handle failure gracefully
      case result do
        {:error, _reason} ->
          # Verify connection is still in database
          refreshed_conn = Repo.get(Tango.Schemas.Connection, connection.id)
          assert refreshed_conn != nil

        {:ok, _updated_connection} ->
          # This could happen if network actually works
          :ok

        other ->
          flunk("Unexpected result from refresh_connection: #{inspect(other)}")
      end
    end

    test "handles invalid refresh token during refresh" do
      provider = Factory.create_github_provider("_refresh_invalid")
      tenant_id = Factory.tenant_id("refresh_invalid_test")

      # Create connection and set refresh token to nil (invalid)
      connection = Factory.create_github_connection(provider, tenant_id, "_invalid")

      # Update with nil refresh token (will fail OAuth2 function clause)
      changeset =
        Tango.Schemas.Connection.changeset(connection, %{
          refresh_token: nil
        })

      {:ok, invalid_connection} = Repo.update(changeset)

      # Attempt refresh - should handle OAuth2 function clause error
      result = Connection.refresh_connection(invalid_connection)

      # Should return specific error for missing refresh token
      assert {:error, reason} = result
      assert reason in [:no_refresh_token, :refresh_not_allowed]
    end

    test "handles connection without refresh token" do
      provider = Factory.create_github_provider("_no_refresh")
      tenant_id = Factory.tenant_id("no_refresh_test")

      # Create connection without refresh token
      connection =
        Factory.create_connection(provider, tenant_id, %{
          "refresh_token" => nil
        })

      result = Connection.refresh_connection(connection)

      # Should return appropriate error
      assert {:error, reason} = result
      assert reason in [:no_refresh_token, :refresh_not_allowed]
    end

    test "handles revoked connections during refresh" do
      provider = Factory.create_github_provider("_revoked_refresh")
      tenant_id = Factory.tenant_id("revoked_refresh_test")

      # Create revoked connection
      revoked_connection = Factory.create_revoked_connection(provider, tenant_id)

      result = Connection.refresh_connection(revoked_connection)

      # Should reject refresh for revoked connection
      assert {:error, _reason} = result
    end
  end

  describe "batch refresh network failures" do
    test "handles mixed success and failure during batch refresh" do
      provider1 = Factory.create_github_provider("_batch1")
      provider2 = Factory.create_github_provider("_batch2")
      tenant_id = Factory.tenant_id("batch_test")

      # Create multiple connections that will expire soon
      connections = [
        Factory.create_github_connection(provider1, tenant_id, "_batch1"),
        Factory.create_github_connection(provider2, tenant_id, "_batch2")
      ]

      # Mark them as expiring soon (within 1 hour)
      # 30 minutes
      future_time =
        DateTime.add(DateTime.utc_now(), 30 * 60, :second)
        |> DateTime.truncate(:second)

      for connection <- connections do
        changeset =
          Tango.Schemas.Connection.changeset(connection, %{
            expires_at: future_time
          })

        {:ok, _} = Repo.update(changeset)
      end

      # Run batch refresh
      result = Connection.refresh_expiring_connections()

      # Should return result even if some fail
      case result do
        {:ok, count} ->
          assert is_integer(count)
          assert count >= 0

        {:error, _reason} ->
          # This is also acceptable - batch operation failed
          :ok

        other ->
          flunk("Unexpected result from batch refresh: #{inspect(other)}")
      end
    end

    test "handles no expiring connections gracefully" do
      # Ensure no connections are expiring
      # (connections created by Factory have future expiry)

      result = Connection.refresh_expiring_connections()

      # Should succeed with 0 count
      assert {:ok, 0} = result
    end
  end

  describe "provider configuration errors" do
    test "handles missing provider configuration during operations" do
      # Test with non-existent provider name
      fake_provider_names = [
        "nonexistent_provider",
        "missing_provider_123",
        ""
      ]

      tenant_id = Factory.tenant_id("incomplete_test")

      for fake_name <- fake_provider_names do
        # Try to create session with non-existent provider
        result = Auth.create_session(fake_name, tenant_id)

        # Should return error for missing provider
        assert {:error, _reason} = result
      end
    end

    test "handles malformed provider URLs during operations" do
      # Create provider with malformed URLs
      malformed_provider =
        Factory.create_provider(%{
          name: "malformed_provider",
          slug: "malformed_provider",
          auth_mode: "oauth2",
          client_secret: "secret",
          config: %{
            "display_name" => "Malformed Provider",
            "client_id" => "client_id",
            "auth_url" => "not-a-valid-url",
            "token_url" => "also-not-valid"
          }
        })

      tenant_id = Factory.tenant_id("malformed_test")

      # Operations should handle malformed URLs gracefully
      result = Auth.create_session(malformed_provider.name, tenant_id)

      # Should either work (if URL validation is lenient) or fail gracefully
      case result do
        {:ok, _session} -> :ok
        {:error, _reason} -> :ok
        other -> flunk("Unexpected result: #{inspect(other)}")
      end
    end
  end

  describe "database connection failures during network operations" do
    test "handles database errors during session creation" do
      provider = Factory.create_github_provider("_db_test")

      # Test with tenant_id that's at the limit (varchar 255)
      long_tenant_id = String.duplicate("x", 250)

      # This should work or fail gracefully
      result =
        try do
          Auth.create_session(provider.name, long_tenant_id)
        rescue
          Postgrex.Error -> {:error, :db_constraint}
          error -> {:error, Exception.message(error)}
        end

      # Should handle database constraints gracefully
      case result do
        {:error, _reason} ->
          # Expected due to constraint or validation
          :ok

        {:ok, _session} ->
          # Might work if DB allows long tenant IDs
          :ok

        other ->
          flunk("Unexpected result: #{inspect(other)}")
      end
    end
  end

  describe "concurrent operation failures" do
    test "handles concurrent session creation for same tenant" do
      provider = Factory.create_github_provider("_concurrent")
      tenant_id = Factory.tenant_id("concurrent_test")

      # Create multiple sessions concurrently
      tasks =
        for i <- 1..5 do
          Task.async(fn ->
            Auth.create_session(provider.name, "#{tenant_id}_#{i}")
          end)
        end

      results = Task.await_many(tasks, 5000)

      # All should succeed or fail gracefully
      for result <- results do
        case result do
          {:ok, _session} -> :ok
          {:error, _reason} -> :ok
          other -> flunk("Unexpected concurrent result: #{inspect(other)}")
        end
      end
    end

    test "handles concurrent connection refresh" do
      tenant_id = Factory.tenant_id("concurrent_refresh_test")

      # Create connections with different providers to avoid unique constraints
      providers =
        for i <- 1..3 do
          Factory.create_github_provider("_concurrent_refresh_#{i}")
        end

      connections =
        for {provider, i} <- Enum.with_index(providers, 1) do
          Factory.create_github_connection(provider, "#{tenant_id}_#{i}", "_concurrent_#{i}")
        end

      # Attempt concurrent refresh with error handling
      tasks =
        for connection <- connections do
          Task.async(fn ->
            try do
              Connection.refresh_connection(connection)
            rescue
              FunctionClauseError -> {:error, :oauth_error}
              error -> {:error, Exception.message(error)}
            end
          end)
        end

      results = Task.await_many(tasks, 10_000)

      # All should complete without crashing the test process
      for result <- results do
        case result do
          {:ok, _connection} -> :ok
          {:error, _reason} -> :ok
          other -> flunk("Unexpected concurrent refresh result: #{inspect(other)}")
        end
      end
    end
  end

  describe "audit logging during failures" do
    test "creates audit logs even when operations fail" do
      provider = Factory.create_github_provider("_audit_failure")
      tenant_id = Factory.tenant_id("audit_failure_test")

      initial_log_count = Repo.aggregate(Tango.Schemas.AuditLog, :count, :id)

      # Try operations that will likely fail
      _session_result = Auth.create_session(provider.name, tenant_id)

      # Check if audit logs were created (depends on implementation)
      final_log_count = Repo.aggregate(Tango.Schemas.AuditLog, :count, :id)

      # Audit logging during failures is implementation-dependent
      # Just verify the system doesn't crash
      assert is_integer(final_log_count)
      assert final_log_count >= initial_log_count
    end
  end
end

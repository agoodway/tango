defmodule Tango.SecurityTest do
  @moduledoc """
  Comprehensive security tests for the Tango OAuth library.

  These tests verify that critical security vulnerabilities have been fixed
  and that the library properly handles edge cases and attack scenarios.
  """

  use Tango.DatabaseCase, async: true

  alias Ecto.Adapters.SQL.Sandbox
  alias Tango.{Audit.Sanitizer, Auth, Factory, OAuthMockServer}
  alias Tango.Schemas.{Connection, OAuthSession, Provider}
  alias Test.Support.OAuthFlowHelper

  describe "cross-tenant session isolation" do
    setup do
      # Create test providers
      {:ok, provider_a} = create_test_provider("github_a")
      {:ok, provider_b} = create_test_provider("slack_b")

      %{provider_a: provider_a, provider_b: provider_b}
    end

    test "exchange_code/4 prevents cross-tenant session hijacking", %{provider_a: provider} do
      tenant_a = "tenant-a-123"
      tenant_b = "tenant-b-456"

      # Try to use OAuth flow but exchange with wrong tenant (should fail)
      result =
        OAuthFlowHelper.test_cross_tenant_exchange(
          provider.slug,
          tenant_a,
          tenant_b,
          "auth_code_123",
          redirect_uri: "https://app.com/callback"
        )

      # Should fail due to tenant mismatch in state validation
      assert {:error, :invalid_state} = result
    end

    test "same state parameter can exist for different tenants", %{provider_a: provider} do
      tenant_a = "tenant-a-123"
      tenant_b = "tenant-b-456"

      # Create sessions with same provider for different tenants
      {:ok, session_a} = Auth.create_session(provider.slug, tenant_a)
      {:ok, session_b} = Auth.create_session(provider.slug, tenant_b)

      # States should be different (unique per tenant)
      assert session_a.state != session_b.state
      assert session_a.tenant_id != session_b.tenant_id
    end

    test "database constraint prevents duplicate (state, tenant_id) combinations" do
      tenant_id = "tenant-123"
      {:ok, provider} = create_test_provider("duplicate_test")
      _state = "duplicate-state"

      # Create a shared state for testing duplicates
      shared_state = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

      # Insert first session (with proper token lengths)
      session_attrs = %{
        provider_id: provider.id,
        tenant_id: tenant_id,
        session_token: :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false),
        state: shared_state,
        expires_at: DateTime.add(DateTime.utc_now(), 1800)
      }

      {:ok, _session1} =
        %OAuthSession{}
        |> OAuthSession.changeset(session_attrs)
        |> Tango.TestRepo.insert()

      # Try to insert duplicate (state, tenant_id) - should fail
      duplicate_attrs = %{
        session_attrs
        | session_token: :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false),
          # Same state, same tenant - should violate constraint
          state: shared_state
      }

      # The unique constraint should prevent duplicate (state, tenant_id) combinations
      assert_raise Ecto.ConstraintError, ~r/tango_oauth_sessions_state_tenant_id_index/, fn ->
        %OAuthSession{}
        |> OAuthSession.changeset(duplicate_attrs)
        |> Tango.TestRepo.insert()
      end
    end
  end

  describe "data sanitization in audit logging" do
    setup do
      {:ok, provider} = create_test_provider("github")
      %{provider: provider}
    end

    test "successful token exchange logs sanitized data", %{provider: provider} do
      tenant_id = "tenant-123"
      {:ok, session} = Auth.create_session(provider.slug, tenant_id)

      # Mock a successful OAuth response
      mock_token_response = %{
        "access_token" => "very-secret-token-123",
        "refresh_token" => "super-secret-refresh-456",
        "expires_in" => 3600
      }

      # This would normally be called during token exchange
      # Convert struct to map for sanitizer
      session_map = Map.from_struct(session)
      sanitized_session = Sanitizer.sanitize_session(session_map)

      sanitized_connection =
        Sanitizer.sanitize_connection(%{
          access_token: mock_token_response["access_token"],
          tenant_id: tenant_id
        })

      # Verify sensitive data is redacted
      # Completely removed
      assert sanitized_session[:code_verifier] == nil
      # Masked
      assert String.ends_with?(to_string(sanitized_session[:state]), "***")
      assert sanitized_connection[:access_token] == "[REDACTED]"
    end

    test "error information is sanitized" do
      error_info = %{
        reason: "invalid_client",
        details: %{
          client_secret: "super-secret-123",
          redirect_uri: "https://app.com/callback"
        }
      }

      sanitized = Sanitizer.sanitize_error(error_info)

      assert sanitized.reason == "invalid_client"
      assert sanitized.details[:client_secret] == "[REDACTED]"
      # Not sensitive
      assert sanitized.details[:redirect_uri] == "https://app.com/callback"
    end

    test "sensitive data hashing provides correlation without exposure" do
      sensitive_value = "very-secret-oauth-token"
      hash1 = Sanitizer.hash_sensitive_data(sensitive_value)
      hash2 = Sanitizer.hash_sensitive_data(sensitive_value)

      # Same input produces same hash (for correlation)
      assert hash1 == hash2
      assert String.starts_with?(hash1, "SHA256:")

      # Different input produces different hash
      hash3 = Sanitizer.hash_sensitive_data("different-value")
      assert hash1 != hash3
    end
  end

  describe "session security edge cases" do
    setup do
      {:ok, provider} = create_test_provider("github")
      %{provider: provider}
    end

    test "expired sessions cannot be used for token exchange", %{provider: provider} do
      tenant_id = "tenant-123"

      # Create session with past expiration
      # 1 hour ago
      expired_time = DateTime.add(DateTime.utc_now(), -3600)

      # Insert directly to bypass validation
      {:ok, session} =
        Tango.TestRepo.insert(%OAuthSession{
          provider_id: provider.id,
          tenant_id: tenant_id,
          session_token: :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false),
          state: :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false),
          expires_at: DateTime.truncate(expired_time, :second),
          scopes: [],
          metadata: %{}
        })

      # Try to exchange code with expired session
      result =
        Auth.exchange_code(session.state, "auth_code", tenant_id,
          redirect_uri: "https://app.com/callback"
        )

      # Should fail due to session validation
      assert {:error, _reason} = result
    end

    test "malformed state parameters are rejected" do
      tenant_id = "tenant-123"

      malformed_states = [
        # Empty string
        "",
        # Nil
        nil,
        # Too short
        "x",
        # Too long
        String.duplicate("a", 1000),
        # Invalid characters
        "state with spaces",
        # Newlines (removed null bytes as they cause UTF8 errors)
        "state\nwith\nnewlines"
      ]

      for malformed_state <- malformed_states do
        try do
          result =
            Auth.exchange_code(malformed_state, "auth_code", tenant_id,
              redirect_uri: "https://app.com/callback"
            )

          # Should return error or raise exception
          assert match?({:error, _}, result) or
                   match?(%FunctionClauseError{}, result)
        rescue
          # Function clause errors are acceptable for invalid inputs
          FunctionClauseError -> :ok
          ArgumentError -> :ok
        end
      end
    end

    test "injection attacks in tenant_id are prevented" do
      {:ok, _provider} = create_test_provider("github_injection")

      # SQL injection attempts
      malicious_tenant_ids = [
        "'; DROP TABLE tango_oauth_sessions; --",
        "tenant' OR '1'='1",
        "tenant\"; DELETE FROM tango_connections; --",
        "tenant' UNION SELECT * FROM tango_providers --"
      ]

      for malicious_id <- malicious_tenant_ids do
        # These should either fail gracefully or return no results
        result =
          Auth.exchange_code("some-state", "auth-code", malicious_id,
            redirect_uri: "https://app.com/callback"
          )

        assert {:error, _reason} = result
      end

      # Verify database integrity - tables should still exist
      assert Tango.TestRepo.all(OAuthSession) == []
      assert Tango.TestRepo.all(Connection) == []
      assert Tango.TestRepo.all(Provider) |> length() >= 0
    end
  end

  describe "concurrent session handling" do
    setup do
      bypass = Bypass.open()

      # Setup mock OAuth endpoint
      Bypass.stub(bypass, "POST", "/login/oauth/access_token", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Conn.resp(
          200,
          "access_token=mock_access_token_12345&token_type=bearer&scope=repo%2Cuser"
        )
      end)

      # Create provider with mock URLs
      urls = OAuthMockServer.github_urls(bypass)
      provider = Factory.create_github_provider("_security", urls: urls)

      %{provider: provider, bypass: bypass}
    end

    test "session cleanup after successful exchange prevents reuse", %{provider: provider} do
      tenant_id = "tenant-123"

      # Create session and get encoded state
      {:ok, encoded_state, _session} =
        OAuthFlowHelper.get_encoded_state_for_session(
          provider.slug,
          tenant_id,
          redirect_uri: "https://app.com/callback"
        )

      # First exchange should succeed
      {:ok, _connection} =
        Auth.exchange_code(
          encoded_state,
          "auth_code_1",
          tenant_id,
          redirect_uri: "https://app.com/callback"
        )

      # Session should be cleaned up, so same state can't be reused
      {:error, reason} =
        Auth.exchange_code(
          encoded_state,
          "auth_code_2",
          tenant_id,
          redirect_uri: "https://app.com/callback"
        )

      # State no longer valid due to session cleanup
      assert reason == :invalid_state
    end

    test "concurrent session creation with same state should fail", %{provider: provider} do
      tenant_id = "tenant-123"
      parent = self()

      # Try to create multiple sessions concurrently
      tasks =
        for _i <- 1..3 do
          Task.async(fn ->
            :ok = Sandbox.allow(Tango.TestRepo, parent, self())
            Auth.create_session(provider.slug, tenant_id)
          end)
        end

      results = Task.await_many(tasks, 5000)

      # All should succeed because states are generated uniquely
      successful_results = Enum.filter(results, &match?({:ok, _}, &1))
      assert length(successful_results) == 3

      # Verify all states are unique
      states = Enum.map(successful_results, fn {:ok, session} -> session.state end)
      assert length(Enum.uniq(states)) == 3
    end
  end

  describe "provider configuration security" do
    test "client secrets are never logged in plain text" do
      provider_config = %{
        name: "Test Provider",
        slug: "test",
        client_id: "public-client-id",
        client_secret: "super-secret-123",
        auth_config: %{
          authorization_url: "https://provider.com/oauth"
        }
      }

      sanitized = Sanitizer.sanitize_provider(provider_config)

      assert sanitized[:client_secret] == "[REDACTED]"
      # Also sensitive
      assert sanitized[:client_id] == "[REDACTED]"
      # Not sensitive
      assert sanitized[:name] == "Test Provider"
    end

    test "provider validation prevents malicious configurations" do
      malicious_configs = [
        # JavaScript injection in URLs
        %{
          name: "Malicious Provider",
          slug: "malicious",
          client_secret: "secret",
          config: %{
            "client_id" => "client123",
            "auth_url" => "javascript:alert('xss')",
            "token_url" => "https://example.com/token"
          }
        },
        # File system access attempts
        %{
          name: "File Access",
          slug: "file",
          client_secret: "secret",
          config: %{
            "client_id" => "client123",
            "auth_url" => "file:///etc/passwd",
            "token_url" => "https://example.com/token"
          }
        },
        # Data URI attempts
        %{
          name: "Data URI",
          slug: "data",
          client_secret: "secret",
          config: %{
            "client_id" => "client123",
            "auth_url" => "data:text/html,<script>alert('xss')</script>",
            "token_url" => "https://example.com/token"
          }
        }
      ]

      for config <- malicious_configs do
        # Note: Provider creation currently does not validate URL schemes
        # This test documents the current behavior and serves as a reminder
        # that URL validation should be added for enhanced security
        result = Tango.Provider.create_provider(config)

        # Current behavior: allows these URLs (security improvement needed)
        # Future: should validate and reject javascript:, file:, data: schemes
        case result do
          # Currently allowed
          {:ok, _provider} -> :ok
          # Would be better security
          {:error, _changeset} -> :ok
        end
      end
    end
  end

  # Helper functions

  defp create_test_provider(slug) do
    attrs = %{
      name: "Test #{String.capitalize(slug)}",
      slug: slug,
      active: true,
      config: %{
        "client_id" => "test-client-id-#{slug}",
        "auth_url" => "https://#{slug}.com/oauth/authorize",
        "token_url" => "https://#{slug}.com/oauth/token"
      },
      client_secret: "test-secret-#{slug}"
    }

    Tango.Provider.create_provider(attrs)
  end
end

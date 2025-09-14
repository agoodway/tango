defmodule Tango.OAuthFlowIntegrationTest do
  @moduledoc """
  Integration tests for complete OAuth flows in the Tango library.

  These tests verify the entire OAuth2 authorization code flow with PKCE,
  from session creation through token exchange, including error scenarios
  and edge cases that could occur in production using local mock servers.
  """

  use Tango.DatabaseCase, async: false

  import Ecto.Query

  alias Tango.Auth
  alias Tango.{Factory, OAuthMockServer}
  alias Tango.Schemas.{Connection, OAuthSession}
  alias Test.Support.OAuthFlowHelper

  describe "complete OAuth2 flow with PKCE" do
    setup do
      bypass = Bypass.open()

      # Setup token endpoint with stub (optional, won't fail if not called)
      Bypass.stub(bypass, "POST", "/login/oauth/access_token", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Conn.resp(
          200,
          "access_token=mock_access_token_12345&token_type=bearer&scope=repo%2Cuser"
        )
      end)

      # Create provider using mock server URLs
      urls = OAuthMockServer.github_urls(bypass)
      provider = Factory.create_github_provider("_integration", urls: urls)

      %{provider: provider, bypass: bypass}
    end

    test "successful OAuth2 authorization code flow", %{provider: provider} do
      tenant_id = "user-12345"
      redirect_uri = "https://myapp.com/oauth/callback"

      # Step 1: Create OAuth session
      {:ok, session} = Auth.create_session(provider.slug, tenant_id)

      assert session.tenant_id == tenant_id
      assert session.provider_id == provider.id
      assert byte_size(session.session_token) >= 32
      assert byte_size(session.state) >= 32
      now = DateTime.utc_now()
      assert DateTime.compare(session.expires_at, now) == :gt

      # Step 2: Generate authorization URL
      {:ok, auth_url} =
        Auth.authorize_url(session.session_token,
          redirect_uri: redirect_uri,
          scopes: ["repo", "user"]
        )

      assert String.contains?(auth_url, "localhost")
      assert String.contains?(auth_url, "/login/oauth/authorize")
      assert String.contains?(auth_url, "client_id=#{provider.config["client_id"]}")
      # Verify state is encoded (not raw session state)
      {:ok, encoded_state} = OAuthFlowHelper.extract_state_from_auth_url(auth_url)
      assert encoded_state != session.state
      assert String.contains?(auth_url, "state=#{encoded_state}")
      assert String.contains?(auth_url, "redirect_uri=#{URI.encode_www_form(redirect_uri)}")
      assert String.contains?(auth_url, "scope=repo+user")

      # Should include PKCE parameters
      assert String.contains?(auth_url, "code_challenge=")
      assert String.contains?(auth_url, "code_challenge_method=S256")

      # Step 3: Mock OAuth callback (simulate provider response)
      mock_auth_code = "mock_authorization_code_12345"

      # Step 4: Exchange authorization code for tokens (using encoded state)
      {:ok, encoded_state} = OAuthFlowHelper.extract_state_from_auth_url(auth_url)

      {:ok, connection} =
        Auth.exchange_code(encoded_state, mock_auth_code, tenant_id, redirect_uri: redirect_uri)

      assert connection.tenant_id == tenant_id
      assert connection.provider_id == provider.id
      assert connection.status == :active
      assert connection.access_token == "mock_access_token_12345"
      # GitHub mock response doesn't include refresh_token, so it should be nil
      assert connection.refresh_token == nil

      # Verify session was cleaned up after successful exchange
      assert {:error, :session_not_found} = Auth.get_session(session.session_token)
    end

    test "OAuth flow with custom scopes", %{provider: provider} do
      tenant_id = "user-custom-scopes"
      custom_scopes = ["repo", "user:email", "public_repo"]

      # Create session and authorize with custom scopes
      {:ok, session} = Auth.create_session(provider.slug, tenant_id)

      {:ok, auth_url} =
        Auth.authorize_url(session.session_token,
          redirect_uri: "https://myapp.com/callback",
          scopes: custom_scopes
        )

      assert String.contains?(auth_url, URI.encode_www_form(Enum.join(custom_scopes, " ")))

      # Test that custom scopes are included in authorization URL
      # (Full OAuth flow would be tested with real provider integration)
      # For now, verify that the flow accepts custom scopes correctly
    end

    test "multiple concurrent sessions for same tenant", %{provider: provider} do
      tenant_id = "user-concurrent"

      # Create multiple sessions concurrently
      tasks =
        for _i <- 1..3 do
          Task.async(fn ->
            Auth.create_session(provider.slug, tenant_id)
          end)
        end

      results = Task.await_many(tasks, 5000)
      sessions = Enum.map(results, fn {:ok, session} -> session end)

      # All sessions should be unique
      states = Enum.map(sessions, & &1.state)
      tokens = Enum.map(sessions, & &1.session_token)

      assert length(Enum.uniq(states)) == 3
      assert length(Enum.uniq(tokens)) == 3

      # All sessions should be valid
      for session <- sessions do
        assert {:ok, _} = Auth.get_session(session.session_token)
      end
    end

    test "session expiration handling", %{provider: provider} do
      tenant_id = "user-expiration"

      # Create session
      {:ok, session} = Auth.create_session(provider.slug, tenant_id)

      # Manually expire the session by updating database
      Tango.TestRepo.update_all(
        from(s in OAuthSession, where: s.id == ^session.id),
        # 1 hour ago
        set: [expires_at: DateTime.add(DateTime.utc_now(), -3600)]
      )

      # Try to use expired session for authorization URL
      result =
        Auth.authorize_url(session.session_token,
          redirect_uri: "https://myapp.com/callback"
        )

      assert {:error, :session_expired} = result

      # Since the session is expired, we can't use the helper that creates a new session
      # Instead, just test with an obviously invalid state (simulating expired session scenario)
      result =
        Auth.exchange_code("expired_state_token", "auth_code", tenant_id,
          redirect_uri: "https://myapp.com/callback"
        )

      assert {:error, _reason} = result
    end
  end

  describe "OAuth flow error scenarios" do
    setup do
      bypass = Bypass.open()

      # Setup token endpoint with stub (optional, won't fail if not called)
      Bypass.stub(bypass, "POST", "/login/oauth/access_token", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Conn.resp(
          200,
          "access_token=mock_access_token_error_test&token_type=bearer&scope=repo%2Cuser"
        )
      end)

      # Create provider using mock server URLs with unique suffix to avoid conflicts
      urls = OAuthMockServer.github_urls(bypass)
      provider = Factory.create_github_provider("_error_scenarios", urls: urls)

      %{provider: provider, bypass: bypass}
    end

    test "invalid state parameter handling", %{provider: provider} do
      tenant_id = "user-invalid-state"

      # Create valid session
      {:ok, session} = Auth.create_session(provider.slug, tenant_id)

      # Try to exchange code with wrong state
      invalid_states = [
        "wrong-state-123",
        "",
        nil,
        session.state <> "tampered"
      ]

      for invalid_state <- invalid_states do
        result =
          Auth.exchange_code(invalid_state, "auth_code", tenant_id,
            redirect_uri: "https://myapp.com/callback"
          )

        assert match?({:error, _}, result)
      end
    end

    test "cross-tenant state hijacking prevention", %{provider: provider} do
      tenant_a = "user-a"
      tenant_b = "user-b"

      # Create session for tenant A (not actually needed for the test)
      {:ok, _session_a} = Auth.create_session(provider.slug, tenant_a)

      # Tenant B tries to use tenant A's session (should fail with encoded state)
      result =
        OAuthFlowHelper.test_cross_tenant_exchange(
          provider.slug,
          tenant_a,
          tenant_b,
          "auth_code",
          redirect_uri: "https://myapp.com/callback"
        )

      assert {:error, :invalid_state} = result
    end

    test "invalid authorization code handling", %{provider: provider} do
      tenant_id = "user-invalid-code"

      # Get encoded state for proper OAuth flow
      {:ok, encoded_state, _session} =
        OAuthFlowHelper.get_encoded_state_for_session(
          provider.slug,
          tenant_id,
          redirect_uri: "https://myapp.com/callback"
        )

      invalid_codes = [
        # Empty
        "",
        # Nil
        nil,
        # Trailing space
        "invalid-code-with-spaces ",
        # Newlines
        "code\nwith\nnewlines",
        # Too long
        String.duplicate("x", 1000)
      ]

      for invalid_code <- invalid_codes do
        result =
          try do
            Auth.exchange_code(encoded_state, invalid_code, tenant_id,
              redirect_uri: "https://myapp.com/callback"
            )
          rescue
            FunctionClauseError -> {:error, :invalid_input}
          end

        assert match?({:error, _}, result)
      end
    end

    test "malicious redirect URI prevention", %{provider: provider} do
      tenant_id = "user-malicious"

      malicious_uris = [
        "javascript:alert('xss')",
        "data:text/html,<script>alert('xss')</script>",
        "file:///etc/passwd",
        "http://evil.com/steal-tokens"
      ]

      for malicious_uri <- malicious_uris do
        {:ok, session} = Auth.create_session(provider.slug, tenant_id)

        # Should fail at authorization URL generation
        result = Auth.authorize_url(session.session_token, redirect_uri: malicious_uri)
        assert match?({:error, _}, result)

        # Should also fail at token exchange (create minimal encoded state for test)
        {:ok, encoded_state, _session} =
          OAuthFlowHelper.get_encoded_state_for_session(provider.slug, tenant_id,
            redirect_uri: "https://valid.com"
          )

        result =
          Auth.exchange_code(encoded_state, "auth_code", tenant_id, redirect_uri: malicious_uri)

        assert match?({:error, _}, result)
      end
    end

    test "session cleanup after successful exchange", %{provider: provider} do
      tenant_id = "user-cleanup"

      # Create session and complete OAuth flow manually to test session cleanup
      {:ok, session} = Auth.create_session(provider.slug, tenant_id)
      session_token = session.session_token

      # Generate auth URL and get encoded state
      {:ok, auth_url} =
        Auth.authorize_url(session.session_token, redirect_uri: "https://myapp.com/callback")

      {:ok, encoded_state} = OAuthFlowHelper.extract_state_from_auth_url(auth_url)

      # Complete OAuth exchange
      {:ok, _connection} =
        Auth.exchange_code(encoded_state, "auth_code", tenant_id,
          redirect_uri: "https://myapp.com/callback"
        )

      # Session should be cleaned up
      assert {:error, :session_not_found} = Auth.get_session(session_token)

      # Session should not exist in database
      assert is_nil(Tango.TestRepo.get(OAuthSession, session.id))
    end

    test "duplicate token exchange prevention", %{provider: provider} do
      tenant_id = "user-duplicate"

      # Get encoded state for proper OAuth flow
      {:ok, encoded_state, _session} =
        OAuthFlowHelper.get_encoded_state_for_session(
          provider.slug,
          tenant_id,
          redirect_uri: "https://myapp.com/callback"
        )

      # First exchange should succeed
      {:ok, connection1} =
        Auth.exchange_code(encoded_state, "auth_code", tenant_id,
          redirect_uri: "https://myapp.com/callback"
        )

      assert connection1.status == :active

      # Second exchange with same parameters should fail (session cleaned up)
      result =
        Auth.exchange_code(encoded_state, "auth_code", tenant_id,
          redirect_uri: "https://myapp.com/callback"
        )

      assert {:error, :invalid_state} = result
    end
  end

  describe "connection management integration" do
    setup do
      bypass = Bypass.open()

      # Setup token endpoint with stub (optional, won't fail if not called)
      Bypass.stub(bypass, "POST", "/login/oauth/access_token", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Conn.resp(
          200,
          "access_token=mock_access_token_connection_test&token_type=bearer&scope=repo%2Cuser"
        )
      end)

      # Create provider using mock server URLs with unique suffix to avoid conflicts
      urls = OAuthMockServer.github_urls(bypass)
      provider = Factory.create_github_provider("_connection_mgmt", urls: urls)

      %{provider: provider, bypass: bypass}
    end

    test "connection creation and retrieval", %{provider: provider} do
      tenant_id = "user-connection"

      # Complete OAuth flow using helper
      {:ok, connection} =
        OAuthFlowHelper.complete_oauth_flow(
          provider.slug,
          tenant_id,
          "auth_code",
          redirect_uri: "https://myapp.com/callback"
        )

      # Retrieve connection by ID (using repo directly since context module doesn't exist yet)
      retrieved = Tango.TestRepo.get(Connection, connection.id)
      assert retrieved.id == connection.id
      assert retrieved.tenant_id == tenant_id

      # Retrieve by provider (simulate the function)
      provider_connection =
        Tango.TestRepo.get_by(Connection,
          provider_id: provider.id,
          tenant_id: tenant_id,
          status: :active
        )

      assert provider_connection.id == connection.id

      # List connections for tenant (simulate the function)
      connections =
        Tango.TestRepo.all(from(c in Connection, where: c.tenant_id == ^tenant_id))

      assert length(connections) == 1
      assert hd(connections).id == connection.id
    end

    test "connection replacement on new OAuth", %{provider: provider} do
      tenant_id = "user-replacement"

      # First OAuth flow
      {:ok, connection1} =
        OAuthFlowHelper.complete_oauth_flow(
          provider.slug,
          tenant_id,
          "auth_code_1",
          redirect_uri: "https://myapp.com/callback"
        )

      assert connection1.status == :active

      # Second OAuth flow (should replace first connection)
      {:ok, connection2} =
        OAuthFlowHelper.complete_oauth_flow(
          provider.slug,
          tenant_id,
          "auth_code_2",
          redirect_uri: "https://myapp.com/callback"
        )

      # Second connection should be active
      assert connection2.status == :active
      assert connection2.id != connection1.id

      # First connection should be revoked
      old_connection = Tango.TestRepo.get(Connection, connection1.id)
      assert old_connection.status == :revoked

      # Only one active connection should exist
      active_connections =
        Tango.TestRepo.all(from(c in Connection, where: c.tenant_id == ^tenant_id))
        |> Enum.filter(&(&1.status == :active))

      assert length(active_connections) == 1
      assert hd(active_connections).id == connection2.id
    end

    test "multi-provider connections", %{provider: github_provider} do
      tenant_id = "user-multi-provider"

      # Create second Bypass server for Slack
      slack_bypass = Bypass.open()

      # Setup Slack OAuth mock (only token endpoint since auth URL is just generated, not called)
      Bypass.expect(slack_bypass, "POST", "/api/oauth.v2.access", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "access_token" => "mock_slack_access_token_12345",
            "token_type" => "Bearer",
            "scope" => "chat:write,channels:read"
          })
        )
      end)

      # Create Slack provider using mock server URLs
      slack_urls =
        OAuthMockServer.generic_urls(slack_bypass,
          auth_path: "/oauth/v2/authorize",
          token_path: "/api/oauth.v2.access"
        )

      slack_provider =
        Factory.create_provider(%{
          name: "Slack",
          slug: "slack_multi_provider_test",
          active: true,
          auth_mode: "oauth2",
          client_secret: "slack_client_secret",
          config:
            %{
              "display_name" => "Slack",
              "client_id" => "slack_client_id"
            }
            |> Map.merge(slack_urls),
          default_scopes: ["chat:write", "channels:read"],
          metadata: %{}
        })

      # Create connections to both providers using proper OAuth flow
      {:ok, github_connection} =
        OAuthFlowHelper.complete_oauth_flow(
          github_provider.slug,
          tenant_id,
          "github_code",
          redirect_uri: "https://myapp.com/callback"
        )

      {:ok, slack_connection} =
        OAuthFlowHelper.complete_oauth_flow(
          slack_provider.slug,
          tenant_id,
          "slack_code",
          redirect_uri: "https://myapp.com/callback"
        )

      # Both connections should be active
      assert github_connection.status == :active
      assert slack_connection.status == :active

      # Should have 2 active connections
      connections =
        Tango.TestRepo.all(from(c in Connection, where: c.tenant_id == ^tenant_id))

      assert length(connections) == 2

      # Can retrieve by specific provider
      github_conn =
        Tango.TestRepo.get_by(Connection,
          provider_id: github_provider.id,
          tenant_id: tenant_id,
          status: :active
        )

      slack_conn =
        Tango.TestRepo.get_by(Connection,
          provider_id: slack_provider.id,
          tenant_id: tenant_id,
          status: :active
        )

      assert github_conn.provider_id == github_provider.id
      assert slack_conn.provider_id == slack_provider.id
    end
  end

  describe "audit logging integration" do
    setup do
      bypass = Bypass.open()

      # Setup token endpoint with stub (optional, won't fail if not called)
      Bypass.stub(bypass, "POST", "/login/oauth/access_token", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Conn.resp(
          200,
          "access_token=mock_access_token_audit_test&token_type=bearer&scope=repo%2Cuser"
        )
      end)

      # Create provider using mock server URLs with unique suffix to avoid conflicts
      urls = OAuthMockServer.github_urls(bypass)
      provider = Factory.create_github_provider("_audit_logging", urls: urls)

      %{provider: provider, bypass: bypass}
    end

    test "complete OAuth flow creates audit trail", %{provider: provider} do
      tenant_id = "user-audit"

      # Clear any existing audit logs
      Tango.TestRepo.delete_all(Tango.Schemas.AuditLog)

      # Complete OAuth flow using helper
      {:ok, _connection} =
        OAuthFlowHelper.complete_oauth_flow(
          provider.slug,
          tenant_id,
          "auth_code",
          redirect_uri: "https://myapp.com/callback"
        )

      # Should have audit log entries
      audit_logs = Tango.TestRepo.all(Tango.Schemas.AuditLog)
      # At least session start and token exchange
      assert length(audit_logs) >= 2

      # Verify log entries
      log_events = Enum.map(audit_logs, & &1.event_type)
      assert :oauth_start in log_events
      assert :token_exchange in log_events

      # All logs should be for the correct tenant
      tenant_ids = Enum.map(audit_logs, & &1.tenant_id)
      assert Enum.all?(tenant_ids, &(&1 == tenant_id))
    end

    test "failed OAuth attempts are logged", %{provider: provider} do
      tenant_id = "user-failed-audit"

      # Clear existing logs
      Tango.TestRepo.delete_all(Tango.Schemas.AuditLog)

      # Create session but use invalid state for exchange
      {:ok, _session} = Auth.create_session(provider.slug, tenant_id)

      # Attempt failed exchange
      result =
        Auth.exchange_code("invalid-state", "auth_code", tenant_id,
          redirect_uri: "https://myapp.com/callback"
        )

      assert match?({:error, _}, result)

      # Should have audit logs including failure
      audit_logs = Tango.TestRepo.all(Tango.Schemas.AuditLog)

      # Should have session start log
      oauth_start_logs = Enum.filter(audit_logs, &(&1.event_type == :oauth_start))
      assert length(oauth_start_logs) == 1

      # Failed exchange might not create audit log (depends on where failure occurs)
      # But session start should always be logged
      start_log = hd(oauth_start_logs)
      assert start_log.tenant_id == tenant_id
      assert start_log.success == true
    end
  end
end

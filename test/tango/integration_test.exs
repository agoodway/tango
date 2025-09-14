defmodule Tango.IntegrationTest do
  @moduledoc """
  Comprehensive end-to-end integration tests for the complete OAuth flow.

  Tests the full OAuth lifecycle:
  1. Setting up OAuth provider
  2. Creating OAuth session (authorization flow)
  3. Exchanging authorization code for tokens (connection creation)
  4. Using the connection for API calls
  5. Token refresh lifecycle
  6. Audit logging verification throughout
  """

  use Tango.DatabaseCase, async: false

  alias Tango.Auth
  alias Tango.Provider
  alias Tango.TestRepo, as: Repo
  alias Tango.Types.EncryptedBinary
  alias Tango.Schemas.{AuditLog, Connection, OAuthSession}

  describe "complete OAuth flow integration" do
    test "full OAuth lifecycle with GitHub provider" do
      # === STEP 1: Set up OAuth Provider ===
      provider_attrs = %{
        name: "github",
        slug: "github",
        client_secret: "github_client_secret_123",
        config: %{
          "display_name" => "GitHub",
          "client_id" => "github_client_id_123",
          "auth_url" => "https://github.com/login/oauth/authorize",
          "token_url" => "https://github.com/login/oauth/access_token",
          "auth_mode" => "OAUTH2"
        },
        default_scopes: ["user:email", "repo"],
        active: true
      }

      {:ok, provider} = Provider.create_provider(provider_attrs)

      # Verify provider was created correctly
      assert provider.name == "github"
      assert provider.active == true
      assert provider.config["client_id"] == "github_client_id_123"
      assert provider.default_scopes == ["user:email", "repo"]

      # === STEP 2: Start OAuth Session (Authorization Flow) ===
      tenant_id = "test-user-123"
      redirect_uri = "https://myapp.com/auth/callback"
      scopes = ["user:email", "repo", "read:org"]

      {:ok, session} =
        Auth.create_session("github", tenant_id,
          redirect_uri: redirect_uri,
          scopes: scopes
        )

      # Verify session was created correctly
      assert session.provider_id == provider.id
      assert session.tenant_id == tenant_id
      assert session.state != nil
      assert session.session_token != nil
      assert session.code_verifier != nil
      assert DateTime.compare(session.expires_at, DateTime.utc_now()) == :gt

      # === STEP 3: Generate Authorization URL ===
      {:ok, auth_url} =
        Auth.authorize_url(session.session_token, redirect_uri: redirect_uri, scopes: scopes)

      # Verify authorization URL contains expected parameters
      assert String.contains?(auth_url, "https://github.com/login/oauth/authorize")
      assert String.contains?(auth_url, "client_id=github_client_id_123")
      assert String.contains?(auth_url, "redirect_uri=#{URI.encode_www_form(redirect_uri)}")
      assert String.contains?(auth_url, "state=#{session.state}")
      assert String.contains?(auth_url, "code_challenge=")
      assert String.contains?(auth_url, "code_challenge_method=S256")
      assert String.contains?(auth_url, "scope=user%3Aemail+repo+read%3Aorg")

      # === STEP 4: Simulate Connection Creation (since we can't make real HTTP calls) ===
      # In a real scenario, the authorization code would be exchanged for tokens
      # For testing, we'll create a connection directly using the schema
      _authorization_code = "github_auth_code_12345"

      token_response = %{
        "access_token" => "gho_access_token_abc123",
        "refresh_token" => "gho_refresh_token_def456",
        "token_type" => :bearer,
        "expires_in" => 3600,
        "scope" => "user:email repo read:org"
      }

      # Create connection from token response using schema function
      connection_changeset =
        Connection.from_token_response(
          provider.id,
          tenant_id,
          token_response
        )

      assert connection_changeset.valid?
      {:ok, connection} = Repo.insert(connection_changeset)

      # Verify connection was created correctly
      assert connection.provider_id == provider.id
      assert connection.tenant_id == tenant_id
      assert connection.access_token == "gho_access_token_abc123"
      assert connection.refresh_token == "gho_refresh_token_def456"
      # Should be normalized
      assert connection.token_type == :bearer
      assert connection.granted_scopes == ["user:email", "repo", "read:org"]
      assert connection.status == :active
      assert DateTime.compare(connection.expires_at, DateTime.utc_now()) == :gt

      # === STEP 5: Use Connection for API Calls ===
      # Simulate using the connection for API requests by updating last_used_at
      update_changeset =
        Connection.changeset(connection, %{last_used_at: DateTime.utc_now()})

      {:ok, updated_connection} = Repo.update(update_changeset)
      assert DateTime.diff(DateTime.utc_now(), updated_connection.last_used_at) < 5

      # === STEP 6: Test Token Refresh Flow ===
      # Simulate token approaching expiration
      expiring_connection = %{
        connection
        | # Expires in 2 minutes
          expires_at: DateTime.add(DateTime.utc_now(), 2 * 60, :second),
          refresh_attempts: 0
      }

      # Check if token needs refresh
      assert Connection.needs_refresh?(expiring_connection) == true
      assert Connection.can_refresh?(expiring_connection) == true

      # Mock successful token refresh
      new_token_response = %{
        "access_token" => "gho_new_access_token_xyz789",
        "refresh_token" => "gho_new_refresh_token_uvw012",
        "expires_in" => 3600,
        "scope" => "user:email repo read:org"
      }

      # Create refreshed connection changeset
      refresh_changeset =
        Connection.refresh_changeset(
          expiring_connection,
          new_token_response
        )

      assert refresh_changeset.valid?
      assert get_change(refresh_changeset, :access_token) == "gho_new_access_token_xyz789"
      assert get_change(refresh_changeset, :refresh_token) == "gho_new_refresh_token_uvw012"
      # refresh_attempts is set to 0 in refresh, but might not show as change if already 0
      assert get_field(refresh_changeset, :refresh_attempts) == 0

      # === STEP 7: Test Connection Lifecycle Management ===
      # Test connection revocation using changeset directly
      revoked_changeset =
        Connection.changeset(connection, %{
          status: :expired,
          refresh_exhausted: true,
          last_refresh_failure: "user_revoked"
        })

      assert revoked_changeset.valid?
      assert get_change(revoked_changeset, :status) == :expired
      assert get_change(revoked_changeset, :refresh_exhausted) == true
      assert get_change(revoked_changeset, :last_refresh_failure) == "user_revoked"

      # Test refresh failure handling
      failure_changeset =
        Connection.record_refresh_failure(
          connection,
          "invalid_refresh_token"
        )

      assert failure_changeset.valid?
      assert get_change(failure_changeset, :refresh_attempts) == 1
      assert get_change(failure_changeset, :last_refresh_failure) == "invalid_refresh_token"

      # === STEP 8: Verify Audit Logging Throughout ===
      # Test OAuth start logging
      oauth_start_log =
        AuditLog.log_oauth_start(
          provider,
          tenant_id,
          session,
          ip_address: "192.168.1.100",
          user_agent: "Mozilla/5.0 Test Browser",
          # Pass the requested scopes
          scopes: scopes
        )

      assert oauth_start_log.valid?
      assert get_change(oauth_start_log, :event_type) == :oauth_start
      assert get_change(oauth_start_log, :tenant_id) == tenant_id
      assert get_change(oauth_start_log, :provider_id) == provider.id
      assert get_change(oauth_start_log, :session_id) == session.session_token
      assert get_change(oauth_start_log, :success) == true

      event_data = get_change(oauth_start_log, :event_data)
      assert event_data.scopes_requested == scopes
      # Uses provider.name, not display_name
      assert event_data.provider_name == "github"
      assert event_data.session_expires_at == session.expires_at

      # Test token exchange logging
      token_exchange_log =
        AuditLog.log_token_exchange(
          session,
          connection,
          true
        )

      assert token_exchange_log.valid?
      assert get_change(token_exchange_log, :event_type) == :token_exchange
      assert get_change(token_exchange_log, :tenant_id) == tenant_id
      assert get_change(token_exchange_log, :connection_id) == connection.id
      assert get_change(token_exchange_log, :success) == true

      # Test connection status change logging
      status_change_log =
        AuditLog.log_connection_event(
          :connection_expired,
          connection,
          true,
          %{old_status: :active, new_status: :expired, reason: "token_expired"}
        )

      assert status_change_log.valid?
      assert get_change(status_change_log, :event_type) == :connection_expired
      assert get_change(status_change_log, :connection_id) == connection.id

      status_event_data = get_change(status_change_log, :event_data)
      assert status_event_data.old_status == :active
      assert status_event_data.new_status == :expired
      assert status_event_data.reason == "token_expired"
    end

    test "OAuth flow with multiple providers and tenants" do
      # === Set up multiple providers ===
      {:ok, github_provider} =
        Provider.create_provider(%{
          name: "github",
          slug: "github",
          client_secret: "github_secret",
          config: %{
            "client_id" => "github_client",
            "auth_url" => "https://github.com/login/oauth/authorize",
            "token_url" => "https://github.com/login/oauth/access_token"
          }
        })

      {:ok, google_provider} =
        Provider.create_provider(%{
          name: "google",
          slug: "google",
          client_secret: "google_secret",
          config: %{
            "client_id" => "google_client",
            "auth_url" => "https://accounts.google.com/o/oauth2/auth",
            "token_url" => "https://oauth2.googleapis.com/token"
          }
        })

      # === Test multi-tenant isolation ===
      tenant1 = "user-tenant-1"
      tenant2 = "user-tenant-2"

      # Create sessions for different tenants with same provider
      {:ok, session1} = Auth.create_session("github", tenant1)
      {:ok, session2} = Auth.create_session("github", tenant2)

      assert session1.tenant_id == tenant1
      assert session2.tenant_id == tenant2
      assert session1.provider_id == github_provider.id
      assert session2.provider_id == github_provider.id
      # Different sessions
      assert session1.session_token != session2.session_token

      # Create sessions for same tenant with different providers
      {:ok, session3} = Auth.create_session("google", tenant1)

      assert session3.tenant_id == tenant1
      assert session3.provider_id == google_provider.id
      # Different sessions
      assert session3.session_token != session1.session_token

      # === Test session validation and cleanup ===
      # Test state validation
      assert {:ok, session1} = Auth.get_session(session1.session_token)
      assert :ok = OAuthSession.validate_state(session1, session1.state)

      assert {:error, :invalid_state} =
               OAuthSession.validate_state(session1, "wrong_state")

      # Test session expiration
      assert OAuthSession.valid?(session1) == true

      expired_session = %{session1 | expires_at: DateTime.add(DateTime.utc_now(), -3600, :second)}
      assert OAuthSession.expired?(expired_session) == true
      assert OAuthSession.valid?(expired_session) == false

      # === Test PKCE flow ===
      code_challenge = OAuthSession.generate_code_challenge(session1)
      assert is_binary(code_challenge)
      # Base64url without padding
      assert byte_size(code_challenge) == 43

      # Verify the challenge is consistent
      challenge2 = OAuthSession.generate_code_challenge(session1)
      assert code_challenge == challenge2
    end

    test "error handling and edge cases" do
      # === Test provider not found ===
      assert {:error, :provider_not_found} = Auth.create_session("nonexistent", "user-123")

      # === Test invalid session token ===
      assert {:error, :session_token_too_short} = Auth.get_session("invalid_session_token")

      # === Test session not found (with valid token format) ===
      valid_fake_token = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
      assert {:error, :session_not_found} = Auth.get_session(valid_fake_token)

      # === Test expired session handling ===
      {:ok, provider} =
        Provider.create_provider(%{
          name: "test-provider",
          slug: "test-provider",
          client_secret: "test_secret",
          config: %{
            "client_id" => "test_client",
            "auth_url" => "https://example.com/auth",
            "token_url" => "https://example.com/token"
          }
        })

      # Create session that's already expired
      expired_session_attrs = %{
        provider_id: provider.id,
        tenant_id: "user-123",
        session_token: "expired_session_token",
        state: "expired_state",
        # 1 hour ago
        expires_at: DateTime.add(DateTime.utc_now(), -3600, :second)
      }

      expired_changeset =
        OAuthSession.changeset(
          %OAuthSession{},
          expired_session_attrs
        )

      # Should fail validation because expires_at is in the past
      refute expired_changeset.valid?
      errors = errors_on(expired_changeset)
      assert "must be in the future" in errors[:expires_at]

      # === Test connection validation ===
      # Test connection without required fields
      invalid_connection = Connection.changeset(%Connection{}, %{})
      refute invalid_connection.valid?

      # Test connection with invalid status
      invalid_status =
        Connection.changeset(%Connection{}, %{
          provider_id: provider.id,
          tenant_id: "user-123",
          access_token: "token",
          status: "invalid_status"
        })

      refute invalid_status.valid?
      errors = errors_on(invalid_status)
      assert "is invalid" in errors[:status]

      # === Test audit log validation ===
      # Test audit log with invalid event type
      invalid_audit =
        AuditLog.changeset(%AuditLog{}, %{
          event_type: "invalid_event",
          tenant_id: "user-123",
          success: true
        })

      refute invalid_audit.valid?
      errors = errors_on(invalid_audit)
      assert "is invalid" in errors[:event_type]
    end

    test "encryption and security properties" do
      # === Test token encryption ===
      {:ok, provider} =
        Provider.create_provider(%{
          name: "security-test",
          slug: "security-test",
          client_secret: "secret_token_for_testing",
          config: %{
            "client_id" => "security_client",
            "auth_url" => "https://example.com/auth",
            "token_url" => "https://example.com/token"
          }
        })

      # Create connection with sensitive tokens
      sensitive_access_token = "very_sensitive_access_token_12345"
      sensitive_refresh_token = "very_sensitive_refresh_token_67890"

      connection_attrs = %{
        provider_id: provider.id,
        tenant_id: "security-user",
        access_token: sensitive_access_token,
        refresh_token: sensitive_refresh_token,
        status: :active
      }

      connection_changeset = Connection.changeset(%Connection{}, connection_attrs)
      assert connection_changeset.valid?

      # === Test EncryptedBinary type behavior ===
      # Test that dumping encrypts the token
      {:ok, encrypted_access} = EncryptedBinary.dump(sensitive_access_token)
      {:ok, encrypted_refresh} = EncryptedBinary.dump(sensitive_refresh_token)

      # Encrypted data should not contain plaintext
      refute String.contains?(encrypted_access, sensitive_access_token)
      refute String.contains?(encrypted_refresh, sensitive_refresh_token)
      refute String.contains?(encrypted_access, "very_sensitive")
      refute String.contains?(encrypted_refresh, "very_sensitive")

      # Encrypted data should be different each time (random IV)
      {:ok, encrypted_access2} = EncryptedBinary.dump(sensitive_access_token)
      assert encrypted_access != encrypted_access2

      # But both should decrypt to the same plaintext
      {:ok, decrypted1} = EncryptedBinary.load(encrypted_access)
      {:ok, decrypted2} = EncryptedBinary.load(encrypted_access2)
      assert decrypted1 == sensitive_access_token
      assert decrypted2 == sensitive_access_token

      # === Test provider client secret encryption ===
      # Provider client secret should also be encrypted
      {:ok, encrypted_secret} = EncryptedBinary.dump(provider.client_secret)
      refute String.contains?(encrypted_secret, "secret_token_for_testing")

      # === Test session token uniqueness and randomness ===
      {:ok, session1} = Auth.create_session("security-test", "user-1")
      {:ok, session2} = Auth.create_session("security-test", "user-2")

      # Session tokens should be unique
      assert session1.session_token != session2.session_token
      assert session1.state != session2.state
      assert session1.code_verifier != session2.code_verifier

      # Tokens should be sufficiently long for security
      assert String.length(session1.session_token) >= 32
      assert String.length(session1.state) >= 32
      # PKCE requirement
      assert String.length(session1.code_verifier) >= 43
    end
  end

  # Helper function to extract errors (similar to Phoenix's errors_on/1)
  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end

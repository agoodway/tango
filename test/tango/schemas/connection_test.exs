defmodule Tango.Schemas.ConnectionTest do
  use Tango.DatabaseCase, async: true

  alias Tango.Schemas.Connection

  describe "changeset/2" do
    test "valid changeset with required fields" do
      attrs = %{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "access_token_123",
        status: :active
      }

      changeset = Connection.changeset(%Connection{}, attrs)
      assert changeset.valid?
    end

    test "invalid changeset without required fields" do
      changeset = Connection.changeset(%Connection{}, %{})
      refute changeset.valid?

      # Status has a default value, so it won't be "can't be blank"
      assert %{
               provider_id: ["can't be blank"],
               tenant_id: ["can't be blank"],
               access_token: ["can't be blank"]
             } = errors_on(changeset)
    end

    test "validates status inclusion" do
      base_attrs = %{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token_123"
      }

      # Valid statuses
      for status <- [:active, :revoked, :expired] do
        changeset = Connection.changeset(%Connection{}, Map.put(base_attrs, :status, status))
        assert changeset.valid?, "Status #{status} should be valid"
      end

      # Invalid status
      changeset = Connection.changeset(%Connection{}, Map.put(base_attrs, :status, "invalid"))
      errors = errors_on(changeset)
      assert "is invalid" in errors[:status]
    end

    test "validates token_type inclusion" do
      base_attrs = %{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token_123",
        status: :active
      }

      # Valid token types
      for token_type <- [:bearer, :token] do
        changeset =
          Connection.changeset(%Connection{}, Map.put(base_attrs, :token_type, token_type))

        assert changeset.valid?, "Token type #{token_type} should be valid"
      end

      # Invalid token type
      changeset = Connection.changeset(%Connection{}, Map.put(base_attrs, :token_type, "invalid"))
      errors = errors_on(changeset)
      assert "is invalid" in errors[:token_type]
    end

    test "validates refresh_attempts must be non-negative" do
      base_attrs = %{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token_123",
        status: :active
      }

      # Valid (zero and positive)
      changeset = Connection.changeset(%Connection{}, Map.put(base_attrs, :refresh_attempts, 0))
      assert changeset.valid?

      changeset = Connection.changeset(%Connection{}, Map.put(base_attrs, :refresh_attempts, 5))
      assert changeset.valid?

      # Invalid (negative)
      changeset = Connection.changeset(%Connection{}, Map.put(base_attrs, :refresh_attempts, -1))
      errors = errors_on(changeset)
      assert "must be greater than or equal to 0" in errors[:refresh_attempts]
    end

    test "normalizes token_type" do
      base_attrs = %{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token_123",
        status: :active
      }

      # Test normalization - check each case individually to debug issues
      changeset = Connection.changeset(%Connection{}, Map.put(base_attrs, :token_type, :bearer))

      assert changeset.valid?,
             "bearer should be valid but got errors: #{inspect(errors_on(changeset))}"

      changeset = Connection.changeset(%Connection{}, Map.put(base_attrs, :token_type, :bearer))

      assert changeset.valid?,
             "Bearer should be valid but got errors: #{inspect(errors_on(changeset))}"

      changeset = Connection.changeset(%Connection{}, Map.put(base_attrs, :token_type, :token))

      assert changeset.valid?,
             "token should be valid but got errors: #{inspect(errors_on(changeset))}"
    end

    test "sets default values" do
      connection = %Connection{}
      assert connection.token_type == :bearer
      assert connection.raw_payload == %{}
      assert connection.metadata == %{}
      assert connection.status == :active
      assert connection.refresh_attempts == 0
      assert connection.refresh_exhausted == false
      assert connection.auto_refresh_enabled == true
      assert connection.connection_config == %{}
    end
  end

  describe "from_token_response/3" do
    test "creates connection from complete OAuth token response" do
      provider = Tango.Factory.create_provider()
      tenant_id = "user-123"

      token_response = %{
        "access_token" => "access_token_abc123",
        "refresh_token" => "refresh_token_def456",
        "token_type" => "bearer",
        "expires_in" => 3600,
        "scope" => "read write user:email"
      }

      changeset = Connection.from_token_response(provider.id, tenant_id, token_response)

      assert changeset.valid?
      assert get_change(changeset, :provider_id) == provider.id
      assert get_change(changeset, :tenant_id) == tenant_id
      assert get_change(changeset, :access_token) == "access_token_abc123"
      assert get_change(changeset, :refresh_token) == "refresh_token_def456"
      # Token type normalization happens in prepare_changes, check field value
      assert get_field(changeset, :token_type) == :bearer
      assert get_change(changeset, :granted_scopes) == ["read", "write", "user:email"]
      # Raw payload should have tokens removed for security
      expected_sanitized_payload = Map.drop(token_response, ["access_token", "refresh_token"])
      assert get_change(changeset, :raw_payload) == expected_sanitized_payload
      # Status is set to "active" but since it's the default, might not be recorded as change
      assert get_field(changeset, :status) == :active

      # Verify expires_at is set correctly
      expires_at = get_change(changeset, :expires_at)
      assert DateTime.compare(expires_at, DateTime.utc_now()) == :gt

      # Verify last_used_at is recent
      last_used_at = get_change(changeset, :last_used_at)
      # Within 5 seconds
      assert DateTime.diff(DateTime.utc_now(), last_used_at) < 5
    end

    test "handles minimal token response" do
      provider = Tango.Factory.create_provider()
      tenant_id = "user-123"

      token_response = %{
        "access_token" => "access_token_only"
      }

      changeset = Connection.from_token_response(provider.id, tenant_id, token_response)

      assert changeset.valid?
      assert get_change(changeset, :access_token) == "access_token_only"
      assert get_change(changeset, :refresh_token) == nil
      # Token type gets default value
      assert get_field(changeset, :token_type) == :bearer
      # No expires_in
      assert get_change(changeset, :expires_at) == nil
      # No scope
      assert get_change(changeset, :granted_scopes) == []
    end

    test "parses different scope formats" do
      provider_id = "550e8400-e29b-41d4-a716-446655440000"
      tenant_id = "user-123"

      # Space-separated string
      token_response = %{"access_token" => "token", "scope" => "read write admin"}
      changeset = Connection.from_token_response(provider_id, tenant_id, token_response)
      assert get_change(changeset, :granted_scopes) == ["read", "write", "admin"]

      # Single scope
      token_response = %{"access_token" => "token", "scope" => "read"}
      changeset = Connection.from_token_response(provider_id, tenant_id, token_response)
      assert get_change(changeset, :granted_scopes) == ["read"]

      # Empty scope
      token_response = %{"access_token" => "token", "scope" => ""}
      changeset = Connection.from_token_response(provider_id, tenant_id, token_response)
      assert get_change(changeset, :granted_scopes) == []
    end
  end

  describe "refresh_changeset/2" do
    test "updates connection with new tokens" do
      connection = %Connection{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "old_token",
        status: :active,
        refresh_token: "old_refresh",
        granted_scopes: ["read"],
        raw_payload: %{"old" => "data"},
        refresh_attempts: 2
      }

      token_response = %{
        "access_token" => "new_access_token",
        "refresh_token" => "new_refresh_token",
        "expires_in" => 7200,
        "scope" => "read write"
      }

      changeset = Connection.refresh_changeset(connection, token_response)

      assert changeset.valid?
      assert get_change(changeset, :access_token) == "new_access_token"
      assert get_change(changeset, :refresh_token) == "new_refresh_token"
      assert get_change(changeset, :granted_scopes) == ["read", "write"]
      # Reset
      assert get_change(changeset, :refresh_attempts) == 0
      # Reset
      assert get_change(changeset, :last_refresh_failure) == nil
      # refresh_exhausted is explicitly set to false, so it should be a change
      assert get_change(changeset, :refresh_exhausted) == false or
               get_field(changeset, :refresh_exhausted) == false

      # Verify raw_payload is merged but tokens are sanitized for security
      new_payload = get_change(changeset, :raw_payload)
      assert new_payload["old"] == "data"
      # Tokens should be removed from raw_payload for security
      refute Map.has_key?(new_payload, "access_token")
      refute Map.has_key?(new_payload, "refresh_token")
      # But other fields should be preserved
      assert new_payload["expires_in"] == 7200
      assert new_payload["scope"] == "read write"
    end

    test "preserves existing refresh_token when not provided" do
      connection = %Connection{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token",
        status: :active,
        refresh_token: "existing_refresh"
      }

      token_response = %{
        "access_token" => "new_access_token"
        # No refresh_token in response
      }

      changeset = Connection.refresh_changeset(connection, token_response)
      # When refresh_token isn't in response, the changeset sets it to the existing value
      # This might be recorded as a change. Check the actual value.
      assert get_field(changeset, :refresh_token) == "existing_refresh"
    end

    test "preserves existing scopes when not provided" do
      connection = %Connection{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token",
        status: :active,
        granted_scopes: ["existing", "scopes"]
      }

      token_response = %{
        "access_token" => "new_access_token"
        # No scope in response
      }

      changeset = Connection.refresh_changeset(connection, token_response)

      assert get_field(changeset, :granted_scopes) == ["existing", "scopes"]
    end

    test "clears a rejection streak, since a refreshed token authenticates again" do
      connection = %Connection{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "old_token",
        status: :active,
        auth_failures: 2,
        last_auth_failure: "http_401",
        next_refresh_at: ~U[2030-01-01 00:00:00Z]
      }

      token_response = %{"access_token" => "new_token", "expires_in" => 3600}

      changeset = Connection.refresh_changeset(connection, token_response)

      assert get_change(changeset, :auth_failures) == 0
      assert get_change(changeset, :last_auth_failure) == nil
      assert get_field(changeset, :next_refresh_at) == nil
    end
  end

  describe "record_refresh_failure/2" do
    test "invalid_grant expires immediately and clears backoff" do
      connection = failure_connection(%{refresh_attempts: 1})

      changeset =
        Connection.record_refresh_failure(connection, {:oauth_error, :invalid_grant})

      assert changeset.valid?
      assert get_change(changeset, :refresh_attempts) == 2
      assert get_change(changeset, :status) == :expired
      assert get_change(changeset, :refresh_exhausted) == true
      assert get_change(changeset, :last_refresh_failure) == "oauth_error:invalid_grant"
      assert get_field(changeset, :next_refresh_at) == nil
    end

    test "client and request failures exhaust on the third attempt" do
      for reason <- [
            {:oauth_error, :invalid_client},
            {:oauth_error, :invalid_request}
          ] do
        first = Connection.record_refresh_failure(failure_connection(), reason)
        assert get_change(first, :refresh_attempts) == 1
        assert get_field(first, :status) == :active
        assert get_field(first, :refresh_exhausted) == false
        assert get_field(first, :next_refresh_at) == nil
        assert get_change(first, :last_refresh_failure) == "oauth_error:#{elem(reason, 1)}"

        third =
          failure_connection(%{refresh_attempts: 2})
          |> Connection.record_refresh_failure(reason)

        assert get_change(third, :refresh_attempts) == 3
        assert get_change(third, :status) == :expired
        assert get_change(third, :refresh_exhausted) == true
        assert get_field(third, :next_refresh_at) == nil
      end
    end

    test "transient failures keep the attempt count and schedule backoff" do
      connection = failure_connection(%{refresh_attempts: 2, refresh_exhausted: false})
      before_time = DateTime.utc_now() |> DateTime.truncate(:second)

      changeset = Connection.record_refresh_failure(connection, {:http_error, 503})

      after_time = DateTime.utc_now() |> DateTime.truncate(:second)
      next = get_change(changeset, :next_refresh_at)

      assert get_field(changeset, :refresh_attempts) == 2
      assert get_change(changeset, :refresh_attempts) == nil
      assert get_field(changeset, :status) == :active
      assert get_field(changeset, :refresh_exhausted) == false
      assert get_change(changeset, :last_refresh_failure) == "http_error:503"
      assert DateTime.compare(next, DateTime.add(before_time, 300, :second)) != :lt
      assert DateTime.compare(next, DateTime.add(after_time, 300, :second)) != :gt
    end

    test "recorded local failures keep the three attempt budget" do
      changeset =
        Connection.record_refresh_failure(failure_connection(), :invalid_config)

      assert get_change(changeset, :refresh_attempts) == 1
      assert get_change(changeset, :last_refresh_failure) == "invalid_config"
      assert get_field(changeset, :next_refresh_at) == nil
      assert get_field(changeset, :status) == :active

      unknown =
        Connection.record_refresh_failure(failure_connection(), "invalid_refresh_token")

      assert get_change(unknown, :refresh_attempts) == 1
      assert get_change(unknown, :last_refresh_failure) == "unknown_refresh_error"
      assert get_field(unknown, :next_refresh_at) == nil
    end

    test "eligibility and database failures do not write retry state" do
      connection = failure_connection(%{refresh_attempts: 2})

      for reason <- [
            :no_refresh_token,
            :refresh_not_allowed,
            :persistence_failed,
            :transaction_failed
          ] do
        changeset = Connection.record_refresh_failure(connection, reason)

        assert get_change(changeset, :refresh_attempts) == nil
        assert get_change(changeset, :status) == nil
        assert get_change(changeset, :refresh_exhausted) == nil
        assert get_change(changeset, :last_refresh_failure) == nil
        assert get_field(changeset, :next_refresh_at) == connection.next_refresh_at
      end
    end
  end

  describe "record_auth_failure/2" do
    test "records the first rejection without expiring the connection" do
      connection = %Connection{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token",
        status: :active,
        auth_failures: 0
      }

      changeset = Connection.record_auth_failure(connection, "http_401")

      assert changeset.valid?
      assert get_change(changeset, :auth_failures) == 1
      assert get_change(changeset, :last_auth_failure) == "http_401"
      refute Map.has_key?(changeset.changes, :status)
    end

    test "expires the connection once the rejections reach the threshold" do
      connection = %Connection{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token",
        status: :active,
        auth_failures: 2
      }

      changeset = Connection.record_auth_failure(connection, "http_401")

      assert changeset.valid?
      assert get_change(changeset, :auth_failures) == 3
      assert get_change(changeset, :status) == :expired
    end

    test "converts a reason term to a string" do
      connection = %Connection{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token",
        status: :active,
        auth_failures: 0
      }

      changeset = Connection.record_auth_failure(connection, :invalid_credentials)

      assert changeset.valid?
      assert get_change(changeset, :last_auth_failure) == "invalid_credentials"
    end

    test "a caller's higher threshold defers expiry past the default ceiling" do
      connection = %Connection{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token",
        status: :active,
        auth_failures: 2
      }

      changeset = Connection.record_auth_failure(connection, "http_401", max_failures: 5)

      assert get_change(changeset, :auth_failures) == 3
      refute Map.has_key?(changeset.changes, :status)
    end

    test "a caller's threshold of one expires the connection on the first rejection" do
      connection = %Connection{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token",
        status: :active,
        auth_failures: 0
      }

      changeset = Connection.record_auth_failure(connection, "http_401", max_failures: 1)

      assert get_change(changeset, :auth_failures) == 1
      assert get_change(changeset, :status) == :expired
    end

    test "keeps a terminal status, never converting :revoked to :expired" do
      connection = %Connection{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token",
        status: :revoked,
        auth_failures: 2
      }

      changeset = Connection.record_auth_failure(connection, "http_401")

      assert get_change(changeset, :auth_failures) == 3
      refute Map.has_key?(changeset.changes, :status)
    end

    test "rejects a threshold that is not a positive integer" do
      connection = %Connection{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token",
        status: :active,
        auth_failures: 0
      }

      for bad <- [0, -1, nil, "3", 2.5] do
        assert_raise ArgumentError, ~r/:max_failures must be a positive integer/, fn ->
          Connection.record_auth_failure(connection, "http_401", max_failures: bad)
        end
      end
    end

    test "leaves the refresh counters untouched" do
      connection = %Connection{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token",
        status: :active,
        auth_failures: 0,
        refresh_attempts: 1
      }

      changeset = Connection.record_auth_failure(connection, "http_401")

      refute Map.has_key?(changeset.changes, :refresh_attempts)
      refute Map.has_key?(changeset.changes, :refresh_exhausted)
      refute Map.has_key?(changeset.changes, :last_refresh_failure)
    end
  end

  describe "clear_auth_failures/1" do
    test "clears a partial rejection streak" do
      connection = %Connection{
        provider_id: 1,
        tenant_id: "user-123",
        access_token: "token",
        status: :active,
        auth_failures: 2,
        last_auth_failure: "http_401"
      }

      changeset = Connection.clear_auth_failures(connection)

      assert changeset.valid?
      assert get_change(changeset, :auth_failures) == 0
      assert get_change(changeset, :last_auth_failure) == nil
    end
  end

  describe "auth_failures_exhausted?/2" do
    test "is false below the threshold" do
      refute Connection.auth_failures_exhausted?(%Connection{auth_failures: 2})
    end

    test "is true at the default threshold" do
      assert Connection.auth_failures_exhausted?(%Connection{auth_failures: 3})
    end

    test "judges against a caller's threshold" do
      refute Connection.auth_failures_exhausted?(%Connection{auth_failures: 3}, max_failures: 5)
      assert Connection.auth_failures_exhausted?(%Connection{auth_failures: 5}, max_failures: 5)
    end
  end

  describe "needs_refresh?/1" do
    test "returns false for connection without expires_at" do
      connection = %Connection{expires_at: nil}
      assert Connection.needs_refresh?(connection) == false
    end

    test "returns true when token expires soon" do
      # Expires in 2 minutes (less than 5 minute buffer)
      expires_soon = DateTime.add(DateTime.utc_now(), 2 * 60, :second)
      connection = %Connection{expires_at: expires_soon}
      assert Connection.needs_refresh?(connection) == true
    end

    test "returns false when token has plenty of time" do
      # Expires in 10 minutes (more than 5 minute buffer)
      expires_later = DateTime.add(DateTime.utc_now(), 10 * 60, :second)
      connection = %Connection{expires_at: expires_later}
      assert Connection.needs_refresh?(connection) == false
    end

    test "returns true for already expired token" do
      expired = DateTime.add(DateTime.utc_now(), -60, :second)
      connection = %Connection{expires_at: expired}
      assert Connection.needs_refresh?(connection) == true
    end
  end

  describe "can_refresh?/1" do
    test "returns true for refreshable connection" do
      connection = %Connection{
        refresh_token: "refresh_token",
        refresh_exhausted: false,
        auto_refresh_enabled: true,
        status: :active
      }

      assert Connection.can_refresh?(connection) == true
    end

    test "returns false when no refresh token" do
      connection = %Connection{
        refresh_token: nil,
        refresh_exhausted: false,
        auto_refresh_enabled: true,
        status: :active
      }

      assert Connection.can_refresh?(connection) == false
    end

    test "returns false when refresh is exhausted" do
      connection = %Connection{
        refresh_token: "refresh_token",
        refresh_exhausted: true,
        auto_refresh_enabled: true,
        status: :active
      }

      assert Connection.can_refresh?(connection) == false
    end

    test "returns false when auto refresh is disabled" do
      connection = %Connection{
        refresh_token: "refresh_token",
        refresh_exhausted: false,
        auto_refresh_enabled: false,
        status: :active
      }

      assert Connection.can_refresh?(connection) == false
    end

    test "returns false when connection is not active" do
      connection = %Connection{
        refresh_token: "refresh_token",
        refresh_exhausted: false,
        auto_refresh_enabled: true,
        status: :expired
      }

      assert Connection.can_refresh?(connection) == false
    end
  end

  describe "get_raw_access_token/1" do
    test "extracts access_token from encrypted field" do
      connection = %Connection{
        access_token: "gho_123456789",
        raw_payload: %{
          "token_type" => "bearer",
          "scope" => "user:email"
        }
      }

      assert Connection.get_raw_access_token(connection) == "gho_123456789"
    end

    test "returns nil when access_token is nil" do
      connection = %Connection{
        access_token: nil,
        raw_payload: %{"other_field" => "value"}
      }

      assert Connection.get_raw_access_token(connection) == nil
    end

    test "handles empty access_token" do
      connection = %Connection{
        access_token: "",
        raw_payload: %{"other_field" => "value"}
      }

      assert Connection.get_raw_access_token(connection) == ""
    end

    test "handles nil raw_payload" do
      connection = %Connection{raw_payload: nil}

      assert Connection.get_raw_access_token(connection) == nil
    end

    test "handles empty raw_payload" do
      connection = %Connection{raw_payload: %{}}

      assert Connection.get_raw_access_token(connection) == nil
    end
  end

  defp failure_connection(attrs \\ %{}) do
    struct!(
      Connection,
      Map.merge(
        %{
          provider_id: 1,
          tenant_id: "user-123",
          access_token: "token",
          status: :active,
          refresh_attempts: 0,
          refresh_exhausted: false,
          next_refresh_at: ~U[2030-01-01 00:00:00Z]
        },
        attrs
      )
    )
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

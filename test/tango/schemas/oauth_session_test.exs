defmodule Tango.Schemas.OAuthSessionTest do
  use Tango.DatabaseCase, async: true

  alias Tango.Schemas.OAuthSession

  describe "changeset/2" do
    test "valid changeset with required fields" do
      attrs = %{
        provider_id: "550e8400-e29b-41d4-a716-446655440000",
        tenant_id: "user-123",
        session_token: String.duplicate("a", 32),
        state: String.duplicate("b", 32),
        expires_at: DateTime.add(DateTime.utc_now(), 3600, :second)
      }

      changeset = OAuthSession.changeset(%OAuthSession{}, attrs)
      assert changeset.valid?
    end

    test "invalid changeset without required fields" do
      changeset = OAuthSession.changeset(%OAuthSession{}, %{})
      refute changeset.valid?

      assert %{
               provider_id: ["can't be blank"],
               tenant_id: ["can't be blank"],
               session_token: ["can't be blank"],
               state: ["can't be blank"],
               expires_at: ["can't be blank"]
             } = errors_on(changeset)
    end

    test "validates session_token length" do
      base_attrs = %{
        provider_id: "550e8400-e29b-41d4-a716-446655440000",
        tenant_id: "user-123",
        state: String.duplicate("b", 32),
        expires_at: DateTime.add(DateTime.utc_now(), 3600, :second)
      }

      # Too short
      short_token = String.duplicate("a", 31)

      changeset =
        OAuthSession.changeset(%OAuthSession{}, Map.put(base_attrs, :session_token, short_token))

      errors = errors_on(changeset)
      assert "should be at least 32 character(s)" in errors[:session_token]
    end

    test "validates state length" do
      base_attrs = %{
        provider_id: "550e8400-e29b-41d4-a716-446655440000",
        tenant_id: "user-123",
        session_token: String.duplicate("a", 32),
        expires_at: DateTime.add(DateTime.utc_now(), 3600, :second)
      }

      # Too short
      short_state = String.duplicate("b", 31)

      changeset =
        OAuthSession.changeset(%OAuthSession{}, Map.put(base_attrs, :state, short_state))

      errors = errors_on(changeset)
      assert "should be at least 32 character(s)" in errors[:state]
    end

    test "validates code_verifier length" do
      base_attrs = %{
        provider_id: "550e8400-e29b-41d4-a716-446655440000",
        tenant_id: "user-123",
        session_token: String.duplicate("a", 32),
        state: String.duplicate("b", 32),
        expires_at: DateTime.add(DateTime.utc_now(), 3600, :second)
      }

      # Too short
      short_verifier = String.duplicate("c", 42)

      changeset =
        OAuthSession.changeset(
          %OAuthSession{},
          Map.put(base_attrs, :code_verifier, short_verifier)
        )

      errors = errors_on(changeset)
      assert "should be at least 43 character(s)" in errors[:code_verifier]

      # Too long
      long_verifier = String.duplicate("c", 129)

      changeset =
        OAuthSession.changeset(
          %OAuthSession{},
          Map.put(base_attrs, :code_verifier, long_verifier)
        )

      errors = errors_on(changeset)
      assert "should be at most 128 character(s)" in errors[:code_verifier]
    end

    test "validates expires_at must be in future" do
      base_attrs = %{
        provider_id: "550e8400-e29b-41d4-a716-446655440000",
        tenant_id: "user-123",
        session_token: String.duplicate("a", 32),
        state: String.duplicate("b", 32)
      }

      # Past date
      past_date = DateTime.add(DateTime.utc_now(), -3600, :second)

      changeset =
        OAuthSession.changeset(%OAuthSession{}, Map.put(base_attrs, :expires_at, past_date))

      errors = errors_on(changeset)
      assert "must be in the future" in errors[:expires_at]

      # Current time (might be considered past due to execution time)
      current_time = DateTime.utc_now()

      changeset =
        OAuthSession.changeset(%OAuthSession{}, Map.put(base_attrs, :expires_at, current_time))

      refute changeset.valid?
    end

    test "sets default values" do
      # Verify struct defaults
      session = %OAuthSession{}
      assert session.scopes == []
      assert session.metadata == %{}
    end
  end

  describe "create_session/3" do
    test "creates valid session changeset" do
      provider_id = "550e8400-e29b-41d4-a716-446655440000"
      tenant_id = "user-123"

      changeset = OAuthSession.create_session(provider_id, tenant_id)

      assert changeset.valid?
      assert get_change(changeset, :provider_id) == provider_id
      assert get_change(changeset, :tenant_id) == tenant_id

      # Verify generated tokens meet requirements
      session_token = get_change(changeset, :session_token)
      state = get_change(changeset, :state)
      code_verifier = get_change(changeset, :code_verifier)

      assert is_binary(session_token) and byte_size(session_token) >= 32
      assert is_binary(state) and byte_size(state) >= 32
      assert is_binary(code_verifier) and byte_size(code_verifier) >= 43

      # Verify expires_at is set in future
      expires_at = get_change(changeset, :expires_at)
      assert DateTime.compare(expires_at, DateTime.utc_now()) == :gt
    end

    test "creates session with metadata from options" do
      provider_id = "550e8400-e29b-41d4-a716-446655440000"
      tenant_id = "user-123"
      opts = [scopes: ["read", "write"], redirect_uri: "https://example.com/callback"]

      changeset = OAuthSession.create_session(provider_id, tenant_id, opts)

      metadata = get_change(changeset, :metadata)
      assert metadata[:scopes] == ["read", "write"]
      assert metadata[:redirect_uri] == "https://example.com/callback"
      assert Map.has_key?(metadata, :created_at)
    end

    test "generates unique tokens for different sessions" do
      provider_id = "550e8400-e29b-41d4-a716-446655440000"

      changeset1 = OAuthSession.create_session(provider_id, "user-1")
      changeset2 = OAuthSession.create_session(provider_id, "user-2")

      token1 = get_change(changeset1, :session_token)
      token2 = get_change(changeset2, :session_token)
      state1 = get_change(changeset1, :state)
      state2 = get_change(changeset2, :state)

      refute token1 == token2
      refute state1 == state2
    end
  end

  describe "generate_code_challenge/1" do
    test "generates PKCE code challenge from verifier" do
      session = %OAuthSession{code_verifier: "test_verifier_" <> String.duplicate("a", 32)}

      challenge = OAuthSession.generate_code_challenge(session)

      assert is_binary(challenge)
      # Should be URL-safe base64 encoded SHA256 hash (43 characters without padding)
      assert byte_size(challenge) == 43
      # No padding
      refute String.contains?(challenge, "=")
      # URL-safe
      refute String.contains?(challenge, "+")
      # URL-safe
      refute String.contains?(challenge, "/")
    end

    test "returns nil for session without code_verifier" do
      session = %OAuthSession{code_verifier: nil}
      assert OAuthSession.generate_code_challenge(session) == nil
    end

    test "returns nil for invalid input" do
      assert OAuthSession.generate_code_challenge(%{}) == nil
      assert OAuthSession.generate_code_challenge(nil) == nil
    end

    test "generates consistent challenge for same verifier" do
      verifier = "test_verifier_consistent"
      session = %OAuthSession{code_verifier: verifier}

      challenge1 = OAuthSession.generate_code_challenge(session)
      challenge2 = OAuthSession.generate_code_challenge(session)

      assert challenge1 == challenge2
    end
  end

  describe "validate_state/2" do
    test "validates matching state tokens" do
      expected_state = "secure_state_token_12345"
      session = %OAuthSession{state: expected_state}

      assert :ok = OAuthSession.validate_state(session, expected_state)
    end

    test "rejects mismatched state tokens" do
      session = %OAuthSession{state: "expected_state"}

      assert {:error, :invalid_state} = OAuthSession.validate_state(session, "wrong_state")
    end

    test "uses secure comparison to prevent timing attacks" do
      session = %OAuthSession{state: "state1"}

      # Even similar strings should be securely compared
      assert {:error, :invalid_state} = OAuthSession.validate_state(session, "state2")
      assert {:error, :invalid_state} = OAuthSession.validate_state(session, "state1x")
    end
  end

  describe "expired?/1" do
    test "returns true for expired session" do
      past_time = DateTime.add(DateTime.utc_now(), -3600, :second)
      session = %OAuthSession{expires_at: past_time}

      assert OAuthSession.expired?(session) == true
    end

    test "returns false for non-expired session" do
      future_time = DateTime.add(DateTime.utc_now(), 3600, :second)
      session = %OAuthSession{expires_at: future_time}

      assert OAuthSession.expired?(session) == false
    end

    test "handles edge case of current time" do
      current_time = DateTime.utc_now()
      session = %OAuthSession{expires_at: current_time}

      # Current time is technically expired (not less than now)
      assert OAuthSession.expired?(session) == true
    end
  end

  describe "valid?/1" do
    test "returns true for non-expired session" do
      future_time = DateTime.add(DateTime.utc_now(), 3600, :second)
      session = %OAuthSession{expires_at: future_time}

      assert OAuthSession.valid?(session) == true
    end

    test "returns false for expired session" do
      past_time = DateTime.add(DateTime.utc_now(), -3600, :second)
      session = %OAuthSession{expires_at: past_time}

      assert OAuthSession.valid?(session) == false
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

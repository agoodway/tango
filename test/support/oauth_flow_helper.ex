defmodule Test.Support.OAuthFlowHelper do
  @moduledoc """
  Test helpers for complete OAuth flow simulation.

  Provides realistic OAuth flow testing that matches production usage
  with proper state encoding and security validation.
  """

  alias Tango.Auth

  @doc """
  Simulates a complete OAuth flow from start to finish.

  This helper mirrors the real OAuth flow:
  1. Creates session
  2. Generates authorization URL (with encoded state)
  3. Extracts encoded state from URL
  4. Exchanges code using encoded state

  ## Examples

      {:ok, connection} = complete_oauth_flow("github", "user-123", "auth_code")
      {:error, :invalid_state} = complete_oauth_flow("github", "wrong-tenant", "auth_code")
  """
  def complete_oauth_flow(provider_name, tenant_id, authorization_code, opts \\ []) do
    with {:ok, session} <- Auth.create_session(provider_name, tenant_id, opts),
         {:ok, auth_url} <- Auth.authorize_url(session.session_token, opts),
         {:ok, encoded_state} <- extract_state_from_auth_url(auth_url) do
      Auth.exchange_code(encoded_state, authorization_code, tenant_id, opts)
    end
  end

  @doc """
  Creates session and authorization URL in one step.

  Returns both the session and the authorization URL for tests that need
  to inspect intermediate state.
  """
  def create_session_with_auth_url(provider_name, tenant_id, opts \\ []) do
    with {:ok, session} <- Auth.create_session(provider_name, tenant_id, opts),
         {:ok, auth_url} <- Auth.authorize_url(session.session_token, opts) do
      {:ok, session, auth_url}
    end
  end

  @doc """
  Extracts the encoded state parameter from an OAuth authorization URL.

  ## Examples

      {:ok, encoded_state} = extract_state_from_auth_url("https://github.com/oauth?state=abc123")
  """
  def extract_state_from_auth_url(auth_url) do
    case URI.parse(auth_url) do
      %URI{query: query} when is_binary(query) ->
        query_params = URI.decode_query(query)

        case Map.get(query_params, "state") do
          state when is_binary(state) -> {:ok, state}
          _ -> {:error, :state_not_found}
        end

      _ ->
        {:error, :invalid_url}
    end
  end

  @doc """
  Creates a session and returns the encoded state that would be used in exchange_code.

  Useful for tests that need the encoded state without going through auth URL generation.
  """
  def get_encoded_state_for_session(provider_name, tenant_id, opts \\ []) do
    with {:ok, session} <- Auth.create_session(provider_name, tenant_id, opts),
         {:ok, auth_url} <- Auth.authorize_url(session.session_token, opts),
         {:ok, encoded_state} <- extract_state_from_auth_url(auth_url) do
      {:ok, encoded_state, session}
    end
  end

  @doc """
  Test cross-tenant scenarios with proper state encoding.

  Creates a session for one tenant but tries to exchange with a different tenant,
  which should fail with our state encoding security.
  """
  def test_cross_tenant_exchange(
        provider_name,
        session_tenant_id,
        exchange_tenant_id,
        authorization_code,
        opts \\ []
      ) do
    with {:ok, session} <- Auth.create_session(provider_name, session_tenant_id, opts),
         {:ok, auth_url} <- Auth.authorize_url(session.session_token, opts),
         {:ok, encoded_state} <- extract_state_from_auth_url(auth_url) do
      # Try to exchange with different tenant_id (should fail)
      Auth.exchange_code(encoded_state, authorization_code, exchange_tenant_id, opts)
    end
  end
end

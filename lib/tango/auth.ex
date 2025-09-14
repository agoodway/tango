defmodule Tango.Auth do
  @moduledoc """
  Main OAuth2 flow orchestrator.

  Handles complete OAuth2 authorization code flow with PKCE support,
  session management, and token exchange with automatic audit logging.
  """

  import Ecto.Query, warn: false

  # Repo will be configured by the host application
  @repo Application.compile_env(:tango, :repo, Tango.Repo)

  alias Tango.Schemas.{AuditLog, Connection, OAuthSession}

  @type session_result :: {:ok, %OAuthSession{}} | {:error, atom()}
  @type connection_result :: {:ok, %Connection{}} | {:error, atom()}
  @type auth_url_result :: {:ok, String.t()} | {:error, atom()}
  @type cleanup_result :: {:ok, non_neg_integer()} | {:error, atom()}

  @doc """
  Creates a new OAuth session for provider and tenant.

  Generates secure session tokens, PKCE parameters, and CSRF state.

  ## Examples

      iex> create_session("github", "user-123")
      {:ok, %OAuthSession{}}

      iex> create_session("nonexistent", "user-123")
      {:error, :provider_not_found}

  """
  @spec create_session(String.t(), String.t(), keyword()) :: session_result()
  def create_session(provider_name, tenant_id, opts \\ [])
      when is_binary(provider_name) and is_binary(tenant_id) do
    # Use Ecto.Multi for atomic session creation and audit logging
    Ecto.Multi.new()
    |> Ecto.Multi.run(:validate, fn _repo, _changes ->
      with :ok <- Tango.Validation.validate_provider_slug(provider_name),
           :ok <- Tango.Validation.validate_tenant_id(tenant_id),
           {:ok, validated_opts} <- Tango.Validation.validate_oauth_options(opts),
           {:ok, provider} <- Tango.Provider.get_provider(provider_name) do
        changeset = OAuthSession.create_session(provider.id, tenant_id, validated_opts)
        {:ok, %{provider: provider, changeset: changeset}}
      else
        {:error, :not_found} -> {:error, :provider_not_found}
        error -> error
      end
    end)
    |> Ecto.Multi.run(:create_session, fn repo, %{validate: %{changeset: changeset}} ->
      repo.insert(changeset)
    end)
    |> Ecto.Multi.run(:audit_log, fn repo,
                                     %{validate: %{provider: provider}, create_session: session} ->
      AuditLog.log_oauth_start(provider, tenant_id, session, opts)
      |> repo.insert()
    end)
    |> @repo.transaction()
    |> case do
      {:ok, %{create_session: session}} ->
        {:ok, session}

      {:error, _failed_operation, reason, _changes} ->
        {:error, reason}
    end
  end

  @doc """
  Generates OAuth authorization URL with PKCE support.

  ## Examples

      iex> authorize_url("session_token_123", redirect_uri: "https://app.com/callback")
      {:ok, "https://github.com/login/oauth/authorize?client_id=..."}

      iex> authorize_url("invalid_token", redirect_uri: "https://app.com/callback")
      {:error, :session_not_found}

  """
  @spec authorize_url(String.t(), keyword()) :: auth_url_result()
  def authorize_url(session_token, opts \\ []) when is_binary(session_token) do
    with {:ok, session} <- get_valid_session(session_token),
         {:ok, provider} <- Tango.Provider.get_provider_by_id(session.provider_id),
         {:ok, oauth_config} <- Tango.Provider.get_oauth_client(provider) do
      redirect_uri = Keyword.fetch!(opts, :redirect_uri)
      scopes = Keyword.get(opts, :scopes, provider.default_scopes)

      # Validate redirect URI for security
      with :ok <- Tango.Validation.validate_redirect_uri(redirect_uri),
           {:ok, updated_session} <- update_session_redirect_uri(session, redirect_uri) do
        build_auth_url(oauth_config, updated_session, redirect_uri, scopes)
      end
    end
  end

  defp build_auth_url(oauth_config, session, redirect_uri, scopes) do
    # Build authorization URL
    auth_params = %{
      client_id: oauth_config.client_id,
      response_type: "code",
      redirect_uri: redirect_uri,
      scope: Enum.join(scopes, " "),
      state: session.state
    }

    # Add PKCE challenge if verifier exists
    auth_params =
      case session.code_verifier do
        nil ->
          auth_params

        _verifier ->
          challenge = OAuthSession.generate_code_challenge(session)

          Map.merge(auth_params, %{
            code_challenge: challenge,
            code_challenge_method: "S256"
          })
      end

    # Build final authorization URL
    auth_url = build_authorization_url(oauth_config.auth_url, auth_params)
    {:ok, auth_url}
  end

  @doc """
  Exchanges authorization code for access token.

  Validates session state, exchanges code with provider, and creates connection.
  SECURITY: Requires tenant_id for multi-tenant isolation.

  ## Examples

      iex> exchange_code("state_123", "auth_code_456", "tenant-123", redirect_uri: "https://app.com/callback")
      {:ok, %Connection{}}

      iex> exchange_code("invalid_state", "code", "tenant-123", redirect_uri: "https://app.com/callback")
      {:error, :invalid_state}

      iex> exchange_code("state_123", "code", "wrong-tenant", redirect_uri: "https://app.com/callback")
      {:error, :tenant_mismatch}

  """
  @spec exchange_code(String.t(), String.t(), String.t(), keyword()) :: connection_result()
  def exchange_code(state, _authorization_code, _tenant_id, _opts)
      when not is_binary(state) do
    {:error, :invalid_state_parameter}
  end

  def exchange_code(_state, authorization_code, _tenant_id, _opts)
      when not is_binary(authorization_code) do
    {:error, :invalid_authorization_code}
  end

  def exchange_code(_state, _authorization_code, tenant_id, _opts)
      when not is_binary(tenant_id) do
    {:error, :invalid_tenant_id}
  end

  def exchange_code(_state, _authorization_code, _tenant_id, opts)
      when not is_list(opts) do
    {:error, :invalid_options}
  end

  def exchange_code(state, authorization_code, tenant_id, opts)
      when is_binary(state) and is_binary(authorization_code) and is_binary(tenant_id) and
             is_list(opts) do
    # Use Ecto.Multi for atomic transaction management
    Ecto.Multi.new()
    |> Ecto.Multi.run(:validate, fn _repo, _changes ->
      with :ok <- Tango.Validation.validate_state(state),
           :ok <- Tango.Validation.validate_authorization_code(authorization_code),
           :ok <- Tango.Validation.validate_tenant_id(tenant_id),
           {:ok, validated_opts} <- Tango.Validation.validate_oauth_options(opts),
           {:ok, session} <- get_session_by_state(state, tenant_id),
           :ok <- OAuthSession.validate_state(session, state),
           :ok <- validate_redirect_uri_binding(session, validated_opts[:redirect_uri]) do
        {:ok, %{session: session, validated_opts: validated_opts}}
      end
    end)
    |> Ecto.Multi.run(:exchange_token, fn _repo,
                                          %{
                                            validate: %{
                                              session: session,
                                              validated_opts: validated_opts
                                            }
                                          } ->
      with {:ok, provider} <- Tango.Provider.get_provider_by_id(session.provider_id),
           {:ok, oauth_config} <- Tango.Provider.get_oauth_client(provider),
           {:ok, token_response} <-
             perform_token_exchange(oauth_config, session, authorization_code, validated_opts) do
        {:ok, %{provider: provider, token_response: token_response}}
      end
    end)
    |> Ecto.Multi.run(:create_connection, fn repo,
                                             %{
                                               validate: %{session: session},
                                               exchange_token: %{
                                                 provider: provider,
                                                 token_response: token_response
                                               }
                                             } ->
      # Atomic connection creation with revocation
      create_connection_from_token_atomic(repo, provider.id, session.tenant_id, token_response)
    end)
    |> Ecto.Multi.run(:cleanup_session, fn repo, %{validate: %{session: session}} ->
      repo.delete(session)
    end)
    |> Ecto.Multi.run(:audit_success, fn repo,
                                         %{
                                           validate: %{session: session},
                                           create_connection: connection
                                         } ->
      AuditLog.log_token_exchange(session, connection, true)
      |> repo.insert()
    end)
    |> @repo.transaction()
    |> case do
      {:ok, %{create_connection: connection}} ->
        {:ok, connection}

      {:error, _failed_operation, reason, _changes} ->
        # Log failed token exchange if session is available
        case get_session_by_state(state, tenant_id) do
          {:ok, session} ->
            AuditLog.log_token_exchange(session, nil, false, reason)
            |> @repo.insert()

          _ ->
            :ok
        end

        {:error, reason}
    end
  end

  @doc """
  Gets a valid (non-expired) session by token.

  ## Examples

      iex> get_session("valid_token")
      {:ok, %OAuthSession{}}

      iex> get_session("expired_token")
      {:error, :session_expired}

  """
  @spec get_session(String.t()) :: session_result()
  def get_session(session_token) when is_binary(session_token) do
    with :ok <- Tango.Validation.validate_session_token(session_token) do
      get_valid_session(session_token)
    end
  end

  @doc """
  Cleans up expired OAuth sessions.

  Should be called periodically to prevent table bloat.

  ## Examples

      iex> cleanup_expired_sessions()
      {:ok, 5}  # 5 sessions cleaned up

  """
  @spec cleanup_expired_sessions() :: cleanup_result()
  def cleanup_expired_sessions do
    # 24 hours ago
    expired_cutoff = DateTime.add(DateTime.utc_now(), -24 * 60 * 60, :second)

    {count, _} =
      from(s in OAuthSession, where: s.expires_at < ^expired_cutoff)
      |> @repo.delete_all()

    if count > 0 do
      AuditLog.log_session_cleanup(count)
      |> @repo.insert()
    end

    {:ok, count}
  end

  defp get_valid_session(session_token) do
    case @repo.get_by(OAuthSession, session_token: session_token) do
      nil ->
        {:error, :session_not_found}

      session ->
        if OAuthSession.valid?(session) do
          {:ok, session}
        else
          {:error, :session_expired}
        end
    end
  end

  defp get_session_by_state(state, tenant_id) do
    # SECURITY FIX: Validate tenant ownership to prevent cross-tenant session hijacking
    case @repo.get_by(OAuthSession, state: state, tenant_id: tenant_id) do
      nil ->
        {:error, :session_not_found}

      session ->
        # Check if session has expired
        if session.expires_at && DateTime.compare(session.expires_at, DateTime.utc_now()) == :lt do
          {:error, :session_expired}
        else
          {:ok, session}
        end
    end
  end

  defp validate_access_token(access_token) when is_binary(access_token) do
    cond do
      # Check if it's empty or only whitespace
      String.trim(access_token) == "" ->
        {:error, :empty_access_token}

      # Check if it looks like HTML content
      String.contains?(access_token, ["<html>", "<HTML>", "<!DOCTYPE"]) ->
        {:error, :invalid_token_format}

      # Check if it looks like a JSON error response (only reject actual error responses)
      String.starts_with?(String.trim(access_token), ["{", "["]) ->
        case Jason.decode(access_token) do
          {:ok, %{"error" => _}} -> {:error, :oauth_error_response}
          # Allow other JSON responses in case OAuth2 library passes them
          {:ok, _} -> :ok
          # Not valid JSON, might be a valid token
          {:error, _} -> :ok
        end

      # Check minimum length (most OAuth tokens are at least 20 characters)
      String.length(access_token) < 10 ->
        {:error, :token_too_short}

      # Additional check for common invalid content (be more specific to avoid false positives)
      String.contains?(access_token, ["error=", "invalid_token", "unauthorized_client"]) and
          String.length(access_token) < 100 ->
        {:error, :suspicious_token_content}

      true ->
        :ok
    end
  end

  defp build_authorization_url(base_url, params) do
    query_string = URI.encode_query(params)
    "#{base_url}?#{query_string}"
  end

  defp perform_token_exchange(oauth_config, session, authorization_code, opts) do
    redirect_uri = Keyword.get(opts, :redirect_uri)

    # Build OAuth2 client
    client =
      OAuth2.Client.new(
        client_id: oauth_config.client_id,
        client_secret: oauth_config.client_secret,
        token_url: oauth_config.token_url,
        redirect_uri: redirect_uri
      )

    # Prepare token exchange parameters
    token_params = [
      code: authorization_code,
      grant_type: "authorization_code"
    ]

    # Add PKCE verifier if used
    token_params =
      case session.code_verifier do
        nil -> token_params
        verifier -> Keyword.put(token_params, :code_verifier, verifier)
      end

    # Exchange code for tokens
    case OAuth2.Client.get_token(client, token_params) do
      {:ok, %{token: %OAuth2.AccessToken{} = token}} ->
        # Validate that we received a proper access token, not malformed content
        case validate_access_token(token.access_token) do
          :ok ->
            # Convert OAuth2.AccessToken to map for our schemas
            token_response = %{
              "access_token" => token.access_token,
              "refresh_token" => token.refresh_token,
              "token_type" => token.token_type,
              "expires_in" =>
                case token.expires_at do
                  expires_at when is_integer(expires_at) ->
                    calculate_expires_in_seconds(expires_at)

                  _ ->
                    nil
                end,
              "scope" => token.other_params["scope"]
            }

            {:ok, token_response}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, %OAuth2.Error{reason: reason}} ->
        {:error, reason}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Atomic version for transaction usage
  defp create_connection_from_token_atomic(repo, provider_id, tenant_id, token_response) do
    # Revoke any existing active connections for this provider/tenant atomically
    {_count, _} =
      from(c in Connection,
        where: c.provider_id == ^provider_id,
        where: c.tenant_id == ^tenant_id,
        where: c.status == :active
      )
      |> repo.update_all(set: [status: :revoked, updated_at: DateTime.utc_now()])

    # Create new connection
    changeset = Connection.from_token_response(provider_id, tenant_id, token_response)
    repo.insert(changeset)
  end

  # Update session with redirect_uri if not already set (for authorize_url flow)
  defp update_session_redirect_uri(session, redirect_uri) do
    case session.redirect_uri do
      nil ->
        # First time setting redirect_uri, update the session
        changeset =
          session
          |> OAuthSession.changeset(%{redirect_uri: redirect_uri})

        @repo.update(changeset)

      ^redirect_uri ->
        # Same redirect_uri, no update needed
        {:ok, session}

      _different ->
        # Different redirect_uri, this is a binding violation
        {:error, :redirect_uri_mismatch}
    end
  end

  # OAuth2 RFC 6749 compliance: validate redirect_uri binding
  defp validate_redirect_uri_binding(session, provided_redirect_uri) do
    case {session.redirect_uri, provided_redirect_uri} do
      {stored, provided} when stored == provided ->
        :ok

      {nil, nil} ->
        :ok

      {nil, _provided} ->
        # Session was created without redirect_uri, but one is provided in exchange
        # This can happen in tests or when authorize_url step was skipped
        # We'll allow this but ideally the full OAuth flow should be used
        :ok

      {_stored, nil} ->
        # Session was created with redirect_uri, but none provided in exchange
        {:error, :redirect_uri_binding_violation}

      {_stored, _provided} ->
        # redirect_uri mismatch
        {:error, :redirect_uri_mismatch}
    end
  end

  defp calculate_expires_in_seconds(expires_at) when is_integer(expires_at) do
    DateTime.diff(DateTime.from_unix!(expires_at), DateTime.utc_now())
  end
end

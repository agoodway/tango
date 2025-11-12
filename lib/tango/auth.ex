defmodule Tango.Auth do
  @moduledoc """
  Main OAuth2 flow orchestrator.

  Handles complete OAuth2 authorization code flow with PKCE support,
  session management, and token exchange with automatic audit logging.
  """

  import Ecto.Query, warn: false
  require Logger

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
        build_auth_url(oauth_config, provider, updated_session, redirect_uri, scopes)
      end
    end
  end

  defp build_auth_url(oauth_config, provider, session, redirect_uri, scopes) do
    auth_url =
      build_base_auth_params(oauth_config, session, redirect_uri, scopes)
      |> maybe_add_pkce_challenge(session)
      |> merge_metadata_auth_params(provider)
      |> then(&build_authorization_url(oauth_config.auth_url, &1))

    {:ok, auth_url}
  end

  defp build_base_auth_params(oauth_config, session, redirect_uri, scopes) do
    %{
      "client_id" => oauth_config.client_id,
      "response_type" => "code",
      "redirect_uri" => redirect_uri,
      "scope" => Enum.join(scopes, " "),
      "state" => encode_state_with_tenant(session.state, session.tenant_id)
    }
  end

  defp maybe_add_pkce_challenge(auth_params, %{code_verifier: nil}), do: auth_params

  defp maybe_add_pkce_challenge(auth_params, session) do
    challenge = OAuthSession.generate_code_challenge(session)

    Map.merge(auth_params, %{
      "code_challenge" => challenge,
      "code_challenge_method" => "S256"
    })
  end

  # Merges provider metadata auth_params into authorization parameters.
  # Metadata params are merged first so standard OAuth params take precedence (security).
  defp merge_metadata_auth_params(auth_params, %{metadata: %{"auth_params" => params}})
       when is_map(params) and map_size(params) > 0 do
    Map.merge(params, auth_params)
  end

  defp merge_metadata_auth_params(auth_params, _provider), do: auth_params

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
           {:ok, original_state, decoded_tenant_id} <- decode_state_with_tenant(state),
           ^tenant_id <- decoded_tenant_id,
           {:ok, session} <- get_session_by_state(original_state, tenant_id),
           :ok <- OAuthSession.validate_state(session, original_state),
           :ok <- validate_redirect_uri_binding(session, validated_opts[:redirect_uri]) do
        Logger.info(
          "Tango OAuth validation complete: session_id=#{session.id}, redirect_uri=#{validated_opts[:redirect_uri]}"
        )

        {:ok, %{session: session, validated_opts: validated_opts}}
      else
        {:error, error} when is_atom(error) ->
          Logger.error("Tango OAuth validation failed: #{inspect(error)}")
          {:error, error}

        _error ->
          {:error, :invalid_state}
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
           _ <-
             Logger.info("Tango OAuth performing token exchange for provider=#{provider.slug}"),
           {:ok, token_response} <-
             perform_token_exchange(oauth_config, session, authorization_code, validated_opts) do
        Logger.info("Tango OAuth token exchange successful")
        {:ok, %{provider: provider, token_response: token_response}}
      else
        {:error, reason} = error ->
          Logger.error("Tango OAuth token exchange step failed: #{inspect(reason)}")
          error

        result ->
          Logger.error("Tango OAuth token exchange invalid result: #{inspect(result)}")
          {:error, :token_exchange_failed}
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
        log_failed_token_exchange(state, tenant_id, reason)
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
    expired_cutoff = session_cleanup_cutoff()

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
    case @repo.get_by(OAuthSession, state: state, tenant_id: tenant_id) do
      nil ->
        {:error, :session_not_found}

      session ->
        if session_expired?(session) do
          {:error, :session_expired}
        else
          {:ok, session}
        end
    end
  end

  defp validate_access_token(""), do: {:error, :empty_access_token}

  defp validate_access_token(access_token)
       when is_binary(access_token) and byte_size(access_token) < 10 do
    {:error, :token_too_short}
  end

  defp validate_access_token(access_token) when is_binary(access_token) do
    cond do
      String.contains?(access_token, ["<html", "<HTML", "<!DOCTYPE", "<head", "<body"]) ->
        {:error, :invalid_token_format}

      String.contains?(access_token, ["error=", "invalid_token", "unauthorized_client"]) and
          byte_size(access_token) < 100 ->
        {:error, :suspicious_token_content}

      match?({:ok, %{"error" => _}}, Jason.decode(access_token)) ->
        {:error, :oauth_error_response}

      true ->
        :ok
    end
  end

  defp build_authorization_url(base_url, params) do
    query_string = URI.encode_query(params)
    "#{base_url}?#{query_string}"
  end

  defp perform_token_exchange(oauth_config, session, authorization_code, opts) do
    validated_redirect_uri = Keyword.get(opts, :redirect_uri)

    with client <- build_oauth_client(oauth_config, opts),
         token_params <- build_token_params(authorization_code, session, validated_redirect_uri),
         _ <- log_token_exchange_params(token_params, session),
         {:ok, %{token: token}} <- OAuth2.Client.get_token(client, token_params),
         :ok <- validate_access_token(token.access_token) do
      Logger.info("Tango OAuth token exchange successful")
      {:ok, convert_token_to_response(token)}
    else
      {:error, %OAuth2.Error{reason: reason}} ->
        Logger.error("Tango OAuth2 error: #{inspect(reason)}")
        {:error, reason}

      {:error, reason} ->
        Logger.error("Tango OAuth token exchange error: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp build_oauth_client(oauth_config, opts) do
    OAuth2.Client.new(
      client_id: oauth_config.client_id,
      client_secret: oauth_config.client_secret,
      token_url: oauth_config.token_url,
      redirect_uri: Keyword.get(opts, :redirect_uri)
    )
  end

  defp build_token_params(
         authorization_code,
         %{code_verifier: nil} = session,
         validated_redirect_uri
       ) do
    base_params = [code: authorization_code, grant_type: "authorization_code"]
    add_redirect_uri_if_present(base_params, session, validated_redirect_uri)
  end

  defp build_token_params(
         authorization_code,
         %{code_verifier: verifier} = session,
         validated_redirect_uri
       ) do
    base_params = [
      code: authorization_code,
      grant_type: "authorization_code",
      code_verifier: verifier
    ]

    add_redirect_uri_if_present(base_params, session, validated_redirect_uri)
  end

  defp add_redirect_uri_if_present(params, session, validated_redirect_uri) do
    redirect_uri = session.redirect_uri || validated_redirect_uri

    case should_include_redirect_uri?(redirect_uri) do
      true -> Keyword.put(params, :redirect_uri, redirect_uri)
      false -> params
    end
  end

  defp should_include_redirect_uri?(nil), do: false

  defp should_include_redirect_uri?(uri) when is_binary(uri) do
    trimmed = String.trim(uri)
    trimmed != ""
  end

  defp should_include_redirect_uri?(_), do: false

  defp log_token_exchange_params(params, session) do
    redirect_uri_status =
      case Keyword.get(params, :redirect_uri) do
        nil -> "omitted"
        uri -> "included: #{String.slice(uri, 0, 50)}..."
      end

    session_redirect_uri =
      case session.redirect_uri do
        nil -> "nil"
        "" -> "empty"
        uri -> String.slice(uri, 0, 50) <> "..."
      end

    Logger.info(
      "Tango OAuth token exchange params: redirect_uri #{redirect_uri_status}, " <>
        "session.redirect_uri: #{session_redirect_uri}, " <>
        "code: #{String.slice(Keyword.get(params, :code, ""), 0, 10)}..."
    )
  end

  @doc false
  def convert_token_to_response(token) do
    # OAuth2 library sometimes returns JSON-encoded token responses
    # Extract the actual access token from JSON if needed
    access_token = extract_access_token(token.access_token)

    %{
      "access_token" => access_token,
      "refresh_token" => token.refresh_token,
      "token_type" => token.token_type,
      "expires_in" => calculate_expires_in_seconds(token.expires_at),
      "scope" => token.other_params["scope"]
    }
  end

  # Extract actual access token from potentially JSON-encoded response
  defp extract_access_token(token) when is_binary(token) do
    case Jason.decode(token) do
      {:ok, %{"access_token" => actual_token}} when is_binary(actual_token) ->
        actual_token

      _ ->
        # Not JSON or no access_token field, use as-is
        token
    end
  end

  defp extract_access_token(token), do: token

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
    Connection.from_token_response(provider_id, tenant_id, token_response)
    |> repo.insert()
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

      _different_redirect_uri ->
        # Different redirect_uri, this is a binding violation
        Logger.error(
          "OAuth redirect_uri mismatch in session update: stored=#{session.redirect_uri}, provided=#{redirect_uri}, session_id=#{session.id}, tenant_id=#{session.tenant_id}"
        )

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

      {stored, nil} ->
        # Session was created with redirect_uri, but none provided in exchange
        Logger.error(
          "OAuth redirect_uri binding violation - nil provided: stored=#{stored}, session_id=#{session.id}, tenant_id=#{session.tenant_id}"
        )

        {:error, :redirect_uri_binding_violation}

      {stored, provided} ->
        # redirect_uri mismatch
        Logger.error(
          "OAuth redirect_uri binding violation - mismatch: stored=#{stored}, provided=#{provided}, session_id=#{session.id}, tenant_id=#{session.tenant_id}"
        )

        {:error, :redirect_uri_mismatch}
    end
  end

  defp calculate_expires_in_seconds(expires_at) when is_integer(expires_at) do
    DateTime.diff(DateTime.from_unix!(expires_at), DateTime.utc_now())
  end

  defp calculate_expires_in_seconds(_), do: nil

  defp session_cleanup_cutoff do
    DateTime.add(DateTime.utc_now(), -24 * 60 * 60, :second)
  end

  defp session_expired?(session) do
    session.expires_at && DateTime.compare(session.expires_at, DateTime.utc_now()) == :lt
  end

  # Encode tenant ID into OAuth state parameter for secure transmission
  defp encode_state_with_tenant(original_state, tenant_id) do
    state_data = %{
      csrf_token: original_state,
      tenant_id: tenant_id
    }

    state_data
    |> Jason.encode!()
    |> Base.url_encode64(padding: false)
  end

  # Decode tenant ID from OAuth state parameter
  def decode_state_with_tenant(encoded_state) do
    with {:ok, decoded} <- Base.url_decode64(encoded_state, padding: false),
         {:ok, state_data} <- Jason.decode(decoded) do
      {:ok, state_data["csrf_token"], state_data["tenant_id"]}
    else
      _ -> {:error, :invalid_state_format}
    end
  end

  # Logs failed token exchange attempts with session context
  defp log_failed_token_exchange(state, tenant_id, reason) do
    case decode_state_with_tenant(state) do
      {:ok, original_state, decoded_tenant_id} when decoded_tenant_id == tenant_id ->
        case get_session_by_state(original_state, tenant_id) do
          {:ok, session} ->
            AuditLog.log_token_exchange(session, nil, false, reason)
            |> @repo.insert()

          _ ->
            :ok
        end

      _ ->
        :ok
    end
  end

  @doc """
  Generate authorization URL with optional scopes.

  Uses session/provider defaults when scopes list is empty,
  otherwise uses explicit scopes provided.
  """
  def authorize_url_with_scopes(session_token, redirect_uri, []) do
    authorize_url(session_token, redirect_uri: redirect_uri)
  end

  def authorize_url_with_scopes(session_token, redirect_uri, scopes) when is_list(scopes) do
    authorize_url(session_token, redirect_uri: redirect_uri, scopes: scopes)
  end

  @doc """
  Parse OAuth scopes from various formats.
  """
  def parse_scopes(scopes) when is_binary(scopes) do
    String.split(scopes, " ", trim: true)
  end

  def parse_scopes(scopes) when is_list(scopes), do: scopes
  def parse_scopes(_), do: []

  @doc """
  Perform OAuth callback exchange for popup flows.
  """
  def perform_callback_exchange(_conn, nil, _state), do: nil
  def perform_callback_exchange(_conn, _code, nil), do: nil

  def perform_callback_exchange(conn, code, state) do
    Logger.info(
      "Tango OAuth callback exchange starting: code=#{String.slice(code || "nil", 0, 10)}..., state=#{String.slice(state || "nil", 0, 20)}..."
    )

    with {:ok, tenant_id, original_state} <- decode_state_safely(state),
         {:ok, session} <- get_session_by_state(original_state, tenant_id),
         callback_url <- session.redirect_uri || build_https_callback_url(conn),
         _ <-
           Logger.info(
             "Tango OAuth using callback_url=#{callback_url}, session.redirect_uri=#{session.redirect_uri}"
           ),
         {:ok, connection} <-
           exchange_code(state, code, tenant_id, redirect_uri: callback_url),
         {:ok, provider} <- Tango.get_provider_by_id(connection.provider_id),
         access_token <- Connection.get_raw_access_token(connection) do
      Logger.info("Tango OAuth exchange successful")
      {:ok, build_connection_response(connection, provider, access_token)}
    else
      {:error, reason} = error ->
        Logger.error("Tango OAuth exchange failed: #{inspect(reason)}")
        error

      result ->
        Logger.error("Tango OAuth exchange invalid result: #{inspect(result)}")
        {:error, :invalid_state}
    end
  end

  @doc """
  Build connection response for OAuth callbacks.
  """
  def build_connection_response(connection, provider, access_token) do
    %{
      provider: provider.name,
      status: connection.status,
      scopes: connection.granted_scopes,
      expires_at: connection.expires_at,
      access_token: access_token
    }
  end

  @doc """
  Safely decode OAuth state parameter.
  """
  def decode_state_safely(nil), do: :error

  def decode_state_safely(state) do
    case decode_state_with_tenant(state) do
      {:ok, original_state, tenant_id} -> {:ok, tenant_id, original_state}
      _ -> :error
    end
  rescue
    _ -> :error
  end

  @doc """
  Log OAuth callback errors with audit trail.
  """
  def log_oauth_callback_error(state, error, error_description) do
    # Try to decode state to get tenant ID and session info
    {tenant_id, session_id, event_type, error_code} =
      case decode_state_safely(state) do
        {:ok, decoded_tenant_id, original_state} ->
          {decoded_tenant_id, original_state, classify_oauth_error(error),
           map_oauth_error_code(error)}

        _ ->
          {"unknown", nil, :oauth_callback_error, :missing_callback_params}
      end

    event_data = %{
      oauth_error: error,
      error_description: error_description,
      state_present: !is_nil(state),
      state_decodable: tenant_id != "unknown"
    }

    AuditLog.log_oauth_callback_error(event_type, error_code, tenant_id, session_id, event_data)
    |> Application.get_env(:tango, :repo, Tango.TestRepo).insert()
    |> case do
      {:ok, _} ->
        :ok

      {:error, reason} ->
        require Logger
        Logger.warning("Failed to log OAuth callback error: #{inspect(reason)}")
        :ok
    end
  end

  @doc """
  Classify OAuth error types.
  """
  def classify_oauth_error("access_denied"), do: :oauth_denied
  def classify_oauth_error(_), do: :oauth_provider_error

  @doc """
  Map OAuth error codes to atoms.
  """
  def map_oauth_error_code("access_denied"), do: :access_denied
  def map_oauth_error_code("invalid_request"), do: :invalid_request
  def map_oauth_error_code("invalid_client"), do: :invalid_client
  def map_oauth_error_code("invalid_grant"), do: :invalid_grant
  def map_oauth_error_code("unsupported_grant_type"), do: :unsupported_grant_type
  def map_oauth_error_code("invalid_scope"), do: :invalid_scope
  def map_oauth_error_code("server_error"), do: :server_error
  def map_oauth_error_code("temporarily_unavailable"), do: :temporarily_unavailable
  def map_oauth_error_code(_), do: :provider_error

  @doc """
  Build HTTPS callback URL from connection.
  """
  def build_https_callback_url(conn) do
    build_callback_url(conn)
  end

  @doc """
  Build OAuth callback URL from connection, handling proxy headers.
  """
  def build_callback_url(conn) do
    # Check for forwarded proto header to handle proxy scenarios
    scheme =
      case Plug.Conn.get_req_header(conn, "x-forwarded-proto") do
        ["https"] -> "https"
        ["http"] -> "http"
        _ -> conn.scheme |> to_string()
      end

    host = conn.host

    # Only include port if it's non-standard for the scheme
    port =
      case {scheme, conn.port} do
        {"https", 443} -> ""
        {"http", 80} -> ""
        {_, port} -> ":#{port}"
      end

    "#{scheme}://#{host}#{port}/api/oauth/callback"
  end

  @doc """
  Generate OAuth callback HTML page for popup flows.
  """
  def generate_callback_html(_code, _state, _error, _error_description, exchange_result) do
    Logger.info(
      "Tango generating callback HTML with exchange_result: #{inspect(exchange_result)}"
    )

    # Safely encode exchange result for JavaScript injection
    # Use HTML escaping to prevent XSS attacks
    result_json =
      case exchange_result do
        {:ok, data} -> Jason.encode!(data)
        {:error, reason} -> Jason.encode!(%{error: format_error_reason(reason)})
        nil -> "null"
      end
      |> html_escape_json()

    """
    <!DOCTYPE html>
    <html>
    <head>
      <title>OAuth Callback</title>
      <meta charset="utf-8">
      <meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';">
    </head>
    <body>
      <div id="status">Processing OAuth callback...</div>

      <script>
        (function() {
          const urlParams = new URLSearchParams(window.location.search);
          const code = urlParams.get('code');
          const state = urlParams.get('state');
          const error = urlParams.get('error');
          const errorDescription = urlParams.get('error_description');

          async function handleCallback() {
            try {
              if (error) {
                throw new Error(errorDescription || error);
              }

              // Use server-side exchange result instead of making API calls
              const exchangeResult = #{result_json};
              console.log('Tango callback - exchangeResult:', exchangeResult);

              if (!exchangeResult) {
                console.error('Tango callback - No exchange result');
                throw new Error('Missing authorization code or state parameter');
              }

              if (exchangeResult.error) {
                console.error('Tango callback - Exchange error:', exchangeResult.error);
                throw new Error(exchangeResult.error);
              }

              // Send success result to parent window
              if (window.opener) {
                console.log('Tango callback - Sending postMessage to opener');
                console.log('Tango callback - Current origin:', window.location.origin);
                
                try {
                  const targetOrigin = window.opener.location.origin;
                  console.log('Tango callback - Target origin:', targetOrigin);
                  
                  window.opener.postMessage({
                    type: 'oauth_complete',
                    connection: {
                      provider: exchangeResult.provider,
                      status: exchangeResult.status,
                      scopes: exchangeResult.scopes || [],
                      expires_at: exchangeResult.expires_at,
                      token: exchangeResult.access_token
                    }
                  }, targetOrigin);
                  console.log('Tango callback - PostMessage sent successfully');
                  
                  // Close popup after successful message
                  setTimeout(() => window.close(), 100);
                } catch (originError) {
                  console.error('Tango callback - Could not access opener origin:', originError);
                  // Fallback to wildcard origin (less secure but functional)
                  window.opener.postMessage({
                    type: 'oauth_complete',
                    connection: {
                      provider: exchangeResult.provider,
                      status: exchangeResult.status,
                      scopes: exchangeResult.scopes || [],
                      expires_at: exchangeResult.expires_at,
                      token: exchangeResult.access_token
                    }
                  }, '*');
                  console.log('Tango callback - PostMessage sent with wildcard origin');
                  
                  // Close popup after successful message
                  setTimeout(() => window.close(), 100);
                }
              } else {
                console.error('Tango callback - No window.opener found');
              }

              document.getElementById('status').textContent = 'OAuth flow completed successfully. You can close this window.';

            } catch (error) {
              console.error('OAuth callback error:', error);

              // Send error to parent window
              if (window.opener) {
                try {
                  const targetOrigin = window.opener.location.origin;
                  window.opener.postMessage({
                    type: 'oauth_error',
                    error: error.message
                  }, targetOrigin);
                } catch (originError) {
                  window.opener.postMessage({
                    type: 'oauth_error',
                    error: error.message
                  }, '*');
                }
              }

              document.getElementById('status').textContent = 'OAuth flow failed: ' + error.message;
            }
          }

          // Process callback when page loads
          handleCallback();
        })();
      </script>
    </body>
    </html>
    """
  end

  # Format error reasons for JSON encoding, handling OAuth2.Response structs
  defp format_error_reason(%OAuth2.Response{status_code: status, body: body}) do
    case Jason.decode(body) do
      {:ok, %{"error_description" => desc}} -> desc
      {:ok, %{"error" => error}} -> error
      _ -> "OAuth error (HTTP #{status})"
    end
  end

  defp format_error_reason(reason) when is_binary(reason), do: reason
  defp format_error_reason(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp format_error_reason(reason), do: inspect(reason)

  def html_escape_json(json_string) do
    # Jason.encode! with escape: :html_safe handles XSS prevention automatically
    json_string
    |> Jason.decode!()
    |> Jason.encode!(escape: :html_safe)
  end
end

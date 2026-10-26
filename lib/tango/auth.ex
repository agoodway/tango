defmodule Tango.Auth do
  @moduledoc """
  Main OAuth2 flow orchestrator.

  Handles complete OAuth2 authorization code flow with PKCE support,
  session management, and token exchange with automatic audit logging.
  """

  import Ecto.Query, warn: false
  require Logger

  defp repo, do: Application.get_env(:tango, :repo) || raise("Tango :repo not configured")

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
    create_session_transaction(provider_name, tenant_id, opts, :legacy)
  end

  @doc """
  Creates an authorization session whose scopes, redirect, completion origin,
  and provider parameters are bound at creation.
  """
  @spec create_authorization_session(String.t(), String.t(), keyword()) :: session_result()
  def create_authorization_session(provider_name, tenant_id, opts)
      when is_binary(provider_name) and is_binary(tenant_id) and is_list(opts) do
    create_session_transaction(provider_name, tenant_id, opts, :authorization)
  end

  defp create_session_transaction(provider_name, tenant_id, opts, mode) do
    # Use Ecto.Multi for atomic session creation and audit logging
    Ecto.Multi.new()
    |> Ecto.Multi.run(:validate, fn repo, _changes ->
      with :ok <- Tango.Validation.validate_provider_slug(provider_name),
           :ok <- Tango.Validation.validate_tenant_id(tenant_id),
           {:ok, provider} <- Tango.Provider.get_provider(provider_name),
           {:ok, oauth_config} <- Tango.Provider.get_oauth_client(provider),
           {:ok, validated_opts} <-
             validate_session_options(repo, provider, tenant_id, opts, mode) do
        session_opts =
          validated_opts
          |> Keyword.put(:oauth_client_id, oauth_config.client_id)

        changeset = OAuthSession.create_session(provider.id, tenant_id, session_opts)
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
    |> repo().transaction()
    |> case do
      {:ok, %{create_session: session}} ->
        {:ok, session}

      {:error, _failed_operation, reason, _changes} ->
        {:error, reason}
    end
  end

  defp validate_session_options(_repo, _provider, _tenant_id, opts, :legacy) do
    with {:ok, validated_opts} <- Tango.Validation.validate_oauth_options(opts) do
      # Keep empty scopes unbound so authorize_url/2 can still supply them (0.1.x).
      scopes = validated_opts[:scopes] || []
      {:ok, Keyword.put(validated_opts, :scopes, scopes)}
    end
  end

  defp validate_session_options(repo, provider, tenant_id, opts, :authorization) do
    scopes = Keyword.get(opts, :scopes, provider.default_scopes)
    redirect_uri = Keyword.get(opts, :redirect_uri)
    completion_origin = Keyword.get(opts, :completion_origin)
    intent_reference = Keyword.get(opts, :intent_reference)
    expires_at = Keyword.get(opts, :expires_at)
    auth_params = Keyword.get(opts, :auth_params, %{})

    with :ok <- Tango.Validation.validate_redirect_uri(redirect_uri),
         :ok <- Tango.Validation.validate_scopes(scopes),
         :ok <- Tango.Validation.validate_completion_origin(completion_origin),
         :ok <- validate_intent_reference(intent_reference),
         :ok <- validate_expiration(expires_at),
         {:ok, auth_params} <- Tango.Validation.validate_auth_params(auth_params),
         {:ok, expected} <-
           validate_expected_connection(
             repo,
             provider,
             tenant_id,
             Keyword.get(opts, :expected_connection_id),
             Keyword.get(opts, :expected_subject)
           ) do
      {:ok,
       [
         scopes: scopes,
         redirect_uri: redirect_uri,
         completion_origin: completion_origin,
         intent_reference: intent_reference,
         expires_at: expires_at,
         auth_params: auth_params,
         expected_connection_id: expected.id,
         expected_subject: expected.subject
       ]}
    end
  end

  defp validate_intent_reference(reference)
       when is_binary(reference) and byte_size(reference) > 0 and byte_size(reference) <= 255,
       do: :ok

  defp validate_intent_reference(_), do: {:error, :invalid_intent_reference}

  defp validate_expiration(nil), do: :ok

  defp validate_expiration(%DateTime{} = expires_at) do
    now = DateTime.utc_now()
    session_timeout = Application.get_env(:tango, :session_timeout, 30 * 60)
    maximum = DateTime.add(now, session_timeout, :second)

    if DateTime.compare(expires_at, now) == :gt and
         DateTime.compare(expires_at, maximum) in [:lt, :eq] do
      :ok
    else
      {:error, :invalid_expiration}
    end
  end

  defp validate_expiration(_), do: {:error, :invalid_expiration}

  defp validate_expected_connection(_repo, _provider, _tenant_id, nil, nil),
    do: {:ok, %{id: nil, subject: nil}}

  defp validate_expected_connection(_repo, _provider, _tenant_id, nil, _subject),
    do: {:error, :stale_connection}

  defp validate_expected_connection(repo, provider, tenant_id, connection_id, expected_subject)
       when is_integer(connection_id) do
    case repo.get_by(Connection,
           id: connection_id,
           provider_id: provider.id,
           tenant_id: tenant_id
         ) do
      %Connection{} = connection ->
        with :ok <- validate_expected_generation(repo, connection),
             {:ok, subject} <-
               validate_expected_subject(connection.account_subject, expected_subject) do
          {:ok, %{id: connection.id, subject: subject}}
        end

      nil ->
        {:error, :stale_connection}
    end
  end

  defp validate_expected_connection(_repo, _provider, _tenant_id, _id, _subject),
    do: {:error, :stale_connection}

  defp validate_expected_generation(repo, %Connection{status: status} = connection)
       when status in [:active, :expired] do
    if Tango.ConnectionLock.other_active_generation?(
         repo,
         connection.provider_id,
         connection.tenant_id,
         connection.id
       ),
       do: {:error, :stale_connection},
       else: :ok
  end

  defp validate_expected_generation(_repo, %Connection{}), do: {:error, :stale_connection}

  defp validate_expected_subject(nil, nil), do: {:ok, nil}
  defp validate_expected_subject(nil, subject) when is_binary(subject), do: {:ok, subject}
  defp validate_expected_subject(subject, nil) when is_binary(subject), do: {:ok, subject}
  defp validate_expected_subject(subject, subject), do: {:ok, subject}
  defp validate_expected_subject(_known, _provided), do: {:error, :account_mismatch}

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
      redirect_uri = Keyword.get(opts, :redirect_uri, session.redirect_uri)

      scopes =
        case session.scopes do
          [] -> Keyword.get(opts, :scopes, provider.default_scopes)
          scopes -> scopes
        end

      # Validate redirect URI for security
      with :ok <- Tango.Validation.validate_redirect_uri(redirect_uri),
           {:ok, updated_session} <- update_session_redirect_uri(session, redirect_uri) do
        build_auth_url(oauth_config, provider, updated_session, redirect_uri, scopes)
      end
    end
  end

  @doc """
  Generates an authorization URL from the values bound to a session.
  """
  @spec authorization_url(OAuthSession.t()) :: auth_url_result()
  def authorization_url(%OAuthSession{} = session) do
    with false <- OAuthSession.expired?(session),
         redirect_uri when is_binary(redirect_uri) <- session.redirect_uri,
         {:ok, provider} <- Tango.Provider.get_provider_by_id(session.provider_id),
         {:ok, oauth_config} <- Tango.Provider.get_oauth_client(provider),
         :ok <- Tango.Validation.validate_redirect_uri(redirect_uri) do
      build_auth_url(oauth_config, provider, session, redirect_uri, session.scopes)
    else
      true -> {:error, :session_expired}
      nil -> {:error, :invalid_redirect_uri}
      error -> error
    end
  end

  defp build_auth_url(oauth_config, provider, session, redirect_uri, scopes) do
    provider_params = metadata_auth_params(provider)
    session_params = session.auth_params || %{}

    auth_params =
      provider_params
      |> Map.merge(session_params)
      |> Map.merge(build_base_auth_params(oauth_config, provider, session, redirect_uri, scopes))
      |> maybe_add_pkce_challenge(session, pkce_disabled?(provider))

    Logger.info(
      "Tango OAuth building authorization URL: provider=#{provider.slug}, " <>
        "has_metadata_auth_params=#{inspect(Map.has_key?(provider.metadata, "auth_params"))}, " <>
        "final_auth_params_keys=#{inspect(Map.keys(auth_params))}"
    )

    {:ok, build_authorization_url(oauth_config.auth_url, auth_params)}
  end

  defp build_base_auth_params(oauth_config, provider, session, redirect_uri, scopes) do
    %{
      "client_id" => session.oauth_client_id || oauth_config.client_id,
      "response_type" => "code",
      "redirect_uri" => redirect_uri,
      "scope" => Enum.join(scopes, scope_separator(provider)),
      "state" => encode_state_with_tenant(session.state, session.tenant_id)
    }
  end

  # Nango catalog `scope_separator` (default " "), recorded in provider metadata.
  defp scope_separator(%{metadata: %{"scope_separator" => separator}})
       when is_binary(separator) and separator != "",
       do: separator

  defp scope_separator(_provider), do: " "

  # Nango catalog `disable_pkce`: no code_challenge on the authorization URL
  # and no code_verifier on the code exchange.
  defp pkce_disabled?(%{metadata: %{"disable_pkce" => true}}), do: true
  defp pkce_disabled?(_provider), do: false

  defp maybe_add_pkce_challenge(auth_params, _session, true), do: auth_params
  defp maybe_add_pkce_challenge(auth_params, %{code_verifier: nil}, false), do: auth_params

  defp maybe_add_pkce_challenge(auth_params, session, false) do
    challenge = OAuthSession.generate_code_challenge(session)

    Map.merge(auth_params, %{
      "code_challenge" => challenge,
      "code_challenge_method" => "S256"
    })
  end

  defp metadata_auth_params(%{metadata: %{"auth_params" => params}})
       when is_map(params) and map_size(params) > 0 do
    params
  end

  defp metadata_auth_params(_provider), do: %{}

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
           :ok <- reject_staged_session(session),
           :ok <- OAuthSession.validate_state(session, original_state),
           :ok <- validate_redirect_uri_binding(session, validated_opts[:redirect_uri]) do
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
           {:ok, token} <-
             perform_token_exchange(
               oauth_config,
               provider,
               session,
               authorization_code,
               validated_opts
             ) do
        {:ok, %{provider: provider, token_response: convert_token_to_response(token)}}
      else
        {:error, reason} ->
          safe_reason = safe_exchange_error(reason)
          Logger.error("Tango OAuth token exchange failed: #{inspect(safe_reason)}")
          {:error, safe_reason}

        _result ->
          Logger.error("Tango OAuth token exchange failed: :token_exchange_failed")
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
    |> repo().transaction()
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
      |> repo().delete_all()

    if count > 0 do
      AuditLog.log_session_cleanup(count)
      |> repo().insert()
    end

    {:ok, count}
  end

  defp get_valid_session(session_token) do
    case repo().get_by(OAuthSession, session_token: session_token) do
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
    case repo().get_by(OAuthSession, state: state, tenant_id: tenant_id) do
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

  defp validate_access_token(nil), do: {:error, :empty_access_token}

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

  # Staged sessions complete only through Tango.stage_authorization/4 and a
  # trusted verifier; the immediate exchange never consumes them.
  defp reject_staged_session(%OAuthSession{} = session) do
    if staged_session?(session), do: {:error, :invalid_session}, else: :ok
  end

  @doc """
  Returns true when the session carries staged-authorization bindings (a
  completion origin or an intent reference).

  Staged sessions complete only through `Tango.stage_authorization/4`.
  """
  def staged_session?(%OAuthSession{completion_origin: origin, intent_reference: reference}),
    do: not is_nil(origin) or not is_nil(reference)

  # Reduces a failed token exchange to an atom or `{:oauth_error, category}` so
  # provider response bodies and headers never reach logs or callers.
  defp safe_exchange_error(%OAuth2.Response{} = response), do: sanitize_oauth_error(response)
  defp safe_exchange_error(%OAuth2.Error{reason: reason}), do: safe_exchange_error(reason)
  defp safe_exchange_error({:oauth_error, _category} = error), do: error
  defp safe_exchange_error(reason) when is_atom(reason), do: reason
  defp safe_exchange_error(_reason), do: :token_exchange_failed

  defp perform_token_exchange(oauth_config, provider, session, authorization_code, opts) do
    validated_redirect_uri = Keyword.get(opts, :redirect_uri)
    session = if pkce_disabled?(provider), do: %{session | code_verifier: nil}, else: session
    token_params = build_token_params(authorization_code, session, validated_redirect_uri)

    with {:ok, %{token: token}} <-
           Tango.TokenRequest.exchange(
             oauth_config,
             provider.metadata,
             token_params,
             validated_redirect_uri
           ),
         :ok <- validate_access_token(token.access_token) do
      {:ok, token}
    else
      {:error, %OAuth2.Error{reason: reason}} ->
        {:error, reason}

      {:error, reason} ->
        {:error, reason}
    end
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

    if should_include_redirect_uri?(redirect_uri) do
      Keyword.put(params, :redirect_uri, redirect_uri)
    else
      params
    end
  end

  defp should_include_redirect_uri?(nil), do: false

  defp should_include_redirect_uri?(uri) when is_binary(uri) do
    trimmed = String.trim(uri)
    trimmed != ""
  end

  defp should_include_redirect_uri?(_), do: false

  @doc """
  Exchanges an authorization code for the session's provider and returns the raw
  token response, with `"provider_data"` holding the fields the provider's
  `"token_response_metadata"` retains (see `Tango.TokenResponseMetadata`).

  Fails with `{:error, :client_changed}` when the provider's OAuth client no
  longer matches the client recorded on the session. Other failures are reduced
  to `{:error, atom}` or `{:error, {:oauth_error, category}}`; provider response
  bodies are never returned.
  """
  def exchange_authorization_code(%OAuthSession{} = session, authorization_code, redirect_uri)
      when is_binary(authorization_code) and is_binary(redirect_uri) do
    with {:ok, provider} <- Tango.Provider.get_provider_by_id(session.provider_id),
         {:ok, oauth_config} <- Tango.Provider.get_oauth_client(provider),
         true <- oauth_config.client_id == session.oauth_client_id,
         {:ok, token} <-
           perform_token_exchange(oauth_config, provider, session, authorization_code,
             redirect_uri: redirect_uri
           ),
         {:ok, provider_data} <-
           Tango.TokenResponseMetadata.extract(token.other_params, provider.metadata) do
      {:ok, Map.put(convert_token_to_response(token), "provider_data", provider_data)}
    else
      false -> {:error, :client_changed}
      {:error, reason} -> {:error, sanitize_oauth_error(reason)}
      _ -> {:error, {:oauth_error, :provider_error}}
    end
  end

  defp sanitize_oauth_error({:oauth_error, _category} = error), do: error

  defp sanitize_oauth_error(%OAuth2.Response{body: body}),
    do: {:oauth_error, oauth_error_category(body)}

  defp sanitize_oauth_error(%OAuth2.Error{reason: reason}), do: sanitize_oauth_error(reason)
  defp sanitize_oauth_error(reason) when is_atom(reason), do: {:oauth_error, reason}
  defp sanitize_oauth_error(reason), do: {:oauth_error, oauth_error_category(reason)}

  defp oauth_error_category(%{"error" => error}), do: map_oauth_error_code(error)

  defp oauth_error_category(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> oauth_error_category(decoded)
      _ -> :provider_error
    end
  end

  defp oauth_error_category(_), do: :provider_error

  @doc """
  Converts an `OAuth2.AccessToken` into the string-keyed token response map used
  by connection creation.
  """
  def convert_token_to_response(token) do
    access_token = extract_access_token(token.access_token)

    response = %{
      "access_token" => access_token,
      "refresh_token" => token.refresh_token,
      "token_type" => token.token_type,
      "expires_in" => calculate_expires_in_seconds(token.expires_at)
    }

    if Map.has_key?(token.other_params, "scope"),
      do: Map.put(response, "scope", token.other_params["scope"]),
      else: response
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
    :ok = Tango.ConnectionLock.lock(repo, provider_id, tenant_id)

    # Revoke any existing active connections for this provider/tenant atomically
    {_count, _} =
      from(c in Connection,
        where: c.provider_id == ^provider_id,
        where: c.tenant_id == ^tenant_id,
        where: c.status == :active
      )
      |> repo.update_all(set: [status: :revoked, updated_at: DateTime.utc_now()])

    # Create new connection
    Tango.RedactedParams.insert(
      repo,
      Connection.from_token_response(provider_id, tenant_id, token_response)
    )
  end

  # Update session with redirect_uri if not already set (for authorize_url flow)
  defp update_session_redirect_uri(session, redirect_uri) do
    case session.redirect_uri do
      nil ->
        # First time setting redirect_uri, update the session
        changeset =
          session
          |> OAuthSession.changeset(%{redirect_uri: redirect_uri})

        repo().update(changeset)

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
        # RFC 6749 §4.1.3: redirect URI binding required
        # If session didn't store a redirect_uri, exchange must fail
        {:error, :redirect_uri_mismatch}

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
  def decode_state_with_tenant(encoded_state) when is_binary(encoded_state) do
    with {:ok, decoded} <- Base.url_decode64(encoded_state, padding: false),
         {:ok, %{} = state_data} <- Jason.decode(decoded),
         csrf when is_binary(csrf) and byte_size(csrf) > 0 <- state_data["csrf_token"],
         tenant when is_binary(tenant) and byte_size(tenant) > 0 <- state_data["tenant_id"] do
      {:ok, csrf, tenant}
    else
      _ -> {:error, :invalid_state_format}
    end
  end

  def decode_state_with_tenant(_), do: {:error, :invalid_state_format}

  # Logs failed token exchange attempts with session context
  defp log_failed_token_exchange(state, tenant_id, reason) do
    case decode_state_with_tenant(state) do
      {:ok, original_state, decoded_tenant_id} when decoded_tenant_id == tenant_id ->
        case get_session_by_state(original_state, tenant_id) do
          {:ok, session} ->
            AuditLog.log_token_exchange(session, nil, false, audit_error_code(reason))
            |> repo().insert()

          _ ->
            :ok
        end

      _ ->
        :ok
    end
  end

  @doc """
  Maps an exchange failure to an enumerated audit error code.

  Audit rows store only enumerated categories, never provider payloads; anything
  unrecognized becomes `:unknown_error`.
  """
  def audit_error_code({:oauth_error, category}), do: audit_error_code(category)

  def audit_error_code(reason) when is_atom(reason) do
    if reason in Ecto.Enum.values(AuditLog, :error_code), do: reason, else: :unknown_error
  end

  def audit_error_code(_reason), do: :unknown_error

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
  Parse OAuth scopes from space- or comma-separated strings, or lists.
  """
  defdelegate parse_scopes(scopes), to: Tango.Validation

  @type callback_result :: %{payload: map() | nil, origin: String.t() | nil}

  @doc """
  Completes a popup OAuth callback by staging the authorization code.

  Only sessions created with `create_authorization_session/3` can complete
  here. The code is exchanged into an encrypted, short-lived candidate and the
  result carries only the opaque completion handle plus the session's intent
  reference. Failures carry a stable category and the intent reference. Neither
  shape includes tokens or provider response bodies.

  Returns `%{payload: payload, origin: origin}`, where `origin` is the session's
  validated completion origin. When the callback cannot be tied to a staged
  session with an allowed origin, both values are `nil` and nothing is posted.
  """
  @spec process_popup_callback(map()) :: callback_result()
  def process_popup_callback(params) when is_map(params) do
    state = params["state"]
    error = binary_param(params["error"])

    if error, do: log_oauth_callback_error(state, error, params["error_description"])

    case Tango.Authorization.callback_context(state) do
      {:ok, context} -> popup_result(context, state, error, binary_param(params["code"]))
      {:error, _reason} -> %{payload: nil, origin: nil}
    end
  end

  def process_popup_callback(_params), do: %{payload: nil, origin: nil}

  defp popup_result(context, _state, error, _code) when is_binary(error),
    do: popup_failure(context, map_oauth_error_code(error))

  defp popup_result(context, _state, nil, nil),
    do: popup_failure(context, :missing_callback_params)

  defp popup_result(context, state, nil, code) do
    case Tango.Authorization.stage_authorization(state, code, context.tenant_id,
           redirect_uri: context.redirect_uri
         ) do
      {:ok, completion} ->
        %{
          origin: context.completion_origin,
          payload: %{
            type: "oauth_complete",
            completion_handle: completion.completion_handle,
            intent_reference: completion.intent_reference
          }
        }

      {:error, reason} ->
        popup_failure(context, reason)
    end
  end

  defp popup_failure(context, reason) do
    %{
      origin: context.completion_origin,
      payload: %{
        type: "oauth_error",
        error: callback_error_category(reason),
        intent_reference: context.intent_reference
      }
    }
  end

  @stable_callback_categories [:invalid_session, :client_changed, :invalid_authorization_code]

  defp callback_error_category({:oauth_error, category}) when is_atom(category),
    do: Atom.to_string(category)

  defp callback_error_category(reason) when reason in @stable_callback_categories,
    do: Atom.to_string(reason)

  defp callback_error_category(reason) when is_atom(reason) do
    if reason in Ecto.Enum.values(AuditLog, :error_code),
      do: Atom.to_string(reason),
      else: "callback_failed"
  end

  defp callback_error_category(_reason), do: "callback_failed"

  defp binary_param(value) when is_binary(value) and value != "", do: value
  defp binary_param(_value), do: nil

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

  The audit row stores the mapped error category and a hash of the session
  state. The provider's raw error code and description are not persisted.
  """
  def log_oauth_callback_error(state, error, error_description) do
    # Try to decode state to get tenant ID and session info
    {tenant_id, session_id, event_type, error_code} =
      case decode_state_safely(state) do
        {:ok, decoded_tenant_id, original_state}
        when is_binary(decoded_tenant_id) and is_binary(original_state) ->
          {decoded_tenant_id, hash_state(original_state), classify_oauth_error(error),
           map_oauth_error_code(error)}

        _ ->
          {"unknown", nil, :oauth_callback_error, :missing_callback_params}
      end

    event_data = %{
      oauth_error: Atom.to_string(error_code),
      has_error_description: is_binary(error_description) and error_description != "",
      state_present: !is_nil(state),
      state_decodable: tenant_id != "unknown"
    }

    AuditLog.log_oauth_callback_error(event_type, error_code, tenant_id, session_id, event_data)
    |> repo().insert()
    |> case do
      {:ok, _} ->
        :ok

      {:error, _changeset} ->
        Logger.warning("Failed to log OAuth callback error")
        :ok
    end
  end

  defp hash_state(state), do: :crypto.hash(:sha256, state) |> Base.encode16(case: :lower)

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
  def map_oauth_error_code("unauthorized_client"), do: :unauthorized_client
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

  # frame-ancestors is ignored when delivered in a <meta> element, so it is
  # added only to the response header.
  @callback_csp_directives [
    "default-src 'none'",
    "script-src 'unsafe-inline'",
    "base-uri 'none'",
    "form-action 'none'"
  ]

  @doc """
  Content Security Policy sent with the popup callback page.
  """
  def callback_content_security_policy do
    Enum.join(@callback_csp_directives ++ ["frame-ancestors 'none'"], "; ")
  end

  # Interpolated into a double-quoted attribute, so only `&` and `"` need
  # escaping; CSP source keywords keep their single quotes readable.
  defp callback_meta_content_security_policy do
    @callback_csp_directives
    |> Enum.join("; ")
    |> String.replace(["&", "\""], fn
      "&" -> "&amp;"
      "\"" -> "&quot;"
    end)
  end

  @doc """
  Generates the popup callback page for a `process_popup_callback/1` result.

  The page posts the payload to the session's exact completion origin and never
  falls back to a wildcard target. Payload and origin are encoded with
  `script_json/1` so they cannot break out of the script element.
  """
  @spec generate_callback_html(callback_result()) :: String.t()
  def generate_callback_html(%{payload: payload, origin: origin}) do
    {status, payload_json, origin_json} = callback_page_values(payload, origin)

    """
    <!DOCTYPE html>
    <html>
    <head>
      <title>OAuth Callback</title>
      <meta charset="utf-8">
      <meta http-equiv="Content-Security-Policy" content="#{callback_meta_content_security_policy()}">
      <meta name="referrer" content="no-referrer">
    </head>
    <body>
      <div id="status">#{status}</div>
      <script>
        (function() {
          const payload = #{payload_json};
          const completionOrigin = #{origin_json};

          if (payload && completionOrigin && window.opener) {
            window.opener.postMessage(payload, completionOrigin);
            window.close();
          }
        })();
      </script>
    </body>
    </html>
    """
  end

  defp callback_page_values(%{type: type} = payload, origin)
       when type in ["oauth_complete", "oauth_error"] and is_binary(origin),
       do: {status_text(type), script_json(payload), script_json(origin)}

  defp callback_page_values(_payload, _origin),
    do: {"This OAuth callback could not be completed. You can close this window.", "null", "null"}

  defp status_text("oauth_complete"), do: "OAuth flow completed. You can close this window."
  defp status_text("oauth_error"), do: "OAuth flow failed. You can close this window."

  @doc """
  Encodes a term as JSON that is safe to embed inside an HTML `<script>` element.

  `<`, `>`, `&`, and the JavaScript line separators are written as unicode
  escapes, so no value can close the element or open an HTML comment.
  """
  @spec script_json(term()) :: String.t()
  def script_json(term) do
    term
    |> Jason.encode!()
    |> String.replace(["<", ">", "&", "\u2028", "\u2029"], fn
      "<" -> "\\u003c"
      ">" -> "\\u003e"
      "&" -> "\\u0026"
      "\u2028" -> "\\u2028"
      "\u2029" -> "\\u2029"
    end)
  end
end

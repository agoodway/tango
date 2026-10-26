defmodule Tango.Authorization do
  @moduledoc """
  Stages and verifies short-lived OAuth authorization candidates.
  """

  import Ecto.Query

  alias Tango.Schemas.{
    AuditLog,
    Authorization,
    Connection,
    OAuthSession,
    Provider
  }

  @candidate_lifetime_seconds 10 * 60
  @maximum_claims_bytes 4 * 1024
  @reserved_claim_keys ~w(
    access_token refresh_token id_token token authorization
    cookie cookies header headers client_secret
  )
  @transient_verifier_errors ~w(
    network_error timeout temporarily_unavailable provider_unavailable
  )a
  # Failures caused by the candidate's own state rather than the verifier's answer.
  @candidate_state_errors ~w(
    invalid_completion expired_completion completion_consumed intent_mismatch stale_connection
    completion_mode_mismatch
  )a

  defp repo, do: Application.get_env(:tango, :repo) || raise("Tango :repo not configured")

  @doc """
  Exchanges a claimed OAuth session into an encrypted, short-lived candidate.
  """
  def stage_authorization(encoded_state, authorization_code, tenant_id, opts)
      when is_binary(encoded_state) and is_binary(authorization_code) and
             is_binary(tenant_id) and is_list(opts) do
    redirect_uri = Keyword.get(opts, :redirect_uri)

    with :ok <- Tango.Validation.validate_authorization_code(authorization_code),
         :ok <- Tango.Validation.validate_tenant_id(tenant_id),
         :ok <- Tango.Validation.validate_redirect_uri(redirect_uri),
         {:ok, session} <- claim_session(encoded_state, tenant_id, redirect_uri),
         {:ok, token_response} <-
           exchange_staged_code(session, authorization_code, redirect_uri),
         {:ok, completion} <- insert_candidate(session, token_response) do
      {:ok, completion}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_session}
    end
  end

  def stage_authorization(_encoded_state, _authorization_code, _tenant_id, _opts),
    do: {:error, :invalid_session}

  @doc false
  # Resolves the routing data a popup callback needs from the state alone: the
  # tenant, the bound redirect URI, the intent reference, and the completion
  # origin. Only staged sessions whose origin is still allowed resolve, so a
  # callback can never be delivered to an unvalidated origin. Read-only; the
  # session is claimed later by `stage_authorization/4`.
  def callback_context(encoded_state) when is_binary(encoded_state) do
    with {:ok, tenant_id, original_state}
         when is_binary(tenant_id) and is_binary(original_state) <-
           Tango.Auth.decode_state_safely(encoded_state),
         %OAuthSession{} = session <-
           repo().get_by(OAuthSession, state: original_state, tenant_id: tenant_id),
         true <- Tango.Auth.staged_session?(session),
         true <- is_binary(session.redirect_uri) and is_binary(session.intent_reference),
         :ok <- Tango.Validation.validate_completion_origin(session.completion_origin) do
      {:ok,
       %{
         tenant_id: tenant_id,
         redirect_uri: session.redirect_uri,
         intent_reference: session.intent_reference,
         completion_origin: session.completion_origin
       }}
    else
      _ -> {:error, :invalid_session}
    end
  end

  def callback_context(_encoded_state), do: {:error, :invalid_session}

  @doc """
  Deletes expired and consumed authorization candidates.

  Credential columns are wiped before the rows are deleted, so token ciphertext
  never outlives the candidate even if deletion is delayed. Consumed candidates
  already have their tokens cleared by finalization; expired candidates that
  were never consumed are marked consumed as they are wiped. When anything was
  deleted, a `:session_expired` audit entry records the count and cleanup type
  only: no handle, token, or claim data.

  Returns `{:ok, deleted_count}`.
  """
  @spec cleanup_expired_authorizations() :: {:ok, non_neg_integer()} | {:error, term()}
  def cleanup_expired_authorizations do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    stale =
      from(candidate in Authorization,
        where: candidate.expires_at <= ^now or not is_nil(candidate.consumed_at)
      )

    repo().transaction(fn ->
      {_wiped, _} =
        repo().update_all(
          stale,
          set: [
            access_token: nil,
            refresh_token: nil,
            provider_data: %{},
            consumed_at: now
          ]
        )

      {deleted, _} = repo().delete_all(stale)

      if deleted > 0 do
        %{cleanup_type: "authorization_candidates", expired_authorizations_count: deleted}
        |> then(&AuditLog.log_system_event(:session_expired, true, &1))
        |> repo().insert!()
      end

      deleted
    end)
  end

  @doc """
  Verifies a staged candidate and stores only its safe identity proof.
  """
  def multi_finalize_authorization(multi, name, handle, tenant_id, opts)
      when is_binary(handle) and is_binary(tenant_id) and is_list(opts) do
    Ecto.Multi.run(multi, name, fn transaction_repo, _changes ->
      finalize_in_transaction(transaction_repo, handle, tenant_id, opts)
    end)
  end

  @doc """
  Atomically consumes a verified authorization and returns its safe identity proof.

  The named Multi step creates no connection. Host writes and credential erasure
  commit together, so a later step's failure leaves the authorization reusable.
  """
  @spec multi_consume_authorization(Ecto.Multi.t(), term(), binary(), binary(), keyword()) ::
          Ecto.Multi.t()
  def multi_consume_authorization(multi, name, handle, tenant_id, opts)
      when is_binary(handle) and is_binary(tenant_id) and is_list(opts) do
    Ecto.Multi.run(multi, name, fn transaction_repo, _changes ->
      consume_in_transaction(transaction_repo, handle, tenant_id, opts)
    end)
  end

  def multi_consume_authorization(multi, name, handle, tenant_id, opts) do
    Ecto.Multi.run(multi, name, fn transaction_repo, _changes ->
      with :ok <- validate_transaction_repo(transaction_repo) do
        validate_completion_input(handle, tenant_id, opts)
      end
    end)
  end

  defp consume_in_transaction(transaction_repo, handle, tenant_id, opts) do
    with :ok <- validate_transaction_repo(transaction_repo),
         :ok <- validate_completion_input(handle, tenant_id, opts),
         :ok <- validate_completion_options(opts, :consume),
         {:ok, hash} <- decode_handle(handle),
         {:ok, candidate, provider} <- lock_candidate(hash, tenant_id),
         :ok <- validate_completion_mode(candidate, :consume),
         :ok <- validate_candidate_bindings(candidate, provider, opts),
         :ok <- validate_verification_provider(candidate, provider),
         :ok <- validate_candidate_state(candidate, tenant_id),
         :ok <- validate_consumed_subject(candidate),
         :ok <- validate_required_scopes(candidate, opts),
         {:ok, consumed} <- consume_candidate(transaction_repo, candidate) do
      {:ok, completion_summary(consumed, provider.slug)}
    end
  end

  defp finalize_in_transaction(transaction_repo, handle, tenant_id, opts) do
    with :ok <- validate_transaction_repo(transaction_repo),
         :ok <- validate_completion_options(opts, :connection),
         {:ok, hash} <- decode_handle(handle),
         {:ok, routing} <- load_candidate_routing(hash, tenant_id),
         :ok <- validate_completion_mode(routing, :connection),
         :ok <-
           Tango.ConnectionLock.lock(
             transaction_repo,
             routing.provider_id,
             routing.tenant_id
           ),
         {:ok, candidate, provider} <- lock_candidate(hash, tenant_id),
         :ok <- validate_completion_mode(candidate, :connection),
         :ok <- validate_verification_snapshot(routing, candidate),
         :ok <- validate_finalize_candidate(candidate, provider, tenant_id, opts),
         {:ok, current} <- lock_expected_generation(transaction_repo, candidate),
         :ok <- validate_finalize_generation(transaction_repo, candidate, current),
         :ok <- validate_required_scopes(candidate, opts),
         {:ok, refresh_token} <- finalized_refresh_token(candidate, current, opts),
         {:ok, connection} <-
           insert_finalized_connection(transaction_repo, candidate, current, refresh_token),
         {:ok, consumed} <- consume_candidate(transaction_repo, candidate) do
      {:ok,
       %{
         connection: connection,
         authorization: completion_summary(consumed, provider.slug)
       }}
    end
  end

  defp validate_completion_input(handle, tenant_id, opts)
       when is_binary(handle) and is_binary(tenant_id) do
    if is_list(opts), do: :ok, else: {:error, :invalid_completion_options}
  end

  defp validate_completion_input(_handle, _tenant_id, _opts),
    do: {:error, :invalid_completion}

  defp validate_completion_options(opts, mode) do
    with true <- Keyword.keyword?(opts),
         false <- invalid_completion_options?(opts, mode),
         :ok <- validate_required_completion_options(opts, mode) do
      validate_completion_scopes(Keyword.get(opts, :required_scopes, []))
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_completion_options}
    end
  end

  defp validate_completion_scopes([]), do: :ok

  defp validate_completion_scopes([scope | rest]) do
    with :ok <- Tango.Validation.validate_scopes([scope]) do
      validate_completion_scopes(rest)
    end
  end

  defp validate_completion_scopes(_scopes), do: {:error, :invalid_scopes}

  defp validate_required_completion_options(opts, :consume) do
    with {:ok, _provider} <- required_option(opts, :provider),
         {:ok, _intent} <- required_option(opts, :intent_reference) do
      :ok
    end
  end

  defp validate_required_completion_options(_opts, :connection), do: :ok

  defp invalid_completion_options?(opts, :consume),
    do:
      Enum.any?(Keyword.keys(opts), &(&1 not in [:provider, :intent_reference, :required_scopes]))

  defp invalid_completion_options?(opts, :connection),
    do: Keyword.has_key?(opts, :completion_mode)

  defp validate_completion_mode(%Authorization{completion_mode: mode}, mode), do: :ok
  defp validate_completion_mode(_candidate, _mode), do: {:error, :completion_mode_mismatch}

  defp validate_consumed_subject(%Authorization{expected_subject: nil}), do: :ok

  defp validate_consumed_subject(%Authorization{
         expected_subject: subject,
         account_subject: subject
       }),
       do: :ok

  defp validate_consumed_subject(_candidate), do: {:error, :account_mismatch}

  defp validate_transaction_repo(transaction_repo) do
    if transaction_repo == repo(), do: :ok, else: {:error, :repo_mismatch}
  end

  defp validate_finalize_candidate(candidate, provider, tenant_id, opts) do
    with :ok <- validate_candidate_state(candidate, tenant_id) do
      validate_candidate_bindings(candidate, provider, opts)
    end
  end

  defp validate_candidate_state(candidate, tenant_id) do
    cond do
      candidate.tenant_id != tenant_id ->
        {:error, :invalid_completion}

      candidate.consumed_at ->
        {:error, :completion_consumed}

      expired?(candidate.expires_at) ->
        {:error, :expired_completion}

      is_nil(candidate.verified_at) or is_nil(candidate.account_subject) ->
        {:error, :verification_required}

      token_expired?(candidate.token_expires_at) ->
        {:error, :token_expired}

      true ->
        :ok
    end
  end

  defp validate_candidate_bindings(candidate, provider, opts) do
    cond do
      candidate.intent_reference != Keyword.get(opts, :intent_reference) ->
        {:error, :intent_mismatch}

      not match?(%Provider{}, provider) or provider.slug != Keyword.get(opts, :provider) ->
        {:error, :invalid_completion}

      true ->
        validate_connection_bindings(candidate, provider, opts)
    end
  end

  defp validate_connection_bindings(%Authorization{completion_mode: :consume}, _provider, _opts),
    do: :ok

  defp validate_connection_bindings(candidate, provider, opts) do
    cond do
      candidate.expected_connection_id != Keyword.get(opts, :expected_connection_id) ->
        {:error, :stale_connection}

      candidate.verified_connection_id != candidate.expected_connection_id ->
        {:error, :verification_required}

      oauth_client_id(provider) != candidate.oauth_client_id ->
        {:error, :client_changed}

      true ->
        :ok
    end
  end

  defp lock_expected_generation(_transaction_repo, %Authorization{
         expected_connection_id: nil
       }),
       do: {:ok, nil}

  defp lock_expected_generation(transaction_repo, candidate) do
    current =
      candidate
      |> expected_connection_query()
      |> lock("FOR UPDATE")
      |> transaction_repo.one()

    if current, do: {:ok, current}, else: {:error, :stale_connection}
  end

  # The connection a candidate replaces, scoped to the candidate's provider and tenant.
  defp expected_connection_query(%Authorization{} = candidate) do
    from(connection in Connection,
      where: connection.id == ^candidate.expected_connection_id,
      where: connection.provider_id == ^candidate.provider_id,
      where: connection.tenant_id == ^candidate.tenant_id
    )
  end

  defp validate_finalize_generation(transaction_repo, candidate, nil) do
    if other_active_generation?(transaction_repo, candidate, nil),
      do: {:error, :stale_connection},
      else: :ok
  end

  defp validate_finalize_generation(transaction_repo, candidate, current) do
    cond do
      current.status not in [:active, :expired] ->
        {:error, :stale_connection}

      not is_nil(current.account_subject) and
          current.account_subject != candidate.account_subject ->
        {:error, :account_mismatch}

      other_active_generation?(transaction_repo, candidate, current.id) ->
        {:error, :stale_connection}

      true ->
        :ok
    end
  end

  defp other_active_generation?(repo, %Authorization{} = candidate, excluded_id) do
    Tango.ConnectionLock.other_active_generation?(
      repo,
      candidate.provider_id,
      candidate.tenant_id,
      excluded_id
    )
  end

  defp validate_required_scopes(candidate, opts) do
    required = Keyword.get(opts, :required_scopes, [])
    granted = MapSet.new(candidate.granted_scopes || [])

    if Enum.all?(required, &MapSet.member?(granted, &1)),
      do: :ok,
      else: {:error, :missing_scopes}
  end

  defp finalized_refresh_token(%Authorization{refresh_token: refresh_token}, _current, _opts)
       when is_binary(refresh_token),
       do: {:ok, refresh_token}

  defp finalized_refresh_token(candidate, current, opts),
    do: refresh_token_for(candidate, current, Keyword.get(opts, :require_refresh_token, false))

  defp refresh_token_for(_candidate, nil, true), do: {:error, :refresh_token_required}
  defp refresh_token_for(_candidate, nil, _required?), do: {:ok, nil}

  # Nothing to retain: skip client/subject continuity and scope-subset checks that only
  # matter when carrying an existing refresh token forward.
  defp refresh_token_for(_candidate, %Connection{refresh_token: nil}, true),
    do: {:error, :refresh_token_required}

  defp refresh_token_for(_candidate, %Connection{refresh_token: nil}, _required?),
    do: {:ok, nil}

  defp refresh_token_for(candidate, current, required?) do
    case validate_refresh_continuity(candidate, current) do
      :ok ->
        retained_refresh_token(candidate, current, required?)

      # Legacy (0.1.x / exchange_code) connections lack client or subject metadata, so
      # continuity cannot be proven. Never carry the old refresh token across that
      # boundary: drop it, unless the caller requires a refresh token.
      {:unverifiable, reason} ->
        if required?, do: {:error, reason}, else: {:ok, nil}

      {:error, _reason} = error ->
        error
    end
  end

  defp validate_refresh_continuity(candidate, current) do
    cond do
      is_nil(current.oauth_client_id) ->
        {:unverifiable, :client_changed}

      current.oauth_client_id != candidate.oauth_client_id ->
        {:error, :client_changed}

      is_nil(current.account_subject) ->
        {:unverifiable, :account_mismatch}

      current.account_subject != candidate.account_subject ->
        {:error, :account_mismatch}

      true ->
        :ok
    end
  end

  defp retained_refresh_token(candidate, current, required?) do
    cond do
      not scope_subset?(candidate.granted_scopes, current.granted_scopes) ->
        if required?, do: {:error, :refresh_token_required}, else: {:ok, nil}

      required? and is_nil(current.refresh_token) ->
        {:error, :refresh_token_required}

      true ->
        {:ok, current.refresh_token}
    end
  end

  defp scope_subset?(candidate_scopes, current_scopes) do
    MapSet.subset?(MapSet.new(candidate_scopes || []), MapSet.new(current_scopes || []))
  end

  defp insert_finalized_connection(transaction_repo, candidate, current, refresh_token) do
    with :ok <- revoke_current_generation(transaction_repo, current) do
      Tango.RedactedParams.insert(
        transaction_repo,
        Connection.changeset(%Connection{}, %{
          provider_id: candidate.provider_id,
          tenant_id: candidate.tenant_id,
          account_subject: candidate.account_subject,
          oauth_client_id: candidate.oauth_client_id,
          access_token: candidate.access_token,
          refresh_token: refresh_token,
          token_type: finalized_token_type(candidate.token_type),
          expires_at: candidate.token_expires_at,
          granted_scopes: candidate.granted_scopes,
          status: :active,
          last_used_at: DateTime.utc_now() |> DateTime.truncate(:second)
        })
      )
      |> normalize_finalize_write()
    end
  end

  defp revoke_current_generation(_transaction_repo, nil), do: :ok

  defp revoke_current_generation(transaction_repo, %Connection{status: status} = current)
       when status in [:active, :expired] do
    current
    |> Connection.changeset(%{status: :revoked})
    |> transaction_repo.update()
    |> case do
      {:ok, _connection} -> :ok
      {:error, _changeset} -> {:error, :stale_connection}
    end
  end

  defp consume_candidate(transaction_repo, candidate) do
    candidate
    |> Authorization.changeset(%{
      consumed_at: DateTime.utc_now() |> DateTime.truncate(:second),
      access_token: nil,
      refresh_token: nil,
      provider_data: %{}
    })
    |> transaction_repo.update()
    |> normalize_finalize_write()
  end

  defp normalize_finalize_write({:ok, value}), do: {:ok, value}
  defp normalize_finalize_write({:error, _changeset}), do: {:error, :invalid_completion}

  defp finalized_token_type(token_type) when token_type in ["token", :token], do: :token
  defp finalized_token_type(_token_type), do: :bearer

  defp oauth_client_id(provider) do
    case Provider.get_oauth_credentials(provider) do
      {:ok, oauth_client} -> oauth_client.client_id
      _ -> nil
    end
  end

  defp token_expired?(nil), do: false
  defp token_expired?(expires_at), do: DateTime.compare(expires_at, DateTime.utc_now()) != :gt

  def verify_authorization(handle, tenant_id, {verifier, verifier_opts}, opts)
      when is_binary(handle) and is_binary(tenant_id) and is_atom(verifier) and
             is_list(verifier_opts) and is_list(opts) do
    with {:ok, intent_reference} <- required_option(opts, :intent_reference),
         {:ok, provider_slug} <- required_option(opts, :provider),
         {:ok, candidate, provider} <-
           load_candidate(handle, tenant_id, intent_reference, provider_slug),
         {:ok, verification} <-
           verifier.verify(
             provider,
             credential(candidate),
             verifier_options(verifier_opts, candidate.expected_connection_id)
           ),
         :ok <-
           validate_verification(
             %{
               connection_id: candidate.expected_connection_id,
               subject: candidate.expected_subject
             },
             verification
           ),
         {:ok, verified} <-
           persist_verification(
             candidate,
             tenant_id,
             intent_reference,
             provider_slug,
             verification
           ) do
      {:ok, authorization_summary(verified, provider.slug)}
    else
      {:error, reason} = error ->
        maybe_consume_after_verifier_failure(handle, tenant_id, reason)
        error

      _ ->
        maybe_consume_after_verifier_failure(handle, tenant_id, :invalid_claims)
        {:error, :invalid_claims}
    end
  end

  def verify_authorization(_handle, _tenant_id, _verifier, _opts),
    do: {:error, :invalid_completion}

  @doc """
  Verifies and, when absent, binds the subject of an active connection.
  """
  def verify_connection_identity(connection_id, tenant_id, {verifier, verifier_opts})
      when is_integer(connection_id) and is_binary(tenant_id) and is_atom(verifier) and
             is_list(verifier_opts) do
    with {:ok, connection, provider} <- load_connection(connection_id, tenant_id),
         {:ok, verification} <-
           verifier.verify(
             provider,
             credential(connection),
             verifier_options(verifier_opts, connection.id)
           ),
         :ok <-
           validate_verification(
             %{connection_id: connection.id, subject: connection.account_subject},
             verification
           ),
         {:ok, _connection} <- bind_connection_subject(connection, verification.subject) do
      {:ok, %{subject: verification.subject, claims: verification.claims}}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_claims}
    end
  end

  def verify_connection_identity(_connection_id, _tenant_id, _verifier),
    do: {:error, :not_found}

  defp claim_session(encoded_state, tenant_id, redirect_uri) do
    case Tango.Auth.decode_state_with_tenant(encoded_state) do
      {:ok, original_state, ^tenant_id} ->
        repo().transaction(fn ->
          claim_locked_session(original_state, tenant_id, redirect_uri)
        end)
        |> unwrap_transaction()

      _ ->
        {:error, :invalid_session}
    end
  end

  defp claim_locked_session(original_state, tenant_id, redirect_uri) do
    session =
      from(session in OAuthSession,
        where: session.state == ^original_state,
        where: session.tenant_id == ^tenant_id,
        lock: "FOR UPDATE"
      )
      |> repo().one()

    with :ok <- validate_claimable_session(session, redirect_uri),
         :ok <- validate_session_client(session),
         {:ok, claimed} <- mark_session_exchanged(session) do
      claimed
    else
      {:error, reason} -> repo().rollback(reason)
    end
  end

  defp validate_claimable_session(%OAuthSession{} = session, redirect_uri) do
    cond do
      not is_nil(session.exchanged_at) or OAuthSession.expired?(session) ->
        {:error, :invalid_session}

      session.redirect_uri != redirect_uri ->
        {:error, :invalid_session}

      true ->
        :ok
    end
  end

  defp validate_claimable_session(_session, _redirect_uri), do: {:error, :invalid_session}

  defp validate_session_client(%OAuthSession{} = session) do
    provider = repo().get(Provider, session.provider_id)

    case provider && Provider.get_oauth_credentials(provider) do
      {:ok, %{client_id: client_id}} when client_id == session.oauth_client_id -> :ok
      {:ok, _oauth_client} -> {:error, :client_changed}
      _ -> {:error, :invalid_session}
    end
  end

  defp mark_session_exchanged(session) do
    changeset =
      Ecto.Changeset.change(session, %{
        exchanged_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })

    case repo().update(changeset) do
      {:ok, claimed} -> {:ok, claimed}
      {:error, _changeset} -> {:error, :invalid_session}
    end
  end

  # Exchanges the code and records a credential-free audit row for failures.
  defp exchange_staged_code(session, authorization_code, redirect_uri) do
    case Tango.Auth.exchange_authorization_code(session, authorization_code, redirect_uri) do
      {:ok, token_response} ->
        {:ok, token_response}

      {:error, reason} ->
        audit_staged_exchange(session, {:error, Tango.Auth.audit_error_code(reason)})
        {:error, reason}
    end
  end

  defp token_summary(token_response, now) do
    %{
      granted_scopes: granted_scopes(token_response),
      token_type: token_response["token_type"],
      token_expires_at: token_expiration(now, token_response["expires_in"])
    }
  end

  # Audit persistence is best-effort so a logging failure never blocks staging.
  defp audit_staged_exchange(session, result) do
    session |> AuditLog.log_staged_exchange(result) |> repo().insert()
    :ok
  end

  defp insert_candidate(session, token_response) do
    handle = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    expires_at =
      earliest(DateTime.add(now, @candidate_lifetime_seconds, :second), session.expires_at)

    attrs = %{
      provider_id: session.provider_id,
      completion_mode: session.completion_mode,
      oauth_session_id: session.id,
      tenant_id: session.tenant_id,
      handle_hash: handle_hash(handle),
      access_token: token_response["access_token"],
      refresh_token: token_response["refresh_token"],
      token_type: token_response["token_type"],
      token_expires_at: token_expiration(now, token_response["expires_in"]),
      granted_scopes: granted_scopes(token_response),
      provider_data: token_response["provider_data"] || %{},
      expected_connection_id: session.expected_connection_id,
      expected_subject: session.expected_subject,
      oauth_client_id: session.oauth_client_id,
      intent_reference: session.intent_reference,
      completion_origin: session.completion_origin,
      expires_at: expires_at
    }

    case Tango.RedactedParams.insert(repo(), Authorization.changeset(%Authorization{}, attrs)) do
      {:ok, _candidate} ->
        audit_staged_exchange(session, {:ok, token_summary(token_response, now)})

        {:ok,
         %{
           completion_handle: handle,
           expires_at: expires_at,
           intent_reference: session.intent_reference,
           completion_origin: session.completion_origin
         }}

      {:error, _changeset} ->
        {:error, :invalid_session}
    end
  end

  defp load_candidate(handle, tenant_id, intent_reference, provider_slug) do
    with {:ok, hash} <- decode_handle(handle),
         {:ok, {candidate, provider}} <-
           repo().transaction(fn ->
             load_candidate_in_transaction(hash, tenant_id, intent_reference, provider_slug)
           end) do
      {:ok, candidate, provider}
    end
  end

  defp load_candidate_in_transaction(hash, tenant_id, intent_reference, provider_slug) do
    with {:ok, candidate, provider} <- lock_candidate(hash, tenant_id),
         :ok <- validate_candidate(candidate, provider, intent_reference, provider_slug),
         :ok <- validate_generation(candidate) do
      {candidate, provider}
    else
      nil -> repo().rollback(:invalid_completion)
      {:error, reason} -> repo().rollback(reason)
    end
  end

  defp persist_verification(
         candidate,
         tenant_id,
         intent_reference,
         provider_slug,
         verification
       ) do
    repo().transaction(fn ->
      with {:ok, current, provider} <- lock_candidate(candidate.handle_hash, tenant_id),
           :ok <- validate_verification_snapshot(candidate, current),
           :ok <- validate_candidate(current, provider, intent_reference, provider_slug),
           :ok <- validate_generation(current),
           :ok <-
             validate_verification(
               %{
                 connection_id: current.expected_connection_id,
                 subject: current.expected_subject
               },
               verification
             ),
           {:ok, verified} <-
             current
             |> Authorization.changeset(%{
               account_subject: verification.subject,
               identity_claims: verification.claims,
               verified_connection_id: current.expected_connection_id,
               verified_at: DateTime.utc_now() |> DateTime.truncate(:second)
             })
             |> repo().update() do
        verified
      else
        {:error, reason} -> repo().rollback(reason)
        _ -> repo().rollback(:invalid_completion)
      end
    end)
    |> unwrap_transaction()
  end

  defp load_candidate_routing(hash, tenant_id) do
    case repo().get_by(Authorization, handle_hash: hash, tenant_id: tenant_id) do
      %Authorization{} = candidate -> {:ok, candidate}
      nil -> {:error, :invalid_completion}
    end
  end

  # Connection finalization acquires its generation lock before this reload.
  # Session locks precede candidate locks so verification and session cleanup
  # cannot wait on one another in opposite order.
  defp lock_candidate(hash, tenant_id) do
    with {:ok, routing} <- load_candidate_routing(hash, tenant_id),
         %OAuthSession{} = session <-
           from(session in OAuthSession,
             where: session.id == ^routing.oauth_session_id,
             lock: "FOR UPDATE"
           )
           |> repo().one(),
         %Authorization{} = candidate <- candidate_query(hash, tenant_id) |> repo().one(),
         :ok <- validate_candidate_session(candidate, session) do
      {:ok, candidate, lock_candidate_provider(candidate)}
    else
      nil -> {:error, :invalid_completion}
      {:error, reason} -> {:error, reason}
    end
  end

  defp lock_candidate_provider(%Authorization{completion_mode: :consume} = candidate) do
    from(provider in Provider, where: provider.id == ^candidate.provider_id, lock: "FOR UPDATE")
    |> repo().one()
  end

  defp lock_candidate_provider(candidate), do: repo().get(Provider, candidate.provider_id)

  defp validate_candidate_session(candidate, session) do
    fields = ~w(completion_mode provider_id tenant_id oauth_client_id expected_connection_id
                expected_subject intent_reference completion_origin)a

    if candidate.oauth_session_id == session.id and
         Enum.all?(fields, &(Map.fetch!(candidate, &1) == Map.fetch!(session, &1))),
       do: :ok,
       else: {:error, :completion_mode_mismatch}
  end

  defp validate_verification_snapshot(candidate, current) do
    fields = ~w(id oauth_session_id completion_mode provider_id tenant_id oauth_client_id
                expected_connection_id expected_subject intent_reference completion_origin)a

    if Enum.all?(fields, &(Map.fetch!(candidate, &1) == Map.fetch!(current, &1))),
      do: :ok,
      else: {:error, :completion_mode_mismatch}
  end

  defp candidate_query(hash, tenant_id) do
    from(candidate in Authorization,
      where: candidate.handle_hash == ^hash,
      where: candidate.tenant_id == ^tenant_id,
      lock: "FOR UPDATE"
    )
  end

  defp validate_candidate(candidate, provider, intent_reference, provider_slug) do
    cond do
      candidate.consumed_at -> {:error, :completion_consumed}
      expired?(candidate.expires_at) -> {:error, :expired_completion}
      not match?(%Provider{}, provider) -> {:error, :invalid_completion}
      provider.slug != provider_slug -> {:error, :invalid_completion}
      candidate.intent_reference != intent_reference -> {:error, :intent_mismatch}
      true -> validate_verification_provider(candidate, provider)
    end
  end

  defp validate_verification_provider(
         %Authorization{completion_mode: :consume} = candidate,
         provider
       ) do
    cond do
      not provider.active -> {:error, :invalid_completion}
      oauth_client_id(provider) != candidate.oauth_client_id -> {:error, :client_changed}
      true -> :ok
    end
  end

  defp validate_verification_provider(_candidate, _provider), do: :ok

  defp validate_generation(%Authorization{completion_mode: :consume}), do: :ok

  defp validate_generation(%Authorization{expected_connection_id: nil} = candidate) do
    if other_active_generation?(repo(), candidate, nil),
      do: {:error, :stale_connection},
      else: :ok
  end

  defp validate_generation(%Authorization{expected_connection_id: connection_id} = candidate) do
    expected = candidate |> expected_connection_query() |> repo().one()

    if match?(%Connection{status: status} when status in [:active, :expired], expected) and
         not other_active_generation?(repo(), candidate, connection_id) do
      :ok
    else
      {:error, :stale_connection}
    end
  end

  # `expected` is the connection the verified identity must continue:
  # `%{connection_id: id | nil, subject: subject | nil}`.
  defp validate_verification(expected, verification) when is_map(verification) do
    with subject when is_binary(subject) <- Map.get(verification, :subject),
         true <- String.trim(subject) != "",
         claims when is_map(claims) <- Map.get(verification, :claims),
         :ok <- validate_claims(claims),
         :ok <- validate_continuity(expected, Map.get(verification, :continuity), subject) do
      :ok
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_claims}
    end
  end

  defp validate_verification(_expected, _verification), do: {:error, :invalid_claims}

  defp validate_continuity(%{connection_id: nil, subject: expected}, :initial, subject) do
    if is_nil(expected) or expected == subject, do: :ok, else: {:error, :account_mismatch}
  end

  defp validate_continuity(%{connection_id: id, subject: expected}, {:connection, id}, subject)
       when is_integer(id) do
    if is_nil(expected) or expected == subject, do: :ok, else: {:error, :account_mismatch}
  end

  defp validate_continuity(_expected, _continuity, _subject),
    do: {:error, :account_mismatch}

  defp validate_claims(claims) do
    with false <- contains_reserved_claim_key?(claims),
         {:ok, encoded} <- Jason.encode(claims),
         true <- byte_size(encoded) <= @maximum_claims_bytes do
      :ok
    else
      _ -> {:error, :invalid_claims}
    end
  end

  defp contains_reserved_claim_key?(map) when is_map(map) do
    Enum.any?(map, fn {key, value} ->
      reserved_claim_key?(key) or contains_reserved_claim_key?(value)
    end)
  end

  defp contains_reserved_claim_key?(list) when is_list(list),
    do: Enum.any?(list, &contains_reserved_claim_key?/1)

  defp contains_reserved_claim_key?(_value), do: false

  defp reserved_claim_key?(key) when is_binary(key) do
    normalized = key |> String.downcase() |> String.replace("-", "_")
    normalized in @reserved_claim_keys
  end

  defp reserved_claim_key?(_key), do: true

  defp maybe_consume_after_verifier_failure(_handle, _tenant_id, reason)
       when reason in @candidate_state_errors or reason in @transient_verifier_errors,
       do: :ok

  defp maybe_consume_after_verifier_failure(handle, tenant_id, _reason) do
    with {:ok, hash} <- decode_handle(handle) do
      repo().transaction(fn -> consume_open_candidate(hash, tenant_id) end)
    end

    :ok
  end

  defp consume_open_candidate(hash, tenant_id) do
    case candidate_query(hash, tenant_id) |> repo().one() do
      %Authorization{consumed_at: nil} = candidate ->
        candidate
        |> Authorization.changeset(%{
          consumed_at: DateTime.utc_now() |> DateTime.truncate(:second),
          access_token: nil,
          refresh_token: nil,
          provider_data: %{}
        })
        |> repo().update()

      _ ->
        :ok
    end
  end

  defp completion_summary(candidate, provider_slug) do
    %{
      provider: provider_slug,
      subject: candidate.account_subject,
      claims: candidate.identity_claims,
      granted_scopes: candidate.granted_scopes,
      intent_reference: candidate.intent_reference
    }
  end

  defp authorization_summary(candidate, provider_slug) do
    candidate
    |> completion_summary(provider_slug)
    |> Map.merge(%{
      expected_connection_id: candidate.expected_connection_id,
      has_refresh_token: not is_nil(candidate.refresh_token)
    })
  end

  defp load_connection(connection_id, tenant_id) do
    case repo().get_by(Connection, id: connection_id, tenant_id: tenant_id) do
      nil ->
        {:error, :not_found}

      %Connection{status: :active} = connection ->
        case repo().get(Provider, connection.provider_id) do
          %Provider{} = provider -> {:ok, connection, provider}
          nil -> {:error, :not_found}
        end

      _ ->
        {:error, :stale_connection}
    end
  end

  defp bind_connection_subject(connection, subject) do
    repo().transaction(fn ->
      from(stored in Connection,
        where: stored.id == ^connection.id,
        where: stored.tenant_id == ^connection.tenant_id,
        lock: "FOR UPDATE"
      )
      |> repo().one()
      |> bind_locked_connection(subject)
    end)
    |> unwrap_transaction()
  end

  defp bind_locked_connection(nil, _subject), do: repo().rollback(:stale_connection)

  defp bind_locked_connection(%Connection{status: status}, _subject) when status != :active,
    do: repo().rollback(:stale_connection)

  defp bind_locked_connection(%Connection{account_subject: nil} = current, subject) do
    case current |> Connection.changeset(%{account_subject: subject}) |> repo().update() do
      {:ok, updated} -> updated
      {:error, _changeset} -> repo().rollback(:stale_connection)
    end
  end

  defp bind_locked_connection(%Connection{account_subject: subject} = current, subject),
    do: current

  defp bind_locked_connection(_current, _subject), do: repo().rollback(:account_mismatch)

  # The token, scopes, and retained token response metadata handed to an
  # `AuthorizationVerifier`, never the refresh token. Retained metadata lives only
  # on staged candidates, so a connection's credential carries an empty map.
  defp credential(%Authorization{} = candidate),
    do: credential(candidate.access_token, candidate.granted_scopes, candidate.provider_data)

  defp credential(%Connection{access_token: access_token, granted_scopes: granted_scopes}),
    do: credential(access_token, granted_scopes, %{})

  defp credential(access_token, granted_scopes, provider_data),
    do: %{
      access_token: access_token,
      granted_scopes: granted_scopes || [],
      provider_data: provider_data || %{}
    }

  defp verifier_options(opts, nil), do: Keyword.delete(opts, :connection_id)
  defp verifier_options(opts, connection_id), do: Keyword.put(opts, :connection_id, connection_id)

  defp required_option(opts, name) do
    case Keyword.get(opts, name) do
      value when is_binary(value) and byte_size(value) > 0 -> {:ok, value}
      _ -> {:error, :invalid_completion}
    end
  end

  defp decode_handle(handle) do
    case Base.url_decode64(handle, padding: false) do
      {:ok, decoded} when byte_size(decoded) == 32 -> {:ok, handle_hash(handle)}
      _ -> {:error, :invalid_completion}
    end
  end

  defp handle_hash(handle), do: :crypto.hash(:sha256, handle)

  defp granted_scopes(%{"scope" => scopes}), do: Tango.Validation.parse_scopes(scopes)
  defp granted_scopes(_response), do: []

  defp token_expiration(now, expires_in) when is_integer(expires_in),
    do: DateTime.add(now, expires_in, :second)

  defp token_expiration(_now, _expires_in), do: nil

  defp earliest(left, right) do
    if DateTime.compare(left, right) == :gt, do: right, else: left
  end

  defp expired?(expires_at), do: DateTime.compare(expires_at, DateTime.utc_now()) != :gt

  defp unwrap_transaction({:ok, value}), do: {:ok, value}
  defp unwrap_transaction({:error, reason}), do: {:error, reason}
end

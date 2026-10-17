defmodule Tango.Connection do
  @moduledoc """
  Context module for OAuth connection management with multi-tenant isolation.

  Provides connection lifecycle management, token refresh, and multi-tenant
  isolation with comprehensive audit logging and automatic token refresh.
  """

  import Ecto.Query, warn: false
  require Logger
  defp repo, do: Application.get_env(:tango, :repo) || raise("Tango :repo not configured")

  alias Tango.ConnectionInfo
  alias Tango.Provider
  alias Tango.RefreshError
  alias Tango.Schemas.{AuditLog, Connection, Provider}

  @info_statuses [:active, :expired, :revoked]

  @doc """
  Lists active connections for a tenant.

  ## Examples

      iex> list_connections("user-123")
      [%Connection{}, ...]

      iex> list_connections("user-123", provider: "github")
      [%Connection{provider: %{name: "github"}}, ...]

  """
  def list_connections(tenant_id, opts \\ []) when is_binary(tenant_id) do
    Connection
    |> where([c], c.tenant_id == ^tenant_id and c.status == :active)
    |> maybe_filter_by_provider(Keyword.get(opts, :provider))
    |> maybe_preload_associations(Keyword.get(opts, :preload, true))
    |> repo().all()
  end

  defp maybe_filter_by_provider(query, nil), do: query

  defp maybe_filter_by_provider(query, provider_name) do
    query
    |> join(:inner, [c], p in assoc(c, :provider))
    |> where([c, p], p.name == ^provider_name)
  end

  defp maybe_preload_associations(query, false), do: query
  defp maybe_preload_associations(query, true), do: preload(query, [:provider])

  @doc """
  Gets a connection by ID with tenant isolation.

  ## Examples

      iex> get_connection("conn-123", "user-123")
      {:ok, %Connection{}}

      iex> get_connection("conn-123", "wrong-tenant")
      {:error, :not_found}

  """
  def get_connection(connection_id, tenant_id)
      when is_integer(connection_id) and is_binary(tenant_id) do
    case repo().get_by(Connection, id: connection_id, tenant_id: tenant_id) do
      nil -> {:error, :not_found}
      connection -> {:ok, connection}
    end
  end

  @doc """
  Gets credential-free connection info for any status.

  Missing and wrong-tenant ids both return `{:error, :not_found}`. The read
  does not refresh tokens or take locks. `:active` does not promise the access
  token is usable.

  ## Examples

      iex> get_connection_info(123, "user-123")
      {:ok, %Tango.ConnectionInfo{id: 123, status: :active}}

  """
  @spec get_connection_info(integer(), String.t()) ::
          {:ok, ConnectionInfo.t()} | {:error, :not_found}
  def get_connection_info(connection_id, tenant_id)
      when is_integer(connection_id) and is_binary(tenant_id) do
    info =
      Connection
      |> join(:inner, [c], p in assoc(c, :provider))
      |> where([c], c.id == ^connection_id and c.tenant_id == ^tenant_id)
      |> select_connection_info()
      |> repo().one()

    case info do
      nil -> {:error, :not_found}
      %ConnectionInfo{} = info -> {:ok, info}
    end
  end

  @doc """
  Lists credential-free connection info for a tenant.

  Results are ordered by ascending connection id. `provider_slug` matches the
  provider slug and includes inactive providers. `status` defaults to
  `:active`. Pass `:any`, one of `:active`, `:expired`, or `:revoked`, or a
  list of those statuses. An empty status list returns `[]`. Invalid options
  raise `ArgumentError` before a query runs.

  The read does not refresh tokens or take locks. `:active` does not promise
  the access token is usable.

  ## Examples

      iex> list_connection_infos("user-123")
      [%Tango.ConnectionInfo{}, ...]

      iex> list_connection_infos("user-123", provider_slug: "records", status: :any)
      [%Tango.ConnectionInfo{}, ...]

  """
  @spec list_connection_infos(String.t(), keyword()) :: [ConnectionInfo.t()]
  def list_connection_infos(tenant_id, opts \\ []) when is_binary(tenant_id) and is_list(opts) do
    opts
    |> validate_connection_info_opts!()
    |> query_connection_infos(tenant_id)
  end

  defp validate_connection_info_opts!(opts) do
    Enum.each(opts, &validate_connection_info_opt!/1)
    opts
  end

  defp validate_connection_info_opt!({:provider_slug, slug}) when is_binary(slug), do: :ok

  defp validate_connection_info_opt!({:status, status}),
    do: validate_connection_info_status!(status)

  defp validate_connection_info_opt!(option) do
    raise ArgumentError, "invalid connection info option: #{inspect(option)}"
  end

  defp validate_connection_info_status!(status)
       when status in [:active, :expired, :revoked, :any],
       do: :ok

  defp validate_connection_info_status!(statuses) when is_list(statuses) do
    if Enum.all?(statuses, &(&1 in @info_statuses)) do
      :ok
    else
      raise ArgumentError, "invalid connection info status: #{inspect(statuses)}"
    end
  end

  defp validate_connection_info_status!(status) do
    raise ArgumentError, "invalid connection info status: #{inspect(status)}"
  end

  defp query_connection_infos(opts, tenant_id) do
    case Keyword.get(opts, :status, :active) do
      [] ->
        []

      status ->
        Connection
        |> join(:inner, [c], p in assoc(c, :provider))
        |> where([c], c.tenant_id == ^tenant_id)
        |> filter_connection_info_status(status)
        |> filter_connection_info_slug(Keyword.get(opts, :provider_slug))
        |> order_by([c], asc: c.id)
        |> select_connection_info()
        |> repo().all()
    end
  end

  defp filter_connection_info_status(query, :any), do: query

  defp filter_connection_info_status(query, status) when is_atom(status) do
    where(query, [c], c.status == ^status)
  end

  defp filter_connection_info_status(query, statuses) when is_list(statuses) do
    where(query, [c], c.status in ^statuses)
  end

  defp filter_connection_info_slug(query, nil), do: query

  defp filter_connection_info_slug(query, slug) when is_binary(slug) do
    where(query, [_c, p], p.slug == ^slug)
  end

  defp select_connection_info(query) do
    select(query, [c, p], %ConnectionInfo{
      id: c.id,
      tenant_id: c.tenant_id,
      provider_slug: p.slug,
      status: c.status,
      account_subject: c.account_subject,
      granted_scopes: c.granted_scopes,
      expires_at: c.expires_at
    })
  end

  @doc """
  Gets an active tenant-owned connection with optional token refresh.

  Without `auto_refresh: true` this is a plain tenant- and status-filtered read
  of the last committed row, so it never waits behind an in-flight refresh.
  With it, the tenant and active status are checked while holding the same row
  lock used for refresh, so callers cannot receive a connection that changes
  state between lookup and refresh.
  """
  def get_active_connection(connection_id, tenant_id, opts \\ [])
      when is_integer(connection_id) and is_binary(tenant_id) and is_list(opts) do
    if Keyword.get(opts, :auto_refresh, false) do
      connection_id
      |> locked_refresh(:expiry, tenant_id)
      |> refresh_outcome()
    else
      fetch_active_connection(connection_id, tenant_id)
    end
  end

  defp fetch_active_connection(connection_id, tenant_id) do
    connection_id
    |> active_connection_query(tenant_id)
    |> one_or_not_found()
  end

  @doc """
  Gets an active connection for provider and tenant.

  Provider is identified by slug, not name.

  ## Examples

      iex> get_connection_for_provider("github", "user-123")
      {:ok, %Connection{}}

      iex> get_connection_for_provider("google", "user-123")
      {:ok, %Connection{}}

      iex> get_connection_for_provider("nonexistent", "user-123")
      {:error, :not_found}

  """
  def get_connection_for_provider(provider_slug, tenant_id)
      when is_binary(provider_slug) and is_binary(tenant_id) do
    query =
      from(c in Connection,
        join: p in assoc(c, :provider),
        where: p.slug == ^provider_slug,
        where: c.tenant_id == ^tenant_id,
        where: c.status == :active,
        order_by: [desc: c.inserted_at],
        limit: 1,
        preload: [:provider]
      )

    case repo().one(query) do
      nil -> {:error, :not_found}
      connection -> {:ok, connection}
    end
  end

  @doc """
  Gets an active connection for provider and tenant with optional auto-refresh.

  Provider is identified by slug, not name. When auto_refresh is true,
  automatically refreshes the token if it's about to expire (within 5 minutes).
  Returns `{:error, {:refresh_failed, reason}}` when an expired token cannot
  be refreshed.

  ## Examples

      iex> get_connection_for_provider("github", "user-123", auto_refresh: true)
      {:ok, %Connection{}}  # Token automatically refreshed if needed

      iex> get_connection_for_provider("google", "user-123", auto_refresh: false)
      {:ok, %Connection{}}  # Token returned as-is, even if expired

  """
  def get_connection_for_provider(provider_slug, tenant_id, opts)
      when is_binary(provider_slug) and is_binary(tenant_id) and is_list(opts) do
    with {:ok, connection} <- get_connection_for_provider(provider_slug, tenant_id) do
      maybe_auto_refresh(connection, Keyword.get(opts, :auto_refresh, false))
    end
  end

  defp maybe_auto_refresh(connection, false), do: {:ok, connection}
  defp maybe_auto_refresh(connection, true), do: refresh_if_needed(connection)

  @doc """
  Refreshes a connection's access token when it is about to expire.

  The connection row is locked while checking its expiry and requesting a token,
  so concurrent callers reuse the first caller's result. A transient or
  non-terminal failure still serves an active unexpired access token. Credential
  expiry, a terminal failure, and a persistence or transaction failure do not.
  """
  @spec refresh_if_needed(Connection.t()) ::
          {:ok, Connection.t()} | {:error, {:refresh_failed, term()}} | {:error, :not_found}
  def refresh_if_needed(%Connection{id: id}) do
    id
    |> locked_refresh()
    |> refresh_outcome()
  end

  defp locked_refresh(id, mode \\ :expiry, tenant_id \\ nil) do
    fn ->
      with {:ok, routing} <- load_connection_routing(id, tenant_id),
           :ok <- Tango.ConnectionLock.lock(repo(), routing.provider_id, routing.tenant_id),
           {:ok, locked} <- lock_active_connection(id, tenant_id) do
        refresh_locked(locked, mode)
      end
    end
    |> repo().transaction()
    |> unwrap_refresh_transaction()
  end

  defp unwrap_refresh_transaction({:ok, {:error, reason}}), do: {:error, reason}
  defp unwrap_refresh_transaction({:ok, outcome}), do: outcome

  defp unwrap_refresh_transaction({:error, :persistence_failed}),
    do: {:error, :persistence_failed}

  defp unwrap_refresh_transaction({:error, _reason}), do: {:error, :transaction_failed}

  defp load_connection_routing(id, tenant_id) do
    Connection
    |> where([c], c.id == ^id)
    |> maybe_filter_by_tenant(tenant_id)
    |> select([c], %{provider_id: c.provider_id, tenant_id: c.tenant_id})
    |> repo().one()
    |> case do
      nil -> {:error, :not_found}
      routing -> {:ok, routing}
    end
  end

  defp lock_active_connection(id, tenant_id) do
    id
    |> active_connection_query(tenant_id)
    |> lock("FOR UPDATE")
    |> one_or_not_found()
  end

  defp active_connection_query(id, tenant_id) do
    Connection
    |> where([c], c.id == ^id and c.status == :active)
    |> maybe_filter_by_tenant(tenant_id)
    |> preload([:provider])
  end

  defp one_or_not_found(query) do
    case repo().one(query) do
      nil -> {:error, :not_found}
      connection -> {:ok, connection}
    end
  end

  defp maybe_filter_by_tenant(query, nil), do: query

  defp maybe_filter_by_tenant(query, tenant_id) do
    from(c in query,
      where: c.tenant_id == ^tenant_id
    )
  end

  defp refresh_locked(connection, :sweep) do
    cond do
      not sweep_due?(connection) -> {:skipped, connection}
      not Connection.needs_refresh?(connection) -> {:skipped, connection}
      not Connection.can_refresh?(connection) -> {:skipped, connection}
      true -> attempt_refresh(connection)
    end
  end

  defp refresh_locked(connection, :expiry) do
    case {Connection.needs_refresh?(connection), Connection.can_refresh?(connection)} do
      {false, _can_refresh} -> {:current, connection}
      {true, false} -> {:failed, :refresh_not_allowed, connection}
      {true, true} -> attempt_refresh(connection)
    end
  end

  defp refresh_locked(connection, {:force, snapshot}) do
    if refresh_generation_changed?(snapshot, connection) do
      {:current, connection}
    else
      attempt_refresh(connection)
    end
  end

  defp refresh_generation_changed?(snapshot, current) do
    snapshot.lock_version != current.lock_version and
      {snapshot.access_token, snapshot.refresh_token, snapshot.expires_at} !=
        {current.access_token, current.refresh_token, current.expires_at}
  end

  defp refresh_outcome({:current, connection}), do: {:ok, connection}
  defp refresh_outcome({:refreshed, connection}), do: {:ok, connection}

  defp refresh_outcome({:failed, reason, connection}),
    do: serve_unless_expired(reason, connection)

  defp refresh_outcome({:error, :not_found}), do: {:error, :not_found}
  defp refresh_outcome({:error, reason}), do: {:error, {:refresh_failed, reason}}

  defp attempt_refresh(connection) do
    case refresh_connection_locked(connection) do
      {:ok, refreshed} ->
        {:refreshed, refreshed}

      {:error, reason} when reason in [:persistence_failed, :transaction_failed] ->
        repo().rollback(reason)

      {:error, reason} when reason in [:no_refresh_token, :refresh_not_allowed] ->
        {:failed, reason, connection}

      {:error, reason} ->
        record_failed_refresh(connection, reason)
    end
  end

  defp record_failed_refresh(connection, reason) do
    case record_refresh_failure(connection, reason) do
      {:ok, failed} ->
        insert_refresh_audit(
          AuditLog.log_connection_event(:token_refresh_failed, failed, false, %{
            reason: RefreshError.to_storage(reason),
            attempts: failed.refresh_attempts
          })
        )

        {:failed, reason, failed}

      {:error, _changeset} ->
        repo().rollback(:persistence_failed)
    end
  end

  defp serve_unless_expired(reason, connection) do
    if fallback_allowed?(reason, connection),
      do: {:ok, connection},
      else: {:error, {:refresh_failed, reason}}
  end

  defp fallback_allowed?(reason, %Connection{status: :active} = connection) do
    reason not in [:persistence_failed, :transaction_failed] and
      RefreshError.classify(reason) != :credential and
      not token_expired?(connection)
  end

  defp fallback_allowed?(_reason, _connection), do: false

  defp sweep_due?(%Connection{next_refresh_at: nil}), do: true

  defp sweep_due?(%Connection{next_refresh_at: next_refresh_at}) do
    DateTime.compare(next_refresh_at, utc_now()) != :gt
  end

  defp utc_now, do: DateTime.utc_now() |> DateTime.truncate(:second)

  defp token_expired?(%Connection{expires_at: nil}), do: false

  defp token_expired?(%Connection{expires_at: expires_at}),
    do: DateTime.compare(expires_at, DateTime.utc_now()) != :gt

  @doc """
  Updates connection usage timestamp.

  Should be called when connection is used for API requests.

  ## Examples

      iex> mark_connection_used(connection)
      {:ok, %Connection{last_used_at: ~U[2023-01-01 12:00:00Z]}}

  """
  def mark_connection_used(%Connection{} = connection) do
    connection
    |> Connection.changeset(%{last_used_at: DateTime.utc_now()})
    |> repo().update()
  end

  @doc """
  Records the provider rejecting a connection's credentials.

  Consumers call this when a provider answers an API call with HTTP 401 or 403.
  Tango issues tokens but never sees the calls made with them, so a connection
  holding credentials the provider has revoked stays `:active` here forever
  unless the consumer reports it. Once the rejections reach the threshold the
  connection is expired, `get_connection_for_provider/2` stops handing it out,
  and the consumer sees `{:error, :not_found}` — its cue to treat the
  integration as disconnected and prompt the tenant to reconnect.

  `opts[:max_failures]` sets the expiry threshold (default 3), per call rather
  than library-wide: one Tango deployment serves many providers, each called on
  its own cadence, and the count is a number of rejections rather than a
  duration. Callers hitting a provider every few seconds pass a higher ceiling
  than one sweeping twice an hour, or the same transient outage expires far
  more of their connections.

  This is not a refresh failure. A connection carrying no refresh token or no
  expiry is never eligible for refresh, so `refresh_connection/1` never runs and
  its counters never move, no matter how long the credentials have been dead.

  Only active connections accept a report: a connection revoked or expired
  between the failing API call and the report is left exactly as it is —
  `:revoked` and `:expired` age out on different schedules, so a late report
  must not convert one into the other. The count is read from a freshly loaded
  row locked for the update, never from the caller's copy, so concurrent
  reporters serialize instead of clobbering each other or raising
  `Ecto.StaleEntryError` on a stale struct.

  Accepts a `%Connection{}`, or a connection id together with `opts[:tenant_id]`
  (a bare id is not proof of access, so id-based reports carry the tenant scope
  every other lookup in this module requires). Returns `{:error, :not_found}`
  when the connection does not exist, is not active, or belongs to another
  tenant, and `{:error, :tenant_id_required}` for an id without a tenant.

  ## Examples

      iex> record_auth_failure(connection, "http_401")
      {:ok, %Connection{auth_failures: 1}}

      iex> record_auth_failure(connection_id, "http_401", tenant_id: "user-123", max_failures: 10)
      {:ok, %Connection{auth_failures: 1}}

  """
  def record_auth_failure(connection, error_reason, opts \\ [])

  def record_auth_failure(%Connection{} = connection, error_reason, opts) do
    do_record_auth_failure(connection.id, connection.tenant_id, error_reason, opts)
  end

  def record_auth_failure(connection_id, error_reason, opts) when is_integer(connection_id) do
    case Keyword.fetch(opts, :tenant_id) do
      {:ok, tenant_id} when is_binary(tenant_id) ->
        do_record_auth_failure(connection_id, tenant_id, error_reason, opts)

      _missing ->
        {:error, :tenant_id_required}
    end
  end

  defp do_record_auth_failure(connection_id, tenant_id, error_reason, opts) do
    Ecto.Multi.new()
    |> Ecto.Multi.run(:load, fn repo, _changes ->
      with {:ok, routing} <- load_connection_routing(repo, connection_id, tenant_id),
           :ok <- Tango.ConnectionLock.lock(repo, routing.provider_id, routing.tenant_id) do
        lock_active_connection(repo, connection_id, tenant_id)
      end
    end)
    |> Ecto.Multi.update(:connection, fn %{load: connection} ->
      Connection.record_auth_failure(connection, error_reason, opts)
    end)
    |> Ecto.Multi.run(:audit_log, fn repo, %{connection: updated_connection} ->
      AuditLog.log_connection_event(:connection_auth_failed, updated_connection, false, %{
        reason: to_string(error_reason),
        auth_failures: updated_connection.auth_failures,
        expired: updated_connection.status == :expired
      })
      |> repo.insert()
    end)
    |> repo().transaction()
    |> case do
      {:ok, %{connection: updated_connection}} -> {:ok, updated_connection}
      {:error, _op, reason, _changes} -> {:error, reason}
    end
  end

  @doc """
  Clears a connection's rejection streak after its credentials authenticate again.

  Keeps `record_auth_failure/3` counting *consecutive* rejections: without this,
  isolated failures spread over months would accumulate to the threshold and
  expire a connection that works. The streak is checked in the database rather
  than on the caller's copy — a struct loaded before another process recorded a
  failure would otherwise skip the clear and leave a phantom strike behind. When
  there is no streak the update matches no row and the call is a single no-op
  statement, so reporting success after every provider call stays cheap.

  Accepts a `%Connection{}`, or a connection id together with `opts[:tenant_id]`.
  Returns `:ok` whether or not anything needed clearing (an inactive or already
  clean connection has no streak worth reporting), and
  `{:error, :tenant_id_required}` for an id without a tenant.

  ## Examples

      iex> record_auth_success(connection)
      :ok

      iex> record_auth_success(connection_id, tenant_id: "user-123")
      :ok

  """
  def record_auth_success(connection, opts \\ [])

  def record_auth_success(%Connection{} = connection, _opts) do
    clear_auth_failure_streak(connection.id, connection.tenant_id)
  end

  def record_auth_success(connection_id, opts) when is_integer(connection_id) do
    case Keyword.fetch(opts, :tenant_id) do
      {:ok, tenant_id} when is_binary(tenant_id) ->
        clear_auth_failure_streak(connection_id, tenant_id)

      _missing ->
        {:error, :tenant_id_required}
    end
  end

  # A single conditional UPDATE: the `auth_failures > 0` predicate makes the
  # no-streak case match zero rows, and counter resets from concurrent
  # reporters are idempotent, so neither a lock nor a prior read is needed.
  defp clear_auth_failure_streak(connection_id, tenant_id) do
    from(c in Connection,
      where: c.id == ^connection_id,
      where: c.tenant_id == ^tenant_id,
      where: c.status == :active,
      where: c.auth_failures > 0
    )
    |> repo().update_all(set: [auth_failures: 0, last_auth_failure: nil])

    :ok
  end

  # Loads the connection for a failure report inside the reporting transaction.
  # Row-locked so concurrent reports increment in sequence rather than racing
  # the optimistic lock; scoped to `:active` so a report landing after a revoke
  # or expiry cannot move a connection between terminal states — `:revoked`
  # rows are kept while `:expired` rows are deleted 30 days on.
  defp lock_active_connection(repo, connection_id, tenant_id) do
    from(c in Connection,
      where: c.id == ^connection_id,
      where: c.tenant_id == ^tenant_id,
      where: c.status == :active,
      lock: "FOR UPDATE"
    )
    |> repo.one()
    |> case do
      nil -> {:error, :not_found}
      connection -> {:ok, connection}
    end
  end

  defp load_connection_routing(repo, connection_id, tenant_id) do
    from(c in Connection,
      where: c.id == ^connection_id,
      where: c.tenant_id == ^tenant_id,
      select: %{provider_id: c.provider_id, tenant_id: c.tenant_id}
    )
    |> repo.one()
    |> case do
      nil -> {:error, :not_found}
      routing -> {:ok, routing}
    end
  end

  @doc """
  Refreshes an OAuth connection's access token.

  Attempts to refresh the access token using the refresh token.
  Updates connection with new token data or marks as expired on failure.

  ## Examples

      iex> refresh_connection(connection)
      {:ok, %Connection{access_token: "new_token"}}

      iex> refresh_connection(expired_connection)
      {:error, {:oauth_error, :invalid_grant}}

  A failed refresh returns `{:error, reason}` even when the current access
  token still has time left. On-demand callers use
  `refresh_if_needed/1`, which wraps the same reason as
  `{:error, {:refresh_failed, reason}}` unless the active token may still
  be served.

  """
  def refresh_connection(%Connection{} = connection) do
    case locked_refresh(connection.id, {:force, connection}) do
      # Unlike refresh_if_needed/1, an explicit refresh reports the provider's
      # failure even while the current access token is still valid.
      {:failed, reason, _connection} -> {:error, reason}
      {:error, {:refresh_failed, reason}} -> {:error, reason}
      {:error, reason} -> {:error, reason}
      outcome -> refresh_outcome(outcome)
    end
  end

  defp refresh_connection_locked(connection) do
    with :ok <- validate_refresh_eligibility(connection),
         {:ok, provider} <- get_connection_provider_cached(connection),
         {:ok, oauth_config} <- Provider.get_oauth_credentials(provider),
         {:ok, token_response} <- perform_token_refresh(oauth_config, provider, connection),
         {:ok, updated_connection} <- save_refreshed_connection(connection, token_response) do
      insert_refresh_audit(
        AuditLog.log_connection_event(:token_refreshed, updated_connection, true)
      )

      {:ok, updated_connection}
    end
  end

  defp save_refreshed_connection(connection, token_response) do
    case Tango.RedactedParams.update(
           repo(),
           Connection.refresh_changeset(connection, token_response)
         ) do
      {:ok, updated_connection} -> {:ok, updated_connection}
      {:error, _changeset} -> {:error, :persistence_failed}
    end
  end

  # Refresh audit rows are best-effort. Once the provider has rotated the tokens
  # they must be stored, or the connection is stranded with a spent refresh token,
  # so an audit failure is logged rather than reported as a refresh failure. The
  # savepoint keeps a database-level failure from aborting the refresh transaction.
  defp insert_refresh_audit(changeset) do
    case repo().insert(changeset, mode: :savepoint) do
      {:ok, _audit_log} -> :ok
      {:error, _changeset} -> log_refresh_audit_failure(changeset, :invalid)
    end
  rescue
    error in Postgrex.Error -> log_refresh_audit_failure(changeset, error.postgres[:code])
  end

  defp log_refresh_audit_failure(changeset, reason) do
    Logger.error(
      "Tango could not write #{Ecto.Changeset.get_field(changeset, :event_type)} " <>
        "audit log: #{inspect(reason)}"
    )

    :error
  end

  @doc """
  Refreshes connections that are about to expire.

  Should be called periodically by a background job.

  ## Examples

      iex> refresh_expiring_connections()
      {:ok, 3}  # 3 connections refreshed

  """
  def refresh_expiring_connections do
    buffer_time = refresh_buffer_time()
    now = utc_now()
    batch_size = Application.get_env(:tango, :refresh_batch_size, 100)

    connections =
      from(c in Connection,
        where: c.status == :active,
        where: c.auto_refresh_enabled == true,
        where: not c.refresh_exhausted,
        where: not is_nil(c.refresh_token),
        where: not is_nil(c.expires_at),
        where: c.expires_at <= ^buffer_time,
        where: is_nil(c.next_refresh_at) or c.next_refresh_at <= ^now,
        order_by: [asc: c.id],
        limit: ^batch_size,
        preload: [:provider]
      )
      |> repo().all()

    outcomes = Enum.map(connections, &locked_refresh(&1.id, :sweep))
    success_count = Enum.count(outcomes, &match?({:refreshed, _connection}, &1))
    failure_count = Enum.count(outcomes, &sweep_failure?/1)

    if success_count > 0 or failure_count > 0 do
      AuditLog.log_system_event(:batch_token_refresh, true, %{
        success_count: success_count,
        failure_count: failure_count,
        total_selected: length(connections),
        total_processed: success_count + failure_count
      })
      |> repo().insert()
    end

    {:ok, success_count}
  end

  defp sweep_failure?({:failed, _reason, _connection}), do: true
  defp sweep_failure?({:error, :not_found}), do: false
  defp sweep_failure?({:error, _reason}), do: true
  defp sweep_failure?(_skipped_or_current), do: false

  @doc """
  Revokes a connection.

  Accepts the connection struct or its integer id. Missing, wrong-tenant, and
  already-revoked ids return `{:error, :not_found}`. A struct whose tenant does
  not match returns `{:error, :not_authorized}`. Active and expired connections
  can be revoked. The row is locked and checked again inside the transaction.

  ## Examples

      iex> revoke_connection(connection, "user-123")
      {:ok, %Connection{status: :revoked}}

      iex> revoke_connection(123, "user-123")
      {:ok, %Connection{status: :revoked}}

  """
  def revoke_connection(connection_id, tenant_id)
      when is_integer(connection_id) and is_binary(tenant_id) do
    revoke_locked_connection(connection_id, tenant_id)
  end

  def revoke_connection(%Connection{tenant_id: tenant_id} = connection, tenant_id) do
    revoke_locked_connection(connection.id, tenant_id)
  end

  def revoke_connection(%Connection{}, _tenant_id) do
    {:error, :not_authorized}
  end

  defp revoke_locked_connection(connection_id, tenant_id) do
    Ecto.Multi.new()
    |> Ecto.Multi.run(:locked_connection, fn repo, _changes ->
      with {:ok, routing} <- load_connection_routing(repo, connection_id, tenant_id),
           :ok <- Tango.ConnectionLock.lock(repo, routing.provider_id, routing.tenant_id) do
        lock_revokeable_connection(repo, connection_id, tenant_id)
      end
    end)
    |> Ecto.Multi.update(:connection, fn %{locked_connection: locked} ->
      Connection.changeset(locked, %{status: :revoked})
    end)
    |> Ecto.Multi.run(:audit_log, fn repo, %{connection: revoked_connection} ->
      AuditLog.log_connection_event(:connection_revoked, revoked_connection, true)
      |> repo.insert()
    end)
    |> repo().transaction()
    |> case do
      {:ok, %{connection: revoked_connection}} -> {:ok, revoked_connection}
      {:error, _op, reason, _changes} -> {:error, reason}
    end
  end

  defp lock_revokeable_connection(repo, connection_id, tenant_id) do
    from(c in Connection,
      where: c.id == ^connection_id,
      where: c.tenant_id == ^tenant_id,
      where: c.status in [:active, :expired],
      lock: "FOR UPDATE"
    )
    |> repo.one()
    |> case do
      nil -> {:error, :not_found}
      connection -> {:ok, connection}
    end
  end

  @doc """
  Acquires generation locks for one tenant's providers.

  The caller must already be inside a transaction on Tango's configured repo.
  A sandbox checkout, or a transaction on a different repo, returns
  `{:error, :not_in_transaction}` before any lookup, including for an empty
  slug list.

  Slugs resolve before any lock, and inactive providers are included.
  `missing: :error` (the default) returns
  `{:error, {:provider_not_found, slug}}` for the first unknown slug in input
  order and takes no locks. `missing: :skip` ignores unknown slugs. Invalid
  options raise `ArgumentError`.

  Pairs are locked by provider id, then Elixir tenant binary order. Repeating a
  held pair does not block. Locks last until the outer transaction commits or
  rolls back; a nested commit does not release them. Acquire the tenant's full
  provider set once, before nested Tango operations. Adding a lower key after a
  higher key can deadlock. Separate transactions are required for several
  tenants unless the complete global order is established first.

  A lock does not authorize the caller or replace a later state check.

  ## Examples

      iex> lock_connection_generations("user-123", ["records"])
      :ok

  """
  @spec lock_connection_generations(String.t(), [String.t()], keyword()) ::
          :ok | {:error, :not_in_transaction | {:provider_not_found, String.t()}}
  def lock_connection_generations(tenant_id, provider_slugs, opts \\ [])
      when is_binary(tenant_id) and is_list(provider_slugs) and is_list(opts) do
    missing = generation_missing_mode!(opts)

    with :ok <- require_generation_transaction() do
      lock_generation_slugs(tenant_id, provider_slugs, missing)
    end
  end

  defp generation_missing_mode!(opts) do
    Enum.each(opts, &validate_generation_opt!/1)
    Keyword.get(opts, :missing, :error)
  end

  defp validate_generation_opt!({:missing, mode}) when mode in [:error, :skip], do: :ok

  defp validate_generation_opt!(option) do
    raise ArgumentError, "invalid generation lock option: #{inspect(option)}"
  end

  defp require_generation_transaction do
    if repo().in_transaction?() do
      :ok
    else
      {:error, :not_in_transaction}
    end
  end

  defp lock_generation_slugs(_tenant_id, [], _missing), do: :ok

  defp lock_generation_slugs(tenant_id, slugs, missing) do
    ids_by_slug = generation_provider_ids(slugs)

    case first_missing_slug(slugs, ids_by_slug, missing) do
      {:error, reason} ->
        {:error, reason}

      :ok ->
        Tango.ConnectionLock.lock_ordered(repo(), generation_keys(slugs, ids_by_slug, tenant_id))
    end
  end

  defp generation_provider_ids(slugs) do
    Provider
    |> where([provider], provider.slug in ^Enum.uniq(slugs))
    |> select([provider], {provider.slug, provider.id})
    |> repo().all()
    |> Map.new()
  end

  defp first_missing_slug(_slugs, _ids_by_slug, :skip), do: :ok

  defp first_missing_slug(slugs, ids_by_slug, :error) do
    case Enum.find(slugs, &(not Map.has_key?(ids_by_slug, &1))) do
      nil -> :ok
      slug -> {:error, {:provider_not_found, slug}}
    end
  end

  defp generation_keys(slugs, ids_by_slug, tenant_id) do
    Enum.flat_map(slugs, fn slug ->
      case Map.fetch(ids_by_slug, slug) do
        {:ok, provider_id} -> [{provider_id, tenant_id}]
        :error -> []
      end
    end)
  end

  @doc """
  Revokes all connections for a tenant.

  ## Examples

      iex> revoke_tenant_connections("user-123")
      {:ok, 3}  # 3 connections revoked

  """
  def revoke_tenant_connections(tenant_id) when is_binary(tenant_id) do
    Ecto.Multi.new()
    |> Ecto.Multi.run(:revoke, fn repo, _changes ->
      revoke_locked_generations(repo, where(Connection, [c], c.tenant_id == ^tenant_id))
    end)
    |> Ecto.Multi.run(:audit_log, fn repo, %{revoke: count} ->
      if count > 0 do
        AuditLog.log_system_event(:tenant_connections_revoked, true, %{
          tenant_id: tenant_id,
          revoked_count: count
        })
        |> repo.insert()
      else
        {:ok, nil}
      end
    end)
    |> repo().transaction()
    |> case do
      {:ok, %{revoke: count}} -> {:ok, count}
      {:error, _op, reason, _changes} -> {:error, reason}
    end
  end

  @doc """
  Revokes all connections for a provider across all tenants.

  Should be used when a provider is deactivated or has security issues.

  ## Examples

      iex> revoke_provider_connections("github")
      {:ok, 15}  # 15 connections revoked

  """
  def revoke_provider_connections(provider_name) when is_binary(provider_name) do
    with {:ok, provider} <- Tango.Provider.get_provider(provider_name) do
      do_revoke_provider_connections(provider, provider_name)
    end
  end

  defp do_revoke_provider_connections(provider, provider_name) do
    Ecto.Multi.new()
    |> Ecto.Multi.run(:revoke, fn repo, _changes ->
      revoke_locked_generations(repo, where(Connection, [c], c.provider_id == ^provider.id))
    end)
    |> Ecto.Multi.run(:audit_log, fn repo, %{revoke: count} ->
      if count > 0 do
        AuditLog.log_system_event(:provider_connections_revoked, true, %{
          provider_name: provider_name,
          revoked_count: count
        })
        |> repo.insert()
      else
        {:ok, nil}
      end
    end)
    |> repo().transaction()
    |> case do
      {:ok, %{revoke: count}} -> {:ok, count}
      {:error, _op, reason, _changes} -> {:error, reason}
    end
  end

  @doc """
  Cleans up expired connections.

  Removes connections that have been expired for more than 30 days.

  ## Examples

      iex> cleanup_expired_connections()
      {:ok, 12}  # 12 connections cleaned up

  """
  def cleanup_expired_connections do
    cleanup_cutoff = cleanup_cutoff_date()

    Ecto.Multi.new()
    |> Ecto.Multi.run(:cleanup, fn repo, _changes ->
      {count, _} =
        from(c in Connection,
          where: c.status == :expired,
          where: c.updated_at < ^cleanup_cutoff
        )
        |> repo.delete_all()

      {:ok, count}
    end)
    |> Ecto.Multi.run(:audit_log, fn repo, %{cleanup: count} ->
      if count > 0 do
        AuditLog.log_system_event(:expired_connections_cleanup, true, %{
          cleaned_count: count,
          cutoff_date: cleanup_cutoff
        })
        |> repo.insert()
      else
        {:ok, nil}
      end
    end)
    |> repo().transaction()
    |> case do
      {:ok, %{cleanup: count}} -> {:ok, count}
      {:error, _op, reason, _changes} -> {:error, reason}
    end
  end

  @doc """
  Gets connection statistics for a tenant.

  ## Examples

      iex> get_connection_stats("user-123")
      %{
        active: 3,
        expired: 1,
        revoked: 2,
        total: 6,
        providers: ["github", "google"]
      }

  """
  def get_connection_stats(tenant_id) when is_binary(tenant_id) do
    status_counts =
      from(c in Connection,
        where: c.tenant_id == ^tenant_id,
        group_by: c.status,
        select: {c.status, count(c.id)}
      )
      |> repo().all()
      |> Map.new()

    providers =
      from(c in Connection,
        join: p in assoc(c, :provider),
        where: c.tenant_id == ^tenant_id,
        where: c.status == :active,
        distinct: p.name,
        select: p.name,
        order_by: p.name
      )
      |> repo().all()

    %{
      active: Map.get(status_counts, :active, 0),
      expired: Map.get(status_counts, :expired, 0),
      revoked: Map.get(status_counts, :revoked, 0),
      total: status_counts |> Map.values() |> Enum.sum(),
      providers: providers
    }
  end

  defp validate_refresh_eligibility(%Connection{refresh_token: nil}),
    do: {:error, :no_refresh_token}

  defp validate_refresh_eligibility(%Connection{} = connection) do
    if Connection.can_refresh?(connection),
      do: :ok,
      else: {:error, :refresh_not_allowed}
  end

  defp get_connection_provider_cached(%Connection{provider: %Provider{} = provider}),
    do: {:ok, provider}

  defp get_connection_provider_cached(%Connection{provider_id: provider_id}) do
    case repo().get(Provider, provider_id) do
      nil -> {:error, :provider_not_found}
      provider -> {:ok, provider}
    end
  end

  defp perform_token_refresh(oauth_config, provider, connection) do
    oauth_config
    |> Tango.TokenRequest.refresh(provider.metadata, connection.refresh_token)
    |> case do
      {:ok, %{token: token}} ->
        {:ok, convert_token_to_response(token, connection)}

      {:error, %OAuth2.Response{status_code: status, headers: headers, body: body}} ->
        {:error, RefreshError.from_response(status, headers, body)}

      {:error, %OAuth2.Error{reason: reason}} ->
        {:error, RefreshError.from_transport(reason)}

      {:error, %Ecto.Changeset{}} ->
        {:error, :persistence_failed}

      {:error, reason} ->
        {:error, RefreshError.from_transport(reason)}
    end
  end

  defp convert_token_to_response(%OAuth2.AccessToken{} = token, connection) do
    response = %{
      "access_token" => token.access_token,
      "refresh_token" => token.refresh_token || connection.refresh_token,
      "token_type" => token.token_type,
      "expires_in" => calculate_expires_in(token.expires_at)
    }

    if Map.has_key?(token.other_params, "scope"),
      do: Map.put(response, "scope", token.other_params["scope"]),
      else: response
  end

  defp record_refresh_failure(connection, reason) do
    connection
    |> Connection.record_refresh_failure(reason)
    |> repo().update()
  end

  defp calculate_expires_in(expires_at) when is_integer(expires_at) do
    expires_at
    |> DateTime.from_unix!()
    |> DateTime.diff(DateTime.utc_now())
  end

  defp calculate_expires_in(_expires_at), do: nil

  defp cleanup_cutoff_date do
    DateTime.add(DateTime.utc_now(), -30 * 24 * 60 * 60, :second)
  end

  # Revokes the active and expired connections in `scope` while holding the
  # generation lock of every (provider, tenant) pair it touches.
  defp revoke_locked_generations(repo, scope) do
    revokeable = where(scope, [c], c.status in [:active, :expired])
    locked_keys = lock_active_generation_keys(repo, revokeable)

    {count, _} =
      revokeable
      |> restrict_to_generation_keys(locked_keys)
      |> repo.update_all(set: [status: :revoked, updated_at: DateTime.utc_now()])

    {:ok, count}
  end

  defp lock_active_generation_keys(repo, query) do
    keys =
      query
      |> select([c], {c.provider_id, c.tenant_id})
      |> distinct(true)
      |> repo.all()

    :ok = Tango.ConnectionLock.lock_ordered(repo, keys)
    keys
  end

  defp restrict_to_generation_keys(query, keys) do
    predicate =
      Enum.reduce(keys, dynamic(false), fn {provider_id, tenant_id}, predicate ->
        dynamic(
          [c],
          ^predicate or (c.provider_id == ^provider_id and c.tenant_id == ^tenant_id)
        )
      end)

    where(query, ^predicate)
  end

  defp refresh_buffer_time do
    DateTime.add(DateTime.utc_now(), 5 * 60, :second)
  end
end

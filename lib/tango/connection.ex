defmodule Tango.Connection do
  @moduledoc """
  Context module for OAuth connection management with multi-tenant isolation.

  Provides connection lifecycle management, token refresh, and multi-tenant
  isolation with comprehensive audit logging and automatic token refresh.
  """

  import Ecto.Query, warn: false
  require Logger
  defp repo, do: Application.get_env(:tango, :repo) || raise("Tango :repo not configured")

  alias Tango.Provider
  alias Tango.Schemas.{AuditLog, Connection, Provider}

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

  defp maybe_auto_refresh(connection, true) do
    if should_refresh?(connection) do
      case refresh_connection(connection) do
        {:ok, refreshed} -> {:ok, refreshed}
        {:error, _} -> {:ok, connection}
      end
    else
      {:ok, connection}
    end
  end

  defp should_refresh?(%Connection{} = connection) do
    Connection.needs_refresh?(connection) and Connection.can_refresh?(connection)
  end

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
  Refreshes an OAuth connection's access token.

  Attempts to refresh the access token using the refresh token.
  Updates connection with new token data or marks as expired on failure.

  ## Examples

      iex> refresh_connection(connection)
      {:ok, %Connection{access_token: "new_token"}}

      iex> refresh_connection(expired_connection)
      {:error, :refresh_failed}

  """
  def refresh_connection(%Connection{} = connection) do
    with :ok <- validate_refresh_eligibility(connection),
         {:ok, provider} <- get_connection_provider_cached(connection),
         {:ok, oauth_config} <- Provider.get_oauth_credentials(provider),
         {:ok, token_response} <- perform_token_refresh(oauth_config, connection) do
      try do
        Ecto.Multi.new()
        |> Ecto.Multi.update(
          :connection,
          Connection.refresh_changeset(connection, token_response)
        )
        |> Ecto.Multi.run(:audit_log, fn repo, %{connection: updated_connection} ->
          AuditLog.log_connection_event(:token_refreshed, updated_connection, true)
          |> repo.insert()
        end)
        |> repo().transaction()
        |> case do
          {:ok, %{connection: updated_connection}} -> {:ok, updated_connection}
          {:error, _op, reason, _changes} -> {:error, reason}
        end
      rescue
        _e in [Ecto.StaleEntryError] -> {:error, :concurrent_refresh}
      end
    else
      {:error, reason} = error ->
        Ecto.Multi.new()
        |> Ecto.Multi.run(:failure, fn _repo, _changes ->
          record_refresh_failure(connection, reason)
        end)
        |> Ecto.Multi.run(:audit_log, fn repo, %{failure: failed_connection} ->
          AuditLog.log_connection_event(:token_refresh_failed, failed_connection, false, %{
            reason: reason,
            attempts: failed_connection.refresh_attempts
          })
          |> repo.insert()
        end)
        |> repo().transaction()

        error
    end
  end

  @doc """
  Refreshes connections that are about to expire.

  Should be called periodically by a background job.

  ## Examples

      iex> refresh_expiring_connections()
      {:ok, 3}  # 3 connections refreshed

  """
  def refresh_expiring_connections do
    # Find connections that need refresh
    buffer_time = refresh_buffer_time()

    batch_size = Application.get_env(:tango, :refresh_batch_size, 100)

    connections =
      from(c in Connection,
        where: c.status == :active,
        where: c.auto_refresh_enabled == true,
        where: not c.refresh_exhausted,
        where: not is_nil(c.refresh_token),
        where: not is_nil(c.expires_at),
        where: c.expires_at <= ^buffer_time,
        limit: ^batch_size,
        preload: [:provider]
      )
      |> repo().all()

    results =
      connections
      |> Enum.map(&refresh_connection/1)
      |> Enum.group_by(&elem(&1, 0))

    success_count = Map.get(results, :ok, []) |> length()
    failure_count = Map.get(results, :error, []) |> length()

    # Log batch refresh summary
    if success_count > 0 or failure_count > 0 do
      AuditLog.log_system_event(:batch_token_refresh, true, %{
        success_count: success_count,
        failure_count: failure_count,
        total_processed: length(connections)
      })
      |> repo().insert()
    end

    {:ok, success_count}
  end

  @doc """
  Revokes a connection.

  Marks connection as revoked and logs the action.

  ## Examples

      iex> revoke_connection(connection, "user-123")
      {:ok, %Connection{status: "revoked"}}

  """
  def revoke_connection(%Connection{tenant_id: tenant_id} = connection, tenant_id) do
    Ecto.Multi.new()
    |> Ecto.Multi.update(:connection, Connection.changeset(connection, %{status: "revoked"}))
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

  def revoke_connection(%Connection{}, _tenant_id) do
    {:error, :not_authorized}
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
      {count, _} =
        from(c in Connection,
          where: c.tenant_id == ^tenant_id,
          where: c.status == :active
        )
        |> repo.update_all(set: [status: :revoked, updated_at: DateTime.utc_now()])

      {:ok, count}
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
      {count, _} =
        from(c in Connection,
          where: c.provider_id == ^provider.id,
          where: c.status == :active
        )
        |> repo.update_all(set: [status: :revoked, updated_at: DateTime.utc_now()])

      {:ok, count}
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

  defp perform_token_refresh(oauth_config, connection) do
    oauth_config
    |> build_refresh_client(connection.refresh_token)
    |> OAuth2.Client.get_token()
    |> case do
      {:ok, %{token: token}} -> {:ok, convert_token_to_response(token, connection)}
      {:error, %OAuth2.Error{reason: reason}} -> {:error, reason}
      {:error, reason} -> {:error, reason}
    end
  end

  defp build_refresh_client(oauth_config, refresh_token) do
    OAuth2.Client.new(
      strategy: OAuth2.Strategy.Refresh,
      client_id: oauth_config.client_id,
      client_secret: oauth_config.client_secret,
      token_url: oauth_config.token_url,
      serializers: %{"application/json" => Jason},
      params: %{"refresh_token" => refresh_token}
    )
  end

  defp convert_token_to_response(%OAuth2.AccessToken{} = token, connection) do
    %{
      "access_token" => token.access_token,
      "refresh_token" => token.refresh_token || connection.refresh_token,
      "token_type" => token.token_type,
      "expires_in" => calculate_expires_in(token.expires_at),
      "scope" => token.other_params["scope"]
    }
  end

  defp record_refresh_failure(connection, reason) do
    connection
    |> Connection.record_refresh_failure(reason)
    |> repo().update()
  end

  defp calculate_expires_in(expires_at) do
    expires_at
    |> DateTime.from_unix!()
    |> DateTime.diff(DateTime.utc_now())
  end

  defp cleanup_cutoff_date do
    DateTime.add(DateTime.utc_now(), -30 * 24 * 60 * 60, :second)
  end

  defp refresh_buffer_time do
    DateTime.add(DateTime.utc_now(), 5 * 60, :second)
  end
end

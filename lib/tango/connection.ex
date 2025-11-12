defmodule Tango.Connection do
  @moduledoc """
  Context module for OAuth connection management with multi-tenant isolation.

  Provides connection lifecycle management, token refresh, and multi-tenant
  isolation with comprehensive audit logging and automatic token refresh.
  """

  import Ecto.Query, warn: false
  # Repo will be configured by the host application
  @repo Application.compile_env(:tango, :repo, Tango.Repo)

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
    query = from(c in Connection, where: c.tenant_id == ^tenant_id and c.status == :active)

    query =
      case Keyword.get(opts, :provider) do
        nil ->
          query

        provider_name ->
          from(c in query,
            join: p in assoc(c, :provider),
            where: p.name == ^provider_name
          )
      end

    query =
      if Keyword.get(opts, :preload, true) do
        from(c in query, preload: [:provider])
      else
        query
      end

    @repo.all(query)
  end

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
    case @repo.get_by(Connection, id: connection_id, tenant_id: tenant_id) do
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

    case @repo.one(query) do
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
    auto_refresh = Keyword.get(opts, :auto_refresh, false)

    with {:ok, connection} <- get_connection_for_provider(provider_slug, tenant_id) do
      if auto_refresh and Connection.needs_refresh?(connection) and
           Connection.can_refresh?(connection) do
        case refresh_connection(connection) do
          {:ok, refreshed_connection} ->
            {:ok, refreshed_connection}

          {:error, _refresh_error} ->
            # Return original connection if refresh fails - let caller handle expired token
            {:ok, connection}
        end
      else
        {:ok, connection}
      end
    end
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
    |> @repo.update()
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
         {:ok, provider} <- get_connection_provider(connection),
         {:ok, oauth_config} <- Provider.get_oauth_credentials(provider),
         {:ok, token_response} <- perform_token_refresh(oauth_config, connection),
         {:ok, updated_connection} <- update_connection_from_refresh(connection, token_response) do
      # Log successful refresh
      AuditLog.log_connection_event(:token_refreshed, updated_connection, true)
      |> @repo.insert()

      {:ok, updated_connection}
    else
      {:error, reason} = error ->
        # Record refresh failure
        {:ok, failed_connection} = record_refresh_failure(connection, reason)

        # Log failed refresh
        AuditLog.log_connection_event(:token_refresh_failed, failed_connection, false, %{
          reason: reason,
          attempts: failed_connection.refresh_attempts
        })
        |> @repo.insert()

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

    connections =
      from(c in Connection,
        where: c.status == :active,
        where: c.auto_refresh_enabled == true,
        where: not c.refresh_exhausted,
        where: not is_nil(c.refresh_token),
        where: not is_nil(c.expires_at),
        where: c.expires_at <= ^buffer_time,
        preload: [:provider]
      )
      |> @repo.all()

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
      |> @repo.insert()
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
    changeset = Connection.changeset(connection, %{status: "revoked"})

    case @repo.update(changeset) do
      {:ok, revoked_connection} ->
        # Log connection revocation
        AuditLog.log_connection_event(:connection_revoked, revoked_connection, true)
        |> @repo.insert()

        {:ok, revoked_connection}

      error ->
        error
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
    {count, _} =
      from(c in Connection,
        where: c.tenant_id == ^tenant_id,
        where: c.status == :active
      )
      |> @repo.update_all(set: [status: :revoked, updated_at: DateTime.utc_now()])

    if count > 0 do
      AuditLog.log_system_event(:tenant_connections_revoked, true, %{
        tenant_id: tenant_id,
        revoked_count: count
      })
      |> @repo.insert()
    end

    {:ok, count}
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
      {count, _} =
        from(c in Connection,
          where: c.provider_id == ^provider.id,
          where: c.status == :active
        )
        |> @repo.update_all(set: [status: :revoked, updated_at: DateTime.utc_now()])

      if count > 0 do
        AuditLog.log_system_event(:provider_connections_revoked, true, %{
          provider_name: provider_name,
          revoked_count: count
        })
        |> @repo.insert()
      end

      {:ok, count}
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

    {count, _} =
      from(c in Connection,
        where: c.status == :expired,
        where: c.updated_at < ^cleanup_cutoff
      )
      |> @repo.delete_all()

    if count > 0 do
      AuditLog.log_system_event(:expired_connections_cleanup, true, %{
        cleaned_count: count,
        cutoff_date: cleanup_cutoff
      })
      |> @repo.insert()
    end

    {:ok, count}
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
    # Use CTEs for better performance - single query instead of two separate ones
    status_counts_cte =
      from(c in Connection,
        where: c.tenant_id == ^tenant_id,
        group_by: c.status,
        select: %{status: c.status, count: count(c.id)}
      )

    active_providers_cte =
      from(c in Connection,
        join: p in assoc(c, :provider),
        where: c.tenant_id == ^tenant_id,
        where: c.status == :active,
        distinct: p.name,
        select: %{name: p.name}
      )

    # Main query using both CTEs
    query =
      from(c in Connection)
      |> with_cte("status_counts", as: ^status_counts_cte)
      |> with_cte("active_providers", as: ^active_providers_cte)
      |> select([c], %{
        status_counts: fragment("(SELECT json_object_agg(status, count) FROM status_counts)"),
        providers: fragment("(SELECT json_agg(name ORDER BY name) FROM active_providers)")
      })
      |> limit(1)

    case @repo.one(query) do
      %{status_counts: status_counts, providers: providers} ->
        status_counts = status_counts || %{}
        providers = providers || []

        %{
          active: Map.get(status_counts, "active", 0),
          expired: Map.get(status_counts, "expired", 0),
          revoked: Map.get(status_counts, "revoked", 0),
          total: Map.values(status_counts) |> Enum.sum(),
          providers: providers
        }

      nil ->
        # Empty result fallback
        %{active: 0, expired: 0, revoked: 0, total: 0, providers: []}
    end
  end

  defp validate_refresh_eligibility(%Connection{} = connection) do
    cond do
      not Connection.can_refresh?(connection) ->
        {:error, :refresh_not_allowed}

      connection.refresh_token == nil ->
        {:error, :no_refresh_token}

      true ->
        :ok
    end
  end

  defp get_connection_provider(%Connection{provider_id: provider_id}) do
    case @repo.get(Provider, provider_id) do
      nil -> {:error, :provider_not_found}
      provider -> {:ok, provider}
    end
  end

  defp perform_token_refresh(oauth_config, connection) do
    # Build OAuth2 client for refresh
    client =
      OAuth2.Client.new(
        client_id: oauth_config.client_id,
        client_secret: oauth_config.client_secret,
        token_url: oauth_config.token_url,
        serializers: %{"application/json" => Jason}
      )

    # Prepare refresh parameters
    refresh_params = [
      refresh_token: connection.refresh_token,
      grant_type: "refresh_token"
    ]

    # Perform refresh
    case OAuth2.Client.refresh_token(client, refresh_params) do
      {:ok, %{token: %OAuth2.AccessToken{} = new_token}} ->
        # Convert to our token response format
        token_response = %{
          "access_token" => new_token.access_token,
          "refresh_token" => new_token.refresh_token || connection.refresh_token,
          "token_type" => new_token.token_type,
          "expires_in" => calculate_expires_in(new_token.expires_at),
          "scope" => new_token.other_params["scope"]
        }

        {:ok, token_response}

      {:error, %OAuth2.Error{reason: reason}} ->
        {:error, reason}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp update_connection_from_refresh(connection, token_response) do
    connection
    |> Connection.refresh_changeset(token_response)
    |> @repo.update()
  end

  defp record_refresh_failure(connection, reason) do
    connection
    |> Connection.record_refresh_failure(reason)
    |> @repo.update()
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
    DateTime.add(DateTime.utc_now(), 10 * 60, :second)
  end
end

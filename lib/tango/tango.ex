defmodule Tango do
  @moduledoc """
  OAuth2 integration library for Elixir applications.

  Provides OAuth2 Authorization Code Flow with PKCE support,
  multi-tenant token management, and provider configuration.

  ## Ready-to-Use API

  For Phoenix applications, Tango provides a complete OAuth API that can be
  mounted with a single line:

      # In your Phoenix router
      scope "/api/oauth" do
        pipe_through :api
        forward "/", Tango.API.Router
      end

  See `Tango.API` for complete setup and usage documentation.

  ## Direct Library Usage

  You can also use Tango's functions directly in your application code:
  """

  @doc """
  Creates OAuth session for provider and tenant.

  Returns session that can be used to generate authorization URL.

  ## Examples

      iex> Tango.create_session("github", "user-123")
      {:ok, %Tango.Schemas.OAuthSession{}}

      iex> Tango.create_session("nonexistent", "user-123")
      {:error, :provider_not_found}

  """
  defdelegate create_session(provider_name, tenant_id, opts \\ []), to: Tango.Auth

  @doc """
  Creates an authorization session with server-bound intent and completion data.
  """
  defdelegate create_authorization_session(provider_name, tenant_id, opts), to: Tango.Auth

  @doc """
  Generates OAuth authorization URL with PKCE support.

  ## Examples

      iex> Tango.authorize_url("session_token", redirect_uri: "https://app.com/callback")
      {:ok, "https://provider.com/oauth/authorize?..."}

  """
  defdelegate authorize_url(session_token, opts \\ []), to: Tango.Auth

  @doc """
  Exchanges authorization code for access token.

  Validates session state, exchanges code with provider, and creates connection
  with multi-tenant isolation.

  ## Examples

      iex> Tango.exchange_code("state", "code", "tenant-123", redirect_uri: "https://app.com/callback")
      {:ok, %Tango.Schemas.Connection{}}

  """
  defdelegate exchange_code(state, code, tenant_id, opts), to: Tango.Auth

  @doc """
  Exchanges an authorization code into an encrypted, short-lived candidate.
  """
  defdelegate stage_authorization(state, code, tenant_id, opts), to: Tango.Authorization

  @doc """
  Deletes expired and consumed authorization candidates.

  Returns `{:ok, deleted_count}`. Token columns are wiped before the rows are
  deleted, and the audit entry records only the count and a cleanup category.

  Tango does not start a scheduler. Schedule this from the consuming
  application's own job runner (Oban, Quantum, a GenServer timer, ...) together
  with `Tango.cleanup_expired_sessions/0`, which is also unscheduled by default.
  Run this function first so candidate credentials are wiped before the sessions
  they belong to are deleted:

      def perform(_job) do
        {:ok, _candidates} = Tango.cleanup_expired_authorizations()
        {:ok, _sessions} = Tango.cleanup_expired_sessions()
        :ok
      end

  Running it every few minutes keeps the candidate table small, since candidates
  live for at most ten minutes.
  """
  defdelegate cleanup_expired_authorizations(), to: Tango.Authorization

  @doc """
  Verifies a staged authorization candidate with a trusted server callback.
  """
  defdelegate verify_authorization(handle, tenant_id, verifier, opts), to: Tango.Authorization

  @doc """
  Adds atomic authorization finalization to a consumer-owned Ecto.Multi.
  """
  defdelegate multi_finalize_authorization(multi, name, handle, tenant_id, opts),
    to: Tango.Authorization

  @doc """
  Verifies and conditionally binds the identity of an active connection.
  """
  defdelegate verify_connection_identity(connection_id, tenant_id, verifier),
    to: Tango.Authorization

  @doc """
  Gets OAuth session by token.

  ## Examples

      iex> Tango.get_session("session_token")
      {:ok, %Tango.Schemas.OAuthSession{}}

  """
  defdelegate get_session(session_token), to: Tango.Auth

  @doc """
  Cleans up expired OAuth sessions.

  ## Examples

      iex> Tango.cleanup_expired_sessions()
      {:ok, 5}  # 5 sessions cleaned up

  """
  defdelegate cleanup_expired_sessions(), to: Tango.Auth

  # Provider management functions

  @doc """
  Lists active OAuth providers.

  ## Examples

      iex> Tango.list_providers()
      [%Tango.Schemas.Provider{}, ...]

  """
  defdelegate list_providers(), to: Tango.Provider

  @doc """
  Gets provider by name.

  ## Examples

      iex> Tango.get_provider("github")
      {:ok, %Tango.Schemas.Provider{}}

  """
  defdelegate get_provider(name), to: Tango.Provider

  @doc """
  Gets provider by ID.

  ## Examples

      iex> Tango.get_provider_by_id(provider_id)
      {:ok, %Tango.Schemas.Provider{}}

  """
  defdelegate get_provider_by_id(id), to: Tango.Provider

  @doc """
  Creates a new provider.

  ## Examples

      iex> Tango.create_provider(%{name: "custom", display_name: "Custom OAuth"})
      {:ok, %Tango.Schemas.Provider{}}

  """
  defdelegate create_provider(attrs), to: Tango.Provider

  @doc """
  Creates provider from Nango configuration.

  ## Examples

      iex> Tango.create_provider_from_nango("github", nango_config, client_id: "abc", client_secret: "xyz")
      {:ok, %Tango.Schemas.Provider{}}

  """
  defdelegate create_provider_from_nango(name, nango_config, opts \\ []), to: Tango.Provider

  @doc """
  Updates a provider.

  ## Examples

      iex> Tango.update_provider(provider, %{display_name: "New Name"})
      {:ok, %Tango.Schemas.Provider{}}

  """
  defdelegate update_provider(provider, attrs), to: Tango.Provider

  @doc """
  Soft deletes a provider.

  ## Examples

      iex> Tango.delete_provider(provider)
      {:ok, %Tango.Schemas.Provider{active: false}}

  """
  defdelegate delete_provider(provider), to: Tango.Provider

  # Connection management functions

  @doc """
  Lists active connections for a tenant.

  ## Examples

      iex> Tango.list_connections("user-123")
      [%Tango.Schemas.Connection{}, ...]

  """
  defdelegate list_connections(tenant_id, opts \\ []), to: Tango.Connection

  @doc """
  Gets credential-free connection info for any status.

  Missing and wrong-tenant ids both return `{:error, :not_found}`. The read
  does not refresh tokens or take locks. `:active` does not promise the access
  token is usable.

  ## Examples

      iex> Tango.get_connection_info(123, "user-123")
      {:ok, %Tango.ConnectionInfo{id: 123, status: :active}}

  """
  defdelegate get_connection_info(connection_id, tenant_id), to: Tango.Connection

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

      iex> Tango.list_connection_infos("user-123")
      [%Tango.ConnectionInfo{}, ...]

      iex> Tango.list_connection_infos("user-123", provider_slug: "records", status: :any)
      [%Tango.ConnectionInfo{}, ...]

  """
  defdelegate list_connection_infos(tenant_id, opts \\ []), to: Tango.Connection

  @doc """
  Gets connection for provider and tenant.

  With `auto_refresh: true`, a refresh that cannot fall back to an active,
  unexpired token returns `{:error, {:refresh_failed, reason}}`. `reason` is
  a `Tango.RefreshError` term.

  ## Examples

      iex> Tango.get_connection_for_provider("github", "user-123")
      {:ok, %Tango.Schemas.Connection{}}

      iex> Tango.get_connection_for_provider("github", "user-123", auto_refresh: true)
      {:ok, %Tango.Schemas.Connection{}}

  """
  defdelegate get_connection_for_provider(provider_name, tenant_id), to: Tango.Connection
  defdelegate get_connection_for_provider(provider_name, tenant_id, opts), to: Tango.Connection

  @doc """
  Gets an active connection by ID with tenant isolation and optional refresh.

  `auto_refresh: true` uses the same envelope as
  `Tango.Connection.refresh_if_needed/1`: `{:error, {:refresh_failed, reason}}`
  unless the active, unexpired token may still be served.
  """
  defdelegate get_active_connection(connection_id, tenant_id, opts \\ []), to: Tango.Connection

  @doc """
  Refreshes an OAuth connection's access token.

  Returns `{:error, reason}` for a failed refresh, including while the current
  access token still has time left. `reason` is a `Tango.RefreshError` term.
  On-demand reads use `Tango.Connection.refresh_if_needed/1` and may wrap that
  reason as `{:error, {:refresh_failed, reason}}`.

  ## Examples

      iex> Tango.refresh_connection(connection)
      {:ok, %Tango.Schemas.Connection{}}

      iex> Tango.refresh_connection(connection)
      {:error, {:oauth_error, :invalid_grant}}

  """
  defdelegate refresh_connection(connection), to: Tango.Connection

  @doc """
  Records the provider rejecting a connection's credentials.

  Call this when a provider rejects the connection's credentials outright — an
  HTTP 401, or a 403 whose provider-specific error body confirms an invalid or
  revoked token rather than a policy, scope, or quota denial. Tango cannot see
  the calls made with the tokens it issues, so a revoked credential stays
  `:active` until a consumer reports the rejection. The connection is expired
  once the rejections reach `opts[:max_failures]` (default 3), after which
  `get_connection_for_provider/2` returns `{:error, :not_found}`. Pass a
  threshold matched to how often the caller hits that provider — the count is a
  number of rejections, not a duration.

  Accepts a connection, or a connection id together with `opts[:tenant_id]`.
  Only active connections accept a report.

  ## Examples

      iex> Tango.record_auth_failure(connection, "http_401")
      {:ok, %Tango.Schemas.Connection{auth_failures: 1}}

      iex> Tango.record_auth_failure(connection_id, "http_401", tenant_id: "user-123", max_failures: 10)
      {:ok, %Tango.Schemas.Connection{auth_failures: 1}}

  """
  defdelegate record_auth_failure(connection, error_reason, opts \\ []), to: Tango.Connection

  @doc """
  Clears a connection's rejection streak after a call authenticates again.

  Pairs with `record_auth_failure/3` to keep its count consecutive. Accepts a
  connection, or a connection id together with `opts[:tenant_id]`.

  ## Examples

      iex> Tango.record_auth_success(connection)
      :ok

  """
  defdelegate record_auth_success(connection, opts \\ []), to: Tango.Connection

  @doc """
  Marks connection as used (updates timestamp).

  ## Examples

      iex> Tango.mark_connection_used(connection)
      {:ok, %Tango.Schemas.Connection{}}

  """
  defdelegate mark_connection_used(connection), to: Tango.Connection

  @doc """
  Acquires generation locks for one tenant's providers.

  The caller must already be inside a transaction on Tango's configured repo,
  in this process. A sandbox checkout or another repo's transaction returns
  `{:error, :not_in_transaction}` before lookup, including for `[]`.

  Inactive providers are resolved. `missing: :error` (the default) returns the
  first unknown slug in input order and takes no locks. `missing: :skip`
  ignores unknown slugs. Invalid options raise `ArgumentError`.

  Pairs lock by provider id, then Elixir tenant binary order, and last until
  the outer transaction commits or rolls back. A nested commit does not release
  them. Acquire the tenant's full provider set once before nested Tango calls.
  Repeating a held key is safe. Adding a lower key later, or composing several
  tenants in arbitrary order, can deadlock. Locks neither authorize the caller
  nor replace a later state check.

  ## Examples

      iex> Repo.transaction(fn -> Tango.lock_connection_generations("user-123", ["records"]) end)
      {:ok, :ok}

  """
  defdelegate lock_connection_generations(tenant_id, provider_slugs, opts \\ []),
    to: Tango.Connection

  @doc """
  Revokes a connection for a tenant.

  Accepts the connection struct or its integer id. Missing, wrong-tenant, and
  already-revoked ids return `{:error, :not_found}`. A struct whose tenant does
  not match returns `{:error, :not_authorized}`. Active and expired connections
  can be revoked.

  ## Examples

      iex> Tango.revoke_connection(connection, "user-123")
      {:ok, %Tango.Schemas.Connection{status: :revoked}}

      iex> Tango.revoke_connection(123, "user-123")
      {:ok, %Tango.Schemas.Connection{status: :revoked}}

  """
  defdelegate revoke_connection(connection, tenant_id), to: Tango.Connection

  @doc """
  Refreshes connections about to expire.

  ## Examples

      iex> Tango.refresh_expiring_connections()
      {:ok, 3}  # 3 connections refreshed

  """
  defdelegate refresh_expiring_connections(), to: Tango.Connection
end

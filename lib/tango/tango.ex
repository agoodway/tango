defmodule Tango do
  @moduledoc """
  OAuth2 integration library for Elixir applications.

  Provides OAuth2 Authorization Code Flow with PKCE support,
  multi-tenant token management, and provider configuration.
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
  Gets connection for provider and tenant.

  ## Examples

      iex> Tango.get_connection_for_provider("github", "user-123")
      {:ok, %Tango.Schemas.Connection{}}

  """
  defdelegate get_connection_for_provider(provider_name, tenant_id), to: Tango.Connection

  @doc """
  Refreshes an OAuth connection's access token.

  ## Examples

      iex> Tango.refresh_connection(connection)
      {:ok, %Tango.Schemas.Connection{}}

  """
  defdelegate refresh_connection(connection), to: Tango.Connection

  @doc """
  Marks connection as used (updates timestamp).

  ## Examples

      iex> Tango.mark_connection_used(connection)
      {:ok, %Tango.Schemas.Connection{}}

  """
  defdelegate mark_connection_used(connection), to: Tango.Connection

  @doc """
  Revokes a connection for a tenant.

  ## Examples

      iex> Tango.revoke_connection(connection, "user-123")
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

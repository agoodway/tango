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
  def create_session(provider_name, tenant_id, opts \\ []) do
    Tango.Auth.create_session(provider_name, tenant_id, opts)
  end

  @doc """
  Generates OAuth authorization URL with PKCE support.

  ## Examples

      iex> Tango.authorize_url("session_token", redirect_uri: "https://app.com/callback")
      {:ok, "https://provider.com/oauth/authorize?..."}

  """
  def authorize_url(session_token, opts \\ []) do
    Tango.Auth.authorize_url(session_token, opts)
  end

  @doc """
  Exchanges authorization code for access token.

  SECURITY: Use the 4-argument version with tenant_id for secure multi-tenant isolation.

  ## Examples

      iex> Tango.exchange_code("state", "code", "tenant-123", redirect_uri: "https://app.com/callback")
      {:ok, %Tango.Schemas.Connection{}}

  """
  # Secure version with tenant validation (recommended)
  def exchange_code(state, code, tenant_id, opts)
      when is_binary(state) and is_binary(code) and is_binary(tenant_id) and is_list(opts) do
    Tango.Auth.exchange_code(state, code, tenant_id, opts)
  end

  # Deprecated version for backward compatibility
  def exchange_code(state, code, opts)
      when is_binary(state) and is_binary(code) and is_list(opts) do
    Tango.Auth.exchange_code(state, code, opts)
  end

  @doc """
  Gets OAuth session by token.

  ## Examples

      iex> Tango.get_session("session_token")
      {:ok, %Tango.Schemas.OAuthSession{}}

  """
  def get_session(session_token) do
    Tango.Auth.get_session(session_token)
  end

  @doc """
  Cleans up expired OAuth sessions.

  ## Examples

      iex> Tango.cleanup_expired_sessions()
      {:ok, 5}  # 5 sessions cleaned up

  """
  def cleanup_expired_sessions do
    Tango.Auth.cleanup_expired_sessions()
  end

  # Provider management functions

  @doc """
  Lists active OAuth providers.

  ## Examples

      iex> Tango.list_providers()
      [%Tango.Schemas.Provider{}, ...]

  """
  def list_providers do
    Tango.Provider.list_providers()
  end

  @doc """
  Gets provider by name.

  ## Examples

      iex> Tango.get_provider("github")
      {:ok, %Tango.Schemas.Provider{}}

  """
  def get_provider(name) do
    Tango.Provider.get_provider(name)
  end

  @doc """
  Creates a new provider.

  ## Examples

      iex> Tango.create_provider(%{name: "custom", display_name: "Custom OAuth"})
      {:ok, %Tango.Schemas.Provider{}}

  """
  def create_provider(attrs) do
    Tango.Provider.create_provider(attrs)
  end

  @doc """
  Creates provider from Nango configuration.

  ## Examples

      iex> Tango.create_provider_from_nango("github", nango_config, client_id: "abc", client_secret: "xyz")
      {:ok, %Tango.Schemas.Provider{}}

  """
  def create_provider_from_nango(name, nango_config, opts \\ []) do
    Tango.Provider.create_provider_from_nango(name, nango_config, opts)
  end

  @doc """
  Updates a provider.

  ## Examples

      iex> Tango.update_provider(provider, %{display_name: "New Name"})
      {:ok, %Tango.Schemas.Provider{}}

  """
  def update_provider(provider, attrs) do
    Tango.Provider.update_provider(provider, attrs)
  end

  @doc """
  Soft deletes a provider.

  ## Examples

      iex> Tango.delete_provider(provider)
      {:ok, %Tango.Schemas.Provider{active: false}}

  """
  def delete_provider(provider) do
    Tango.Provider.delete_provider(provider)
  end

  # Connection management functions

  @doc """
  Lists active connections for a tenant.

  ## Examples

      iex> Tango.list_connections("user-123")
      [%Tango.Schemas.Connection{}, ...]

  """
  def list_connections(tenant_id, opts \\ []) do
    Tango.Connection.list_connections(tenant_id, opts)
  end

  @doc """
  Gets connection for provider and tenant.

  ## Examples

      iex> Tango.get_connection_for_provider("github", "user-123")
      {:ok, %Tango.Schemas.Connection{}}

  """
  def get_connection_for_provider(provider_name, tenant_id) do
    Tango.Connection.get_connection_for_provider(provider_name, tenant_id)
  end

  @doc """
  Refreshes an OAuth connection's access token.

  ## Examples

      iex> Tango.refresh_connection(connection)
      {:ok, %Tango.Schemas.Connection{}}

  """
  def refresh_connection(connection) do
    Tango.Connection.refresh_connection(connection)
  end

  @doc """
  Marks connection as used (updates timestamp).

  ## Examples

      iex> Tango.mark_connection_used(connection)
      {:ok, %Tango.Schemas.Connection{}}

  """
  def mark_connection_used(connection) do
    Tango.Connection.mark_connection_used(connection)
  end

  @doc """
  Revokes a connection for a tenant.

  ## Examples

      iex> Tango.revoke_connection(connection, "user-123")
      {:ok, %Tango.Schemas.Connection{status: :revoked}}

  """
  def revoke_connection(connection, tenant_id) do
    Tango.Connection.revoke_connection(connection, tenant_id)
  end

  @doc """
  Refreshes connections about to expire.

  ## Examples

      iex> Tango.refresh_expiring_connections()
      {:ok, 3}  # 3 connections refreshed

  """
  def refresh_expiring_connections do
    Tango.Connection.refresh_expiring_connections()
  end
end

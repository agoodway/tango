defmodule Tango.Validation do
  @moduledoc """
  Comprehensive input validation for the Tango OAuth library.

  This module provides validation functions for all user inputs to prevent
  security vulnerabilities and ensure data integrity.
  """

  @doc """
  Validates tenant ID format and security.

  ## Examples

      iex> Tango.Validation.validate_tenant_id("tenant-123")
      :ok
      
      iex> Tango.Validation.validate_tenant_id("")
      {:error, :invalid_tenant_id}
      
      iex> Tango.Validation.validate_tenant_id("tenant'; DROP TABLE users; --")
      {:error, :invalid_tenant_id}

  """
  def validate_tenant_id(tenant_id) when is_binary(tenant_id) do
    cond do
      byte_size(tenant_id) == 0 ->
        {:error, :invalid_tenant_id}

      byte_size(tenant_id) > 255 ->
        {:error, :tenant_id_too_long}

      not String.match?(tenant_id, ~r/^[a-zA-Z0-9_-]+$/) ->
        {:error, :invalid_tenant_id}

      true ->
        :ok
    end
  end

  def validate_tenant_id(_), do: {:error, :invalid_tenant_id}

  @doc """
  Validates OAuth state parameter.

  ## Examples

      iex> valid_state = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
      iex> Tango.Validation.validate_state(valid_state)
      :ok
      
      iex> Tango.Validation.validate_state("short")
      {:error, :invalid_state}

  """
  def validate_state(state) when is_binary(state) do
    cond do
      byte_size(state) < 16 ->
        {:error, :state_too_short}

      byte_size(state) > 128 ->
        {:error, :state_too_long}

      not String.match?(state, ~r/^[a-zA-Z0-9_-]+$/) ->
        {:error, :invalid_state}

      true ->
        :ok
    end
  end

  def validate_state(_), do: {:error, :invalid_state}

  @doc """
  Validates authorization code format.

  ## Examples

      iex> Tango.Validation.validate_authorization_code("valid-auth-code-123")
      :ok
      
      iex> Tango.Validation.validate_authorization_code("")
      {:error, :invalid_authorization_code}

  """
  def validate_authorization_code(""), do: {:error, :invalid_authorization_code}

  def validate_authorization_code(code) when is_binary(code) and byte_size(code) > 512 do
    {:error, :authorization_code_too_long}
  end

  def validate_authorization_code(code) when is_binary(code) do
    if String.match?(code, ~r/^[a-zA-Z0-9_.-]+$/) do
      :ok
    else
      {:error, :invalid_authorization_code}
    end
  end

  def validate_authorization_code(_), do: {:error, :invalid_authorization_code}

  @doc """
  Validates provider slug format.

  ## Examples

      iex> Tango.Validation.validate_provider_slug("github")
      :ok
      
      iex> Tango.Validation.validate_provider_slug("invalid slug")
      {:error, :invalid_provider_slug}

  """
  def validate_provider_slug(""), do: {:error, :invalid_provider_slug}

  def validate_provider_slug(slug) when is_binary(slug) and byte_size(slug) > 50 do
    {:error, :provider_slug_too_long}
  end

  def validate_provider_slug(slug) when is_binary(slug) do
    if String.match?(slug, ~r/^[a-z0-9_-]+$/) do
      :ok
    else
      {:error, :invalid_provider_slug}
    end
  end

  def validate_provider_slug(_), do: {:error, :invalid_provider_slug}

  @doc """
  Validates redirect URI for security.

  ## Examples

      iex> Tango.Validation.validate_redirect_uri("https://app.com/callback")
      :ok
      
      iex> Tango.Validation.validate_redirect_uri("javascript:alert('xss')")
      {:error, :unsafe_redirect_uri}

  """
  def validate_redirect_uri(uri) when is_binary(uri) do
    case URI.parse(uri) do
      %URI{scheme: nil} ->
        {:error, :invalid_redirect_uri}

      %URI{scheme: scheme} when scheme in ["javascript", "data", "file", "ftp"] ->
        {:error, :unsafe_redirect_uri}

      %URI{scheme: "https", host: host} when not is_nil(host) ->
        :ok

      %URI{scheme: "http", host: host} when not is_nil(host) ->
        # Allow HTTP only for localhost and local development
        if host in ["localhost", "127.0.0.1"] or String.ends_with?(host, ".local") do
          :ok
        else
          # Reject HTTP for external domains for security
          {:error, :insecure_redirect_uri}
        end

      %URI{scheme: "custom"} ->
        # Allow custom schemes for mobile apps (e.g., myapp://oauth/callback)
        :ok

      _ ->
        {:error, :invalid_redirect_uri}
    end
  end

  def validate_redirect_uri(_), do: {:error, :invalid_redirect_uri}

  @doc """
  Validates redirect URI when present, allows nil for session creation.
  """
  def validate_optional_redirect_uri(nil), do: :ok
  def validate_optional_redirect_uri(uri), do: validate_redirect_uri(uri)

  @doc """
  Validates OAuth scopes list.

  ## Examples

      iex> Tango.Validation.validate_scopes(["read", "write"])
      :ok
      
      iex> Tango.Validation.validate_scopes(["invalid scope with spaces"])
      {:error, :invalid_scopes}

  """
  def validate_scopes(scopes) when is_list(scopes) do
    if Enum.all?(scopes, &validate_scope/1) do
      :ok
    else
      {:error, :invalid_scopes}
    end
  end

  def validate_scopes(_), do: {:error, :invalid_scopes}

  defp validate_scope(scope) when is_binary(scope) do
    String.match?(scope, ~r/^[a-zA-Z0-9:._-]+$/) and byte_size(scope) <= 100
  end

  defp validate_scope(_), do: false

  @doc """
  Validates session token format.

  ## Examples

      iex> valid_token = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
      iex> Tango.Validation.validate_session_token(valid_token)
      :ok

  """
  def validate_session_token(token) when is_binary(token) do
    cond do
      byte_size(token) < 32 ->
        {:error, :session_token_too_short}

      byte_size(token) > 128 ->
        {:error, :session_token_too_long}

      not String.match?(token, ~r/^[a-zA-Z0-9_-]+$/) ->
        {:error, :invalid_session_token}

      true ->
        :ok
    end
  end

  def validate_session_token(_), do: {:error, :invalid_session_token}

  @doc """
  Validates OAuth provider configuration URLs.

  ## Examples

      iex> Tango.Validation.validate_oauth_url("https://github.com/login/oauth/authorize")
      :ok
      
      iex> Tango.Validation.validate_oauth_url("javascript:alert('xss')")
      {:error, :unsafe_oauth_url}

  """
  def validate_oauth_url(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: scheme} when scheme in ["javascript", "data", "file", "ftp"] ->
        {:error, :unsafe_oauth_url}

      %URI{scheme: "https", host: host} when not is_nil(host) ->
        :ok

      %URI{scheme: "http", host: "localhost"} ->
        # Allow HTTP for localhost development
        :ok

      %URI{scheme: "http", host: host} when not is_nil(host) ->
        # HTTP for production should be discouraged but not blocked
        {:warning, :insecure_oauth_url}

      _ ->
        {:error, :invalid_oauth_url}
    end
  end

  def validate_oauth_url(_), do: {:error, :invalid_oauth_url}

  @doc """
  Sanitizes and validates metadata map for storage.

  ## Examples

      iex> Tango.Validation.validate_metadata(%{"key" => "value"})
      {:ok, %{"key" => "value"}}
      
      iex> Tango.Validation.validate_metadata(%{sensitive_data: "secret"})
      {:ok, %{}}

  """
  def validate_metadata(metadata) when is_map(metadata) do
    # Remove sensitive fields that shouldn't be stored
    sensitive_keys = [
      :access_token,
      :refresh_token,
      :client_secret,
      :password,
      :api_key,
      :session_token,
      :code_verifier
    ]

    sanitized =
      Enum.reduce(sensitive_keys, metadata, fn key, acc ->
        Map.delete(acc, key) |> Map.delete(to_string(key))
      end)

    # Validate remaining keys and values
    if valid_metadata_map?(sanitized) do
      {:ok, sanitized}
    else
      {:error, :invalid_metadata}
    end
  end

  def validate_metadata(_), do: {:error, :invalid_metadata}

  # Prevent DoS
  defp valid_metadata_map?(map) when map_size(map) > 100, do: false

  defp valid_metadata_map?(map) do
    Enum.all?(map, fn {key, value} ->
      valid_metadata_key?(key) and valid_metadata_value?(value)
    end)
  end

  defp valid_metadata_key?(key) when is_binary(key) do
    byte_size(key) <= 50 and String.match?(key, ~r/^[a-zA-Z0-9_.-]+$/)
  end

  defp valid_metadata_key?(key) when is_atom(key) do
    valid_metadata_key?(to_string(key))
  end

  defp valid_metadata_key?(_), do: false

  defp valid_metadata_value?(value) when is_binary(value) do
    # Reasonable size limit
    byte_size(value) <= 1000
  end

  defp valid_metadata_value?(value) when is_number(value), do: true
  defp valid_metadata_value?(value) when is_boolean(value), do: true

  defp valid_metadata_value?(value) when is_list(value) do
    length(value) <= 20 and Enum.all?(value, &valid_metadata_value?/1)
  end

  defp valid_metadata_value?(value) when is_map(value) do
    map_size(value) <= 10 and valid_metadata_map?(value)
  end

  defp valid_metadata_value?(_), do: false

  @doc """
  Validates complete OAuth options map for security.

  ## Examples

      iex> opts = [redirect_uri: "https://app.com/callback", scopes: ["read"]]
      iex> Tango.Validation.validate_oauth_options(opts)
      {:ok, [redirect_uri: "https://app.com/callback", scopes: ["read"]]}

  """
  def validate_oauth_options(opts) when is_list(opts) do
    redirect_uri = Keyword.get(opts, :redirect_uri)
    scopes = Keyword.get(opts, :scopes, [])
    metadata = Keyword.get(opts, :metadata, %{})

    with :ok <- validate_optional_redirect_uri(redirect_uri),
         :ok <- validate_scopes(scopes),
         {:ok, metadata} <- validate_metadata(metadata) do
      validated_opts =
        opts
        |> Keyword.put(:metadata, metadata)
        |> Keyword.take([:redirect_uri, :scopes, :metadata])

      {:ok, validated_opts}
    else
      error -> error
    end
  end

  def validate_oauth_options(_), do: {:error, :invalid_oauth_options}
end

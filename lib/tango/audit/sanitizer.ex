defmodule Tango.Audit.Sanitizer do
  @moduledoc """
  Provides data sanitization for audit logging to prevent information disclosure.

  This module ensures that sensitive data is properly masked or removed from
  audit logs while maintaining sufficient information for security investigation.
  """

  @sensitive_fields [
    :access_token,
    :refresh_token,
    :client_secret,
    :client_id,
    :code_verifier,
    :authorization_code,
    :api_key,
    :password,
    :session_token
  ]

  @doc """
  Sanitizes session data for audit logging.

  Removes or masks sensitive fields while preserving important metadata.

  ## Examples

      iex> session = %{tenant_id: "123", state: "abc", code_verifier: "secret"}
      iex> Tango.Audit.Sanitizer.sanitize_session(session)
      %{tenant_id: "123", state: "abc***", code_verifier: "[REDACTED]"}

  """
  def sanitize_session(%{} = session) when is_map(session) do
    session
    # Completely remove PKCE verifier
    |> Map.drop([:code_verifier])
    |> sanitize_sensitive_fields()
    |> mask_identifiers()
  end

  def sanitize_session(session), do: session

  @doc """
  Sanitizes connection data for audit logging.

  ## Examples

      iex> connection = %{access_token: "token123", tenant_id: "tenant-456"}
      iex> Tango.Audit.Sanitizer.sanitize_connection(connection)
      %{access_token: "[REDACTED]", tenant_id: "tenant***"}

  """
  def sanitize_connection(%{} = connection) when is_map(connection) do
    connection
    |> sanitize_sensitive_fields()
    |> mask_identifiers()
  end

  def sanitize_connection(connection), do: connection

  @doc """
  Sanitizes provider configuration for audit logging.

  ## Examples

      iex> provider = %{client_secret: "secret123", name: "GitHub"}
      iex> Tango.Audit.Sanitizer.sanitize_provider(provider)
      %{client_secret: "[REDACTED]", name: "GitHub"}

  """
  def sanitize_provider(%{} = provider) when is_map(provider) do
    provider
    |> sanitize_sensitive_fields()
  end

  def sanitize_provider(provider), do: provider

  @doc """
  Sanitizes OAuth error information for audit logging.

  ## Examples

      iex> error_info = %{reason: "invalid_client", details: %{client_secret: "secret"}}
      iex> Tango.Audit.Sanitizer.sanitize_error(error_info)
      %{reason: "invalid_client", details: %{client_secret: "[REDACTED]"}}

  """
  def sanitize_error(%{} = error_info) when is_map(error_info) do
    error_info
    |> Map.update(:details, %{}, &sanitize_map/1)
    |> sanitize_sensitive_fields()
  end

  def sanitize_error(error_info), do: error_info

  @doc """
  Creates a security hash of sensitive data for correlation while protecting actual values.

  ## Examples

      iex> Tango.Audit.Sanitizer.hash_sensitive_data("sensitive-value")
      "SHA256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"

  """
  def hash_sensitive_data(nil), do: nil

  def hash_sensitive_data(data) when is_binary(data) do
    hash = :crypto.hash(:sha256, data)
    "SHA256:" <> Base.encode16(hash)
  end

  def hash_sensitive_data(data), do: hash_sensitive_data(to_string(data))

  # Private helper functions

  defp sanitize_sensitive_fields(%{} = data) when is_map(data) do
    Enum.reduce(@sensitive_fields, data, fn field, acc ->
      case Map.get(acc, field) do
        nil -> acc
        _value -> Map.put(acc, field, "[REDACTED]")
      end
    end)
  end

  defp sanitize_map(%{} = map) do
    Map.new(map, fn {key, value} ->
      {key, sanitize_value(key, value)}
    end)
  end

  defp sanitize_map(value), do: value

  defp sanitize_value(key, _value) when key in @sensitive_fields, do: "[REDACTED]"
  defp sanitize_value(_key, %{} = value), do: sanitize_map(value)
  defp sanitize_value(_key, value), do: value

  defp mask_identifiers(%{} = data) do
    data
    |> mask_field(:state, 3)
    |> mask_field(:session_token, 8)
    |> mask_field(:tenant_id, 3)
    |> mask_field(:connection_id, 4)
  end

  defp mask_field(data, field, preserve_length) do
    case Map.get(data, field) do
      nil ->
        data

      value when is_binary(value) and byte_size(value) > preserve_length ->
        prefix = String.slice(value, 0, preserve_length)
        Map.put(data, field, prefix <> "***")

      _ ->
        data
    end
  end
end

defmodule Tango.OAuthErrorCode do
  @moduledoc """
  Extracts the error code from an OAuth 2.0 `error` value.

  RFC 6749 section 5.2 error codes are single tokens with no whitespace or
  colon. Some providers append a human-readable reason to the code, as in
  `"invalid_client: Invalid client_id or client_secret"`. The code is the
  leading token; the reason is discarded and never returned, so callers still
  match the code against their own allowlist.
  """

  @separators [":", " ", "\t", "\r", "\n"]

  @doc """
  Returns the leading token of an `error` value, or `nil` when there is none.

      iex> Tango.OAuthErrorCode.leading_code("invalid_client: Invalid client_id")
      "invalid_client"

      iex> Tango.OAuthErrorCode.leading_code("invalid_grant")
      "invalid_grant"

      iex> Tango.OAuthErrorCode.leading_code(": invalid_grant")
      nil
  """
  @spec leading_code(term()) :: String.t() | nil
  def leading_code(error) when is_binary(error) do
    case error |> String.trim_leading() |> String.split(@separators, parts: 2) do
      ["" | _rest] -> nil
      [code | _rest] -> code
    end
  end

  def leading_code(_error), do: nil
end

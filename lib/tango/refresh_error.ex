defmodule Tango.RefreshError do
  @moduledoc """
  Closed refresh-failure values for token refresh.

  HTTP status wins over a misleading OAuth error body on 429, 408, and 5xx.
  Only the fixed OAuth error allowlist becomes an atom. Storage strings are
  safe JSON scalars; unknown terms become `"unknown_refresh_error"`.
  """

  @type oauth_code ::
          :invalid_grant
          | :invalid_client
          | :unauthorized_client
          | :invalid_request
          | :invalid_scope
          | :unsupported_grant_type
          | :temporarily_unavailable
          | :server_error

  @type reason ::
          {:rate_limited, non_neg_integer() | nil}
          | {:http_error, integer()}
          | {:oauth_error, oauth_code()}
          | {:transport_error, :timeout | :network_error}
          | :no_refresh_token
          | :refresh_not_allowed
          | :provider_not_found
          | :invalid_config
          | :persistence_failed
          | :transaction_failed

  @type class :: :credential | :client | :request | :transient | :local

  @oauth_codes %{
    "invalid_grant" => :invalid_grant,
    "invalid_client" => :invalid_client,
    "unauthorized_client" => :unauthorized_client,
    "invalid_request" => :invalid_request,
    "invalid_scope" => :invalid_scope,
    "unsupported_grant_type" => :unsupported_grant_type,
    "temporarily_unavailable" => :temporarily_unavailable,
    "server_error" => :server_error
  }

  @oauth_code_atoms Map.values(@oauth_codes)
  @local_reasons [
    :no_refresh_token,
    :refresh_not_allowed,
    :provider_not_found,
    :invalid_config,
    :persistence_failed,
    :transaction_failed
  ]
  @client_codes [:invalid_client, :unauthorized_client]
  @request_codes [:invalid_request, :invalid_scope, :unsupported_grant_type]
  @transient_oauth_codes [:temporarily_unavailable, :server_error]
  @default_backoff_seconds 300
  @max_backoff_seconds 3600

  @doc """
  Classifies an HTTP token-endpoint failure.

  `headers` is a tuple list. The first `retry-after` value is kept only when
  the whole value is a non-negative decimal integer. A 429, 408, or 5xx status
  ignores the body. Other 4xx failures use an allowlisted `"error"` code when the
  body is a map or a JSON object; everything else stays `{:http_error, status}`.
  """
  @spec from_response(integer(), [{String.t(), String.t()}], term()) :: reason()
  def from_response(status, headers, _body) when is_integer(status) and status == 429 do
    {:rate_limited, first_retry_after(headers)}
  end

  def from_response(status, _headers, _body)
      when status in 500..599 or status == 408 do
    {:http_error, status}
  end

  def from_response(status, _headers, body) when status in 400..499 do
    case oauth_code(body) do
      {:ok, code} -> {:oauth_error, code}
      :error -> {:http_error, status}
    end
  end

  def from_response(status, _headers, _body) when is_integer(status), do: {:http_error, status}

  @doc """
  Bounds a transport failure to `:timeout` or `:network_error`.

  `:timeout` and `:etimedout` are timeouts. Every other term, including
  unknown maps and strings, is a network error.
  """
  @spec from_transport(term()) :: {:transport_error, :timeout | :network_error}
  def from_transport(reason) when reason in [:timeout, :etimedout],
    do: {:transport_error, :timeout}

  def from_transport(_reason), do: {:transport_error, :network_error}

  @doc """
  Classifies a refresh failure for the retry policy.

  Unknown terms are `:local` and are not treated as invalid credentials.
  """
  @spec classify(term()) :: class()
  def classify({:rate_limited, seconds})
      when is_nil(seconds) or (is_integer(seconds) and seconds >= 0),
      do: :transient

  def classify({:transport_error, kind}) when kind in [:timeout, :network_error], do: :transient
  def classify({:oauth_error, :invalid_grant}), do: :credential
  def classify({:oauth_error, code}) when code in @client_codes, do: :client
  def classify({:oauth_error, code}) when code in @request_codes, do: :request
  def classify({:oauth_error, code}) when code in @transient_oauth_codes, do: :transient

  def classify({:http_error, status})
      when status in 500..599 or status == 408,
      do: :transient

  def classify({:http_error, status}) when is_integer(status), do: :request
  def classify(reason) when reason in @local_reasons, do: :local
  def classify(_reason), do: :local

  @doc """
  Serializes a refresh failure to an allowlisted string.

  Unknown terms become `"unknown_refresh_error"`. The result is a JSON scalar
  and never contains a response body, token, or arbitrary term.
  """
  @spec to_storage(term()) :: String.t()
  def to_storage({:rate_limited, nil}), do: "rate_limited"

  def to_storage({:rate_limited, seconds}) when is_integer(seconds) and seconds >= 0,
    do: "rate_limited:#{seconds}"

  def to_storage({:http_error, status}) when is_integer(status), do: "http_error:#{status}"

  def to_storage({:oauth_error, code}) when code in @oauth_code_atoms,
    do: "oauth_error:#{code}"

  def to_storage({:transport_error, :timeout}), do: "transport_error:timeout"
  def to_storage({:transport_error, :network_error}), do: "transport_error:network_error"
  def to_storage(reason) when reason in @local_reasons, do: Atom.to_string(reason)
  def to_storage(_reason), do: "unknown_refresh_error"

  @doc """
  Scheduling delay in seconds for a refresh failure.

  A numeric `Retry-After` is capped at 3600. Zero is kept. Every other reason
  waits 300 seconds. The reason itself keeps the uncapped parsed value.
  """
  @spec backoff_seconds(reason()) :: non_neg_integer()
  def backoff_seconds({:rate_limited, seconds}) when is_integer(seconds) and seconds >= 0 do
    min(seconds, @max_backoff_seconds)
  end

  def backoff_seconds(_reason), do: @default_backoff_seconds

  defp first_retry_after(headers) when is_list(headers) do
    Enum.find_value(headers, fn
      {name, value} ->
        if retry_after_name?(name), do: {:header, parse_retry_after(value)}

      _other ->
        nil
    end)
    |> case do
      {:header, seconds} -> seconds
      _other -> nil
    end
  end

  defp first_retry_after(_headers), do: nil

  defp retry_after_name?(name) when is_binary(name), do: String.downcase(name) == "retry-after"
  defp retry_after_name?(_name), do: false

  defp parse_retry_after(value) when is_binary(value) do
    if Regex.match?(~r/\A[0-9]+\z/, value), do: String.to_integer(value)
  end

  defp parse_retry_after(_value), do: nil

  defp oauth_code(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} when is_map(decoded) -> oauth_code(decoded)
      _other -> :error
    end
  end

  defp oauth_code(%{"error" => code}) when is_binary(code), do: Map.fetch(@oauth_codes, code)

  defp oauth_code(_body), do: :error
end

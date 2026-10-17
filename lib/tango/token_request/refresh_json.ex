defmodule Tango.TokenRequest.RefreshJSON do
  @moduledoc false

  @doc """
  Encodes a refresh request body.

  Delegates to Jason so a JSON token request stays compatible with the
  catalog `body_format`.
  """
  @spec encode!(term()) :: String.t()
  def encode!(data), do: Jason.encode!(data)

  @undecoded_key {__MODULE__, :undecoded}

  @doc """
  Decodes a refresh response body without raising.

  A JSON object is returned as a map. Any other body, including malformed
  JSON and JSON scalars, is returned as the original binary. OAuth2 treats a
  binary success body as the access token, so `consume_undecoded?/0` reports
  that this response must not be stored.
  """
  @spec decode!(binary()) :: term()
  def decode!(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} when is_map(decoded) -> decoded
      _other -> mark_undecoded(body)
    end
  end

  @doc """
  Returns whether the latest `decode!/1` in this process was not a JSON object.

  The flag is cleared. A decode on another process does not affect this one.
  """
  @spec consume_undecoded?() :: boolean()
  def consume_undecoded?, do: Process.delete(@undecoded_key) == true

  defp mark_undecoded(body) do
    Process.put(@undecoded_key, true)
    body
  end
end

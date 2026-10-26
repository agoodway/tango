defmodule Tango.TokenRequest.JSONSerializer do
  @moduledoc false

  @doc """
  Encodes a token request body.

  Delegates to Jason so a JSON token request stays compatible with the
  catalog `body_format`.
  """
  @spec encode!(term()) :: String.t()
  def encode!(data), do: Jason.encode!(data)

  @doc """
  Returns a token response body undecoded.

  `Tango.TokenRequest` decodes it so HTML, scalar, and malformed bodies are
  rejected instead of OAuth2 raising on them or treating a binary as the
  access token.
  """
  @spec decode!(binary()) :: binary()
  def decode!(body) when is_binary(body), do: body
end

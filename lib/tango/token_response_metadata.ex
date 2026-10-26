defmodule Tango.TokenResponseMetadata do
  @moduledoc """
  Retains configured, non-secret fields from an OAuth token response.

  A provider opts in with the Nango catalog key `"token_response_metadata"` in
  its `metadata`: a list of response field names such as `["instance_url"]`.
  A dotted name (`"team.id"`) reads a nested object and is retained under the
  dotted name itself.

  Fields are read from `OAuth2.AccessToken.other_params`. OAuth2 has already
  moved `access_token`, `refresh_token`, `expires_in`, and `token_type` out of
  that map, so those can never be retained. Only string, number, and boolean
  values are kept; absent, `nil`, and non-scalar values are skipped, as is any
  name matching `Tango.Validation.sensitive_key?/1` (for example `id_token`).
  The result may be empty.
  """

  @maximum_bytes 4 * 1024

  @doc """
  Extracts the configured fields from a token response's extra params.

  Returns `{:error, :invalid_grant_metadata}` when the retained fields encode
  to more than 4 KiB of JSON.
  """
  @spec extract(map(), map()) :: {:ok, map()} | {:error, :invalid_grant_metadata}
  def extract(other_params, %{"token_response_metadata" => fields})
      when is_map(other_params) and is_list(fields) do
    data =
      for field <- fields,
          is_binary(field),
          not Tango.Validation.sensitive_key?(field),
          {:ok, value} <- [fetch_scalar(other_params, field)],
          into: %{},
          do: {field, value}

    case Jason.encode(data) do
      {:ok, encoded} when byte_size(encoded) <= @maximum_bytes -> {:ok, data}
      _ -> {:error, :invalid_grant_metadata}
    end
  end

  def extract(_other_params, _metadata), do: {:ok, %{}}

  @doc """
  Checks a `"token_response_metadata"` setting: `nil` or a list of non-blank
  field names.
  """
  @spec valid_config?(term()) :: boolean()
  def valid_config?(nil), do: true

  def valid_config?(fields) when is_list(fields),
    do: Enum.all?(fields, &(is_binary(&1) and String.trim(&1) != ""))

  def valid_config?(_fields), do: false

  defp fetch_scalar(params, field) do
    case get_path(params, String.split(field, ".")) do
      value when is_binary(value) or is_number(value) or is_boolean(value) -> {:ok, value}
      _ -> :skip
    end
  end

  defp get_path(value, []), do: value

  defp get_path(map, [segment | rest]) when is_map(map),
    do: get_path(Map.get(map, segment), rest)

  defp get_path(_value, _segments), do: nil
end

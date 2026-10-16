defmodule Tango.TokenRequest do
  @moduledoc """
  Sends token-endpoint requests (authorization-code exchange and refresh) with
  the per-provider options recorded from the Nango catalog in provider
  `metadata` (see `Tango.Schemas.Provider.catalog_metadata/1`).

  Without those options the request is the `oauth2` library default: client
  credentials in an HTTP Basic header (plus `client_id` in the body for the
  code exchange) and a form-encoded body. The options follow Nango
  (`packages/shared/lib/clients/oauth2.client.ts` and
  `packages/server/lib/controllers/oauth.controller.ts`):

    * `"token_request_auth_method" => "basic"` - Basic header, and the client
      credentials also in the body
    * `"authorization_method" => "header"` - client credentials only in the
      Basic header
    * `"body_format" => "json"` - JSON body instead of a form
    * `"token_params"` - extra params for the code exchange; also used for
      refresh when there are no `"refresh_params"`
    * `"refresh_params"` - extra params for the refresh

  Extra params never override the grant type, code, redirect URI, PKCE
  verifier, or refresh token Tango sets.
  """

  alias OAuth2.Client
  alias Tango.TokenRequest.HeaderAuthCode

  @doc """
  Exchanges an authorization code. `params` is the keyword list of standard
  params (`code`, `redirect_uri`, `code_verifier`).
  """
  def exchange(oauth_config, metadata, params, redirect_uri) do
    metadata = metadata || %{}

    oauth_config
    |> new_client(exchange_strategy(metadata), redirect_uri: redirect_uri)
    |> Client.merge_params(extra_params(metadata["token_params"]))
    |> put_body_credentials(oauth_config, metadata)
    |> Client.get_token(params, headers(metadata))
  end

  @doc "Refreshes an access token with `refresh_token`."
  def refresh(oauth_config, metadata, refresh_token) do
    metadata = metadata || %{}

    oauth_config
    |> new_client(OAuth2.Strategy.Refresh, [])
    |> Client.merge_params(extra_params(refresh_params(metadata)))
    |> put_body_credentials(oauth_config, metadata)
    |> Client.put_param("refresh_token", refresh_token)
    |> Client.get_token([], headers(metadata))
  end

  defp new_client(oauth_config, strategy, opts) do
    Client.new(
      strategy: strategy,
      client_id: oauth_config.client_id,
      client_secret: oauth_config.client_secret,
      token_url: oauth_config.token_url,
      redirect_uri: Keyword.get(opts, :redirect_uri),
      serializers: %{"application/json" => Jason}
    )
  end

  defp exchange_strategy(%{"authorization_method" => "header"}),
    do: HeaderAuthCode

  defp exchange_strategy(_metadata), do: OAuth2.Strategy.AuthCode

  # Nango sends refresh_params when present, otherwise token_params.
  defp refresh_params(%{"refresh_params" => params}) when is_map(params) and params != %{},
    do: params

  defp refresh_params(metadata), do: metadata["token_params"]

  # The strategies set grant_type; the catalog's grant_type values only
  # describe which flow the provider uses.
  defp extra_params(params) when is_map(params) do
    params
    |> Map.new(fn {key, value} -> {to_string(key), value} end)
    |> Map.delete("grant_type")
    |> Map.reject(fn {_key, value} -> is_nil(value) end)
  end

  defp extra_params(_params), do: %{}

  defp put_body_credentials(client, oauth_config, %{"token_request_auth_method" => "basic"}) do
    Client.merge_params(client, %{
      "client_id" => oauth_config.client_id,
      "client_secret" => oauth_config.client_secret
    })
  end

  defp put_body_credentials(client, _oauth_config, _metadata), do: client

  defp headers(%{"body_format" => "json"}), do: [{"content-type", "application/json"}]
  defp headers(_metadata), do: []
end

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
    * `"authorization_method" => "body"` - client credentials in the POST
      body for code exchange and refresh, without Basic authentication unless
      `"token_request_auth_method" => "basic"` is also set
    * `"body_format" => "json"` - JSON body instead of a form
    * `"token_params"` - extra params for the code exchange; also used for
      refresh when there are no `"refresh_params"`
    * `"refresh_params"` - extra params for the refresh

  Extra params never override the grant type, code, redirect URI, PKCE
  verifier, or refresh token Tango sets.

  ## Responses

  Each call posts exactly once. JSON and form-encoded token objects are
  accepted. In error responses a JSON object body is decoded to a map; any
  other body stays the raw binary. A code exchange fails with:

    * `{:error, %OAuth2.Response{}}` - a 3xx, 4xx or 5xx status, or a 2xx JSON
      object carrying an `"error"` member
    * `{:error, :empty_access_token}` - a 2xx response with an empty body
    * `{:error, :invalid_token_response}` - any other 2xx body that is not a
      token object (HTML, a JSON scalar, malformed JSON)
    * `{:error, %OAuth2.Error{}}` - a transport failure

  A refresh fails with `{:error, %OAuth2.Response{}}` for a 4xx or 5xx status
  and for a body that is not a token object, and with
  `{:error, %OAuth2.Error{}}` for a transport failure.
  """

  alias OAuth2.{AccessToken, Client, Response}
  alias OAuth2.Strategy.{AuthCode, Refresh}
  alias Tango.TokenRequest.{HeaderAuthCode, JSONSerializer}

  @doc """
  Exchanges an authorization code. `params` is the keyword list of standard
  params (`code`, `redirect_uri`, `code_verifier`).
  """
  def exchange(oauth_config, metadata, params, redirect_uri) do
    metadata = metadata || %{}

    oauth_config
    |> new_client(exchange_strategy(metadata), redirect_uri)
    |> Client.merge_params(extra_params(metadata["token_params"]))
    |> put_body_credentials(oauth_config, metadata)
    |> request_token(params, metadata)
    |> build_exchange_token()
  end

  @doc "Refreshes an access token with `refresh_token`."
  def refresh(oauth_config, metadata, refresh_token) do
    metadata = metadata || %{}

    oauth_config
    |> new_client(Refresh, nil)
    |> Client.merge_params(extra_params(refresh_params(metadata)))
    |> put_body_credentials(oauth_config, metadata)
    |> Client.put_param("refresh_token", refresh_token)
    |> request_token([], metadata)
    |> build_refresh_token()
  end

  # Builds the request with the client's strategy and posts it once, so the
  # response body is inspected before OAuth2 can turn a binary into a token.
  defp request_token(client, params, metadata) do
    client =
      client
      |> Client.put_header("content-type", "application/x-www-form-urlencoded")
      |> Client.put_header("accept", "application/json")
      |> client.strategy.get_token(params, headers(metadata))
      |> drop_basic_auth(metadata)

    {Client.post(client, client.token_url, client.params, client.headers), client}
  end

  defp build_exchange_token({{:ok, %Response{status_code: status} = response}, client})
       when status in 200..299 do
    case token_body(response.body) do
      {:ok, %{"error" => error} = body} when not is_nil(error) ->
        {:error, %{response | body: body}}

      {:ok, body} ->
        {:ok, token_client(client, body)}

      :empty ->
        {:error, :empty_access_token}

      :error ->
        {:error, :invalid_token_response}
    end
  end

  defp build_exchange_token({{_result, %Response{} = response}, _client}),
    do: {:error, error_response(response)}

  defp build_exchange_token({{:error, _reason} = error, _client}), do: error

  defp build_refresh_token({{:ok, %Response{} = response}, client}) do
    case token_body(response.body) do
      {:ok, body} -> {:ok, token_client(client, body)}
      _other -> {:error, response}
    end
  end

  defp build_refresh_token({{:error, %Response{} = response}, _client}),
    do: {:error, error_response(response)}

  defp build_refresh_token({{:error, _reason} = error, _client}), do: error

  defp token_client(client, body),
    do: %{client | headers: [], params: %{}, token: AccessToken.new(body)}

  # OAuth2 decodes form-encoded bodies to maps and, through JSONSerializer,
  # returns JSON bodies undecoded. Only a JSON or form object is a token body.
  defp token_body(""), do: :empty
  defp token_body(body) when is_map(body), do: {:ok, body}

  defp token_body(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} when is_map(decoded) -> {:ok, decoded}
      _other -> :error
    end
  end

  defp token_body(_body), do: :error

  defp error_response(%Response{body: body} = response) do
    case token_body(body) do
      {:ok, decoded} -> %{response | body: decoded}
      _other -> response
    end
  end

  defp new_client(oauth_config, strategy, redirect_uri) do
    Client.new(
      strategy: strategy,
      client_id: oauth_config.client_id,
      client_secret: oauth_config.client_secret,
      token_url: oauth_config.token_url,
      redirect_uri: redirect_uri,
      serializers: %{"application/json" => JSONSerializer}
    )
  end

  defp exchange_strategy(%{"authorization_method" => "header"}), do: HeaderAuthCode
  defp exchange_strategy(_metadata), do: AuthCode

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

  defp put_body_credentials(client, oauth_config, metadata) do
    if metadata["token_request_auth_method"] == "basic" or
         metadata["authorization_method"] == "body" do
      Client.merge_params(client, %{
        "client_id" => oauth_config.client_id,
        "client_secret" => oauth_config.client_secret
      })
    else
      client
    end
  end

  # The strategies always add the Basic header. Body authentication removes
  # it unless token_request_auth_method "basic" asks for both.
  defp drop_basic_auth(client, %{"token_request_auth_method" => "basic"}), do: client

  defp drop_basic_auth(client, %{"authorization_method" => "body"}),
    do: %{client | headers: List.keydelete(client.headers, "authorization", 0)}

  defp drop_basic_auth(client, _metadata), do: client

  defp headers(%{"body_format" => "json"}), do: [{"content-type", "application/json"}]
  defp headers(_metadata), do: []
end

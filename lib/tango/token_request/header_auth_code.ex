defmodule Tango.TokenRequest.HeaderAuthCode do
  @moduledoc false
  # Authorization-code strategy that sends client credentials only in the
  # Basic header (Nango `authorization_method: header`). The stock
  # `OAuth2.Strategy.AuthCode` also puts `client_id` in the body.

  use OAuth2.Strategy

  alias OAuth2.Strategy.AuthCode

  @impl true
  def authorize_url(client, params), do: AuthCode.authorize_url(client, params)

  @impl true
  def get_token(client, params, headers) do
    client = AuthCode.get_token(client, params, headers)
    %{client | params: Map.drop(client.params, ["client_id", "client_secret"])}
  end
end

defmodule Tango.TokenRequestOptionsTest do
  @moduledoc """
  Request-shape tests for the Nango catalog options Tango honors:
  `scope_separator` and `disable_pkce` on the authorization URL, and
  `token_request_auth_method`, `authorization_method`, `body_format`,
  `token_params`, and `refresh_params` on the code exchange and refresh.
  """

  use Tango.DatabaseCase, async: false

  alias Tango.Factory
  alias Test.Support.OAuthFlowHelper

  @redirect_uri "https://myapp.com/callback"

  setup do
    {:ok, bypass: Bypass.open()}
  end

  defp create_provider(bypass, metadata) do
    Factory.create_provider(%{
      client_secret: "the_secret",
      config: %{
        "client_id" => "the_client",
        "auth_url" => "http://localhost:#{bypass.port}/authorize",
        "token_url" => "http://localhost:#{bypass.port}/token",
        "auth_mode" => "OAUTH2"
      },
      metadata: metadata
    })
  end

  # Captures the token request and answers with a fresh token.
  defp expect_token_request(bypass) do
    parent = self()

    Bypass.expect_once(bypass, "POST", "/token", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)

      send(parent, {:token_request, conn.req_headers, body})

      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.resp(
        200,
        Jason.encode!(%{
          "access_token" => "fresh_access_token",
          "refresh_token" => "fresh_refresh_token",
          "token_type" => "Bearer",
          "expires_in" => 3600
        })
      )
    end)
  end

  defp receive_token_request do
    assert_received {:token_request, headers, body}
    headers = Map.new(headers)

    params =
      case headers["content-type"] do
        "application/json" <> _ -> Jason.decode!(body)
        _ -> URI.decode_query(body)
      end

    {headers, params}
  end

  defp basic_auth_header,
    do: "Basic " <> Base.encode64("the_client:the_secret")

  defp auth_url_params(provider, opts \\ []) do
    tenant = Factory.tenant_id("auth_url")
    opts = Keyword.merge([redirect_uri: @redirect_uri], opts)

    {:ok, _session, url} =
      OAuthFlowHelper.create_session_with_auth_url(provider.slug, tenant, opts)

    url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
  end

  defp exchange(provider) do
    tenant = Factory.tenant_id("exchange")

    OAuthFlowHelper.complete_oauth_flow(provider.slug, tenant, "the_code",
      redirect_uri: @redirect_uri
    )
  end

  defp refresh(provider) do
    connection = Factory.create_connection(provider, Factory.tenant_id("refresh"))
    Tango.Connection.refresh_connection(connection)
  end

  describe "authorization URL" do
    test "joins scopes with a space and sends PKCE by default", %{bypass: bypass} do
      params = auth_url_params(create_provider(bypass, %{}), scopes: ["a", "b"])

      assert params["scope"] == "a b"
      assert params["code_challenge_method"] == "S256"
      assert is_binary(params["code_challenge"])
    end

    test "joins scopes with the catalog scope_separator", %{bypass: bypass} do
      provider = create_provider(bypass, %{"scope_separator" => ","})

      assert auth_url_params(provider, scopes: ["chat:write", "channels:read"])["scope"] ==
               "chat:write,channels:read"
    end

    test "omits the PKCE challenge when disable_pkce is set", %{bypass: bypass} do
      params = auth_url_params(create_provider(bypass, %{"disable_pkce" => true}))

      refute Map.has_key?(params, "code_challenge")
      refute Map.has_key?(params, "code_challenge_method")
    end
  end

  describe "code exchange" do
    test "keeps the default request: Basic header, form body, client_id and code_verifier",
         %{bypass: bypass} do
      expect_token_request(bypass)
      assert {:ok, _connection} = exchange(create_provider(bypass, %{}))

      {headers, params} = receive_token_request()
      assert headers["authorization"] == basic_auth_header()
      assert headers["content-type"] =~ "application/x-www-form-urlencoded"
      assert params["grant_type"] == "authorization_code"
      assert params["code"] == "the_code"
      assert params["client_id"] == "the_client"
      assert is_binary(params["code_verifier"])
      refute Map.has_key?(params, "client_secret")
    end

    test "omits code_verifier when disable_pkce is set", %{bypass: bypass} do
      expect_token_request(bypass)
      assert {:ok, _connection} = exchange(create_provider(bypass, %{"disable_pkce" => true}))

      {_headers, params} = receive_token_request()
      refute Map.has_key?(params, "code_verifier")
    end

    test "token_request_auth_method basic sends credentials in the header and body",
         %{bypass: bypass} do
      expect_token_request(bypass)
      provider = create_provider(bypass, %{"token_request_auth_method" => "basic"})
      assert {:ok, _connection} = exchange(provider)

      {headers, params} = receive_token_request()
      assert headers["authorization"] == basic_auth_header()
      assert params["client_id"] == "the_client"
      assert params["client_secret"] == "the_secret"
    end

    test "authorization_method header sends credentials only in the header", %{bypass: bypass} do
      expect_token_request(bypass)
      provider = create_provider(bypass, %{"authorization_method" => "header"})
      assert {:ok, _connection} = exchange(provider)

      {headers, params} = receive_token_request()
      assert headers["authorization"] == basic_auth_header()
      refute Map.has_key?(params, "client_id")
      refute Map.has_key?(params, "client_secret")
    end

    test "body_format json sends a JSON body", %{bypass: bypass} do
      expect_token_request(bypass)
      assert {:ok, _connection} = exchange(create_provider(bypass, %{"body_format" => "json"}))

      {headers, params} = receive_token_request()
      assert headers["content-type"] =~ "application/json"
      assert params["grant_type"] == "authorization_code"
      assert params["code"] == "the_code"
    end

    test "merges token_params without letting them change the grant or code", %{bypass: bypass} do
      expect_token_request(bypass)

      provider =
        create_provider(bypass, %{
          "token_params" => %{
            "grant_type" => "client_credentials",
            "code" => "not_the_code",
            "audience" => "api"
          }
        })

      assert {:ok, _connection} = exchange(provider)

      {_headers, params} = receive_token_request()
      assert params["audience"] == "api"
      assert params["grant_type"] == "authorization_code"
      assert params["code"] == "the_code"
    end
  end

  describe "refresh" do
    test "keeps the default request: Basic header, form body, no client credentials in body",
         %{bypass: bypass} do
      expect_token_request(bypass)
      assert {:ok, _connection} = refresh(create_provider(bypass, %{}))

      {headers, params} = receive_token_request()
      assert headers["authorization"] == basic_auth_header()
      assert headers["content-type"] =~ "application/x-www-form-urlencoded"
      assert params["grant_type"] == "refresh_token"
      assert is_binary(params["refresh_token"])
      refute Map.has_key?(params, "client_secret")
    end

    test "token_request_auth_method basic sends credentials in the header and body",
         %{bypass: bypass} do
      expect_token_request(bypass)
      provider = create_provider(bypass, %{"token_request_auth_method" => "basic"})
      assert {:ok, _connection} = refresh(provider)

      {headers, params} = receive_token_request()
      assert headers["authorization"] == basic_auth_header()
      assert params["client_id"] == "the_client"
      assert params["client_secret"] == "the_secret"
    end

    test "body_format json sends a JSON body", %{bypass: bypass} do
      expect_token_request(bypass)
      assert {:ok, _connection} = refresh(create_provider(bypass, %{"body_format" => "json"}))

      {headers, params} = receive_token_request()
      assert headers["content-type"] =~ "application/json"
      assert params["grant_type"] == "refresh_token"
    end

    test "sends refresh_params instead of token_params", %{bypass: bypass} do
      expect_token_request(bypass)

      provider =
        create_provider(bypass, %{
          "token_params" => %{"audience" => "api"},
          "refresh_params" => %{"grant_type" => "refresh_token", "scope" => "offline"}
        })

      assert {:ok, _connection} = refresh(provider)

      {_headers, params} = receive_token_request()
      assert params["scope"] == "offline"
      refute Map.has_key?(params, "audience")
      assert params["grant_type"] == "refresh_token"
    end

    test "falls back to token_params without their grant_type", %{bypass: bypass} do
      expect_token_request(bypass)

      provider =
        create_provider(bypass, %{
          "token_params" => %{"grant_type" => "authorization_code", "audience" => "api"}
        })

      assert {:ok, _connection} = refresh(provider)

      {_headers, params} = receive_token_request()
      assert params["audience"] == "api"
      assert params["grant_type"] == "refresh_token"
    end
  end
end

defmodule Tango.ExchangeResponseTest do
  @moduledoc """
  Code-exchange response handling for a provider without catalog options:
  `Tango.TokenRequest.exchange/4` result shapes, and the errors callers see
  through the immediate `exchange_code` flow and `stage_authorization/4`.
  Each case allows exactly one token request, so a retry fails the test.
  """

  use Tango.DatabaseCase, async: false

  import ExUnit.CaptureLog

  alias Tango.Factory
  alias Tango.Schemas.{Authorization, Connection}
  alias Test.Support.OAuthFlowHelper

  @redirect_uri "https://api.example.test/callback"
  @sentinel "LEAKED_PROVIDER_BODY"

  @html "<!DOCTYPE html><html><body>#{@sentinel}</body></html>"

  # {label, status, content type, body, extra response headers}
  @responses %{
    html: {"200 HTML", 200, "text/html", @html, []},
    json_html: {"200 JSON content type with HTML", 200, "application/json", @html, []},
    scalar: {"200 JSON scalar", 200, "application/json", Jason.encode!(@sentinel), []},
    empty: {"200 empty body", 200, "application/json", "", []},
    error_object:
      {"200 JSON error object", 200, "application/json",
       Jason.encode!(%{"error" => "access_denied", "error_description" => @sentinel}), []},
    redirect:
      {"302 redirect", 302, "text/html", @html, [{"location", "https://login.example.test/"}]},
    invalid_grant:
      {"400 invalid_grant", 400, "application/json",
       Jason.encode!(%{"error" => "invalid_grant", "error_description" => @sentinel}), []},
    server_html: {"500 JSON content type with HTML", 500, "application/json", @html, []}
  }

  # Expected result per response for each entry point.
  @expected [
    {:html, :invalid_token_response, :invalid_token_response,
     {:oauth_error, :invalid_token_response}},
    {:json_html, :invalid_token_response, :invalid_token_response,
     {:oauth_error, :invalid_token_response}},
    {:scalar, :invalid_token_response, :invalid_token_response,
     {:oauth_error, :invalid_token_response}},
    {:empty, :empty_access_token, :empty_access_token, {:oauth_error, :empty_access_token}},
    {:error_object, {:response, 200, :map}, {:oauth_error, :access_denied},
     {:oauth_error, :access_denied}},
    {:redirect, {:response, 302, :binary}, {:oauth_error, :provider_error},
     {:oauth_error, :provider_error}},
    {:invalid_grant, {:response, 400, :map}, {:oauth_error, :invalid_grant},
     {:oauth_error, :invalid_grant}},
    {:server_html, {:response, 500, :binary}, {:oauth_error, :provider_error},
     {:oauth_error, :provider_error}}
  ]

  setup do
    bypass = Bypass.open()
    previous_origins = Application.get_env(:tango, :allowed_completion_origins)
    Application.put_env(:tango, :allowed_completion_origins, ["https://app.example.test"])

    on_exit(fn ->
      if previous_origins do
        Application.put_env(:tango, :allowed_completion_origins, previous_origins)
      else
        Application.delete_env(:tango, :allowed_completion_origins)
      end
    end)

    provider =
      Factory.create_provider(%{
        client_secret: "the_secret",
        config: %{
          "client_id" => "the_client",
          "auth_url" => "http://localhost:#{bypass.port}/authorize",
          "token_url" => "http://localhost:#{bypass.port}/token"
        }
      })

    %{bypass: bypass, provider: provider}
  end

  for {key, token_request, exchange_code, staged} <- @expected do
    {label, _status, _content_type, _body, _headers} = Map.fetch!(@responses, key)
    @key key
    @token_request token_request
    @exchange_code exchange_code
    @staged staged

    test "#{label}: TokenRequest.exchange result", %{bypass: bypass} do
      expect_response(bypass, @key)

      result =
        Tango.TokenRequest.exchange(
          %{
            client_id: "the_client",
            client_secret: "the_secret",
            token_url: "http://localhost:#{bypass.port}/token"
          },
          %{},
          [code: "the_code", redirect_uri: @redirect_uri],
          @redirect_uri
        )

      assert_token_request_result(result, @token_request)
    end

    test "#{label}: exchange_code error", %{bypass: bypass, provider: provider} do
      expect_response(bypass, @key)
      tenant = Factory.tenant_id("exchange_response")

      log =
        capture_log(fn ->
          assert {:error, @exchange_code} =
                   OAuthFlowHelper.complete_oauth_flow(provider.slug, tenant, "the_code",
                     redirect_uri: @redirect_uri
                   )
        end)

      refute log =~ @sentinel
      assert Repo.aggregate(Connection, :count) == 0
    end

    test "#{label}: stage_authorization error", %{bypass: bypass, provider: provider} do
      tenant = Factory.tenant_id("stage_response")

      {:ok, session} =
        Tango.create_authorization_session(provider.slug, tenant,
          redirect_uri: @redirect_uri,
          completion_origin: "https://app.example.test",
          intent_reference: "intent-#{@key}"
        )

      {:ok, url} = Tango.Auth.authorization_url(session)

      state =
        url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("state")

      expect_response(bypass, @key)

      log =
        capture_log(fn ->
          assert {:error, @staged} =
                   Tango.stage_authorization(state, "the_code", tenant,
                     redirect_uri: @redirect_uri
                   )
        end)

      refute log =~ @sentinel
      assert Repo.aggregate(Authorization, :count) == 0
    end
  end

  test "a 2xx JSON error object with a null error is a token", %{bypass: bypass} do
    Bypass.expect_once(bypass, "POST", "/token", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{"access_token" => "fresh-token", "error" => nil}))
    end)

    assert {:ok, %{token: %{access_token: "fresh-token"}}} =
             Tango.TokenRequest.exchange(
               %{
                 client_id: "the_client",
                 client_secret: "the_secret",
                 token_url: "http://localhost:#{bypass.port}/token"
               },
               %{},
               [code: "the_code"],
               @redirect_uri
             )
  end

  test "a 2xx form-encoded token response is accepted", %{bypass: bypass} do
    Bypass.expect_once(bypass, "POST", "/token", fn conn ->
      conn
      |> Plug.Conn.put_resp_header("content-type", "application/x-www-form-urlencoded")
      |> Plug.Conn.resp(200, "access_token=form-token&token_type=bearer")
    end)

    assert {:ok, %{token: %{access_token: "form-token"}}} =
             Tango.TokenRequest.exchange(
               %{
                 client_id: "the_client",
                 client_secret: "the_secret",
                 token_url: "http://localhost:#{bypass.port}/token"
               },
               nil,
               [code: "the_code"],
               @redirect_uri
             )
  end

  # Error responses keep JSON objects decoded and any other body raw.
  defp assert_token_request_result(result, {:response, status, :map}),
    do: assert({:error, %OAuth2.Response{status_code: ^status, body: %{"error" => _}}} = result)

  defp assert_token_request_result(result, {:response, status, :binary}),
    do: assert({:error, %OAuth2.Response{status_code: ^status, body: @html}} = result)

  defp assert_token_request_result(result, reason), do: assert({:error, ^reason} = result)

  defp expect_response(bypass, key) do
    {_label, status, content_type, body, headers} = Map.fetch!(@responses, key)

    Bypass.expect_once(bypass, "POST", "/token", fn conn ->
      conn =
        Enum.reduce(headers, conn, fn {name, value}, conn ->
          Plug.Conn.put_resp_header(conn, name, value)
        end)

      conn
      |> Plug.Conn.put_resp_header("content-type", content_type)
      |> Plug.Conn.resp(status, body)
    end)
  end
end

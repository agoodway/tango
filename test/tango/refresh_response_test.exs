defmodule Tango.RefreshResponseTest do
  use ExUnit.Case, async: true

  alias Tango.RefreshError

  @sentinel "<html>LEAKED_PROVIDER_BODY"

  setup do
    {:ok, bypass: Bypass.open()}
  end

  for {label, content_type, body} <- [
        {"HTML", "text/html", "<html>maintenance</html>"},
        {"missing content type", nil, "<html>maintenance</html>"},
        {"empty JSON", "application/json", ""},
        {"blank JSON", "application/json", " "}
      ] do
    test "rejects successful #{label} bodies before token construction", %{bypass: bypass} do
      expect_token(bypass, 200, unquote(content_type), unquote(body))
      assert {:error, %OAuth2.Response{status_code: 200}} = refresh(bypass)
    end
  end

  test "keeps form-encoded token responses", %{bypass: bypass} do
    for content_type <- ["application/x-www-form-urlencoded", "text/plain"] do
      expect_token(bypass, 200, content_type, "access_token=form_token&expires_in=3600")
      assert {:ok, %{token: %{access_token: "form_token"}}} = refresh(bypass)
    end
  end

  test "preserves JSON refresh requests, credentials and parameter precedence", %{bypass: bypass} do
    Bypass.expect_once(bypass, "POST", "/oauth/token", fn conn ->
      assert Plug.Conn.get_req_header(conn, "authorization") ==
               ["Basic " <> Base.encode64("client-id:client-secret")]

      assert Plug.Conn.get_req_header(conn, "content-type") == ["application/json"]
      {:ok, body, conn} = Plug.Conn.read_body(conn)

      assert Jason.decode!(body) == %{
               "client_id" => "client-id",
               "client_secret" => "client-secret",
               "grant_type" => "refresh_token",
               "refresh_token" => "refresh-token",
               "scope" => "records.read"
             }

      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{"access_token" => "fresh-token"}))
    end)

    assert {:ok, %{token: %{access_token: "fresh-token"}}} =
             refresh(bypass, %{
               "body_format" => "json",
               "token_request_auth_method" => "basic",
               "token_params" => %{"audience" => "unused"},
               "refresh_params" => %{
                 "scope" => "records.read",
                 "grant_type" => "client_credentials",
                 "refresh_token" => "ignored"
               }
             })
  end

  test "malformed JSON error responses survive OAuth2 decoding", %{bypass: bypass} do
    html = "#{@sentinel}</html>"

    expect_token(bypass, 502, "application/json", html)

    assert {:error, %OAuth2.Response{status_code: 502, body: ^html}} =
             refresh(bypass)

    assert RefreshError.from_response(502, [], html) == {:http_error, 502}
    assert RefreshError.classify({:http_error, 502}) == :transient
    refute String.contains?(RefreshError.to_storage({:http_error, 502}), @sentinel)

    expect_token(bypass, 502, "application/json", "{not-json")

    assert {:error, %OAuth2.Response{status_code: 502, body: "{not-json"}} =
             refresh(bypass)

    assert RefreshError.from_response(502, [], "{not-json") == {:http_error, 502}

    expect_token(bypass, 429, "application/json", Jason.encode!(%{"error" => "invalid_grant"}), [
      {"Retry-After", "120"}
    ])

    assert {:error, %OAuth2.Response{status_code: 429, headers: headers, body: body}} =
             refresh(bypass)

    assert {"retry-after", "120"} in headers
    assert RefreshError.from_response(429, headers, body) == {:rate_limited, 120}
    assert RefreshError.backoff_seconds({:rate_limited, 120}) == 120

    expect_token(
      bypass,
      200,
      "application/json",
      Jason.encode!(%{
        "access_token" => "fresh_access_token",
        "refresh_token" => "fresh_refresh_token",
        "token_type" => "Bearer",
        "expires_in" => 3600
      })
    )

    assert {:ok, %{token: token}} = refresh(bypass)
    assert token.access_token == "fresh_access_token"
    assert token.refresh_token == "fresh_refresh_token"

    expect_token(bypass, 200, "application/json", "#{@sentinel}</html>")

    assert {:error, %OAuth2.Response{status_code: 200, body: body}} = refresh(bypass)
    assert body =~ @sentinel
    assert RefreshError.from_response(200, [], body) == {:http_error, 200}
    refute String.contains?(RefreshError.to_storage({:http_error, 200}), @sentinel)

    encoded_error = Jason.encode!(%{"error" => "invalid_grant"})

    expect_token(bypass, 400, "application/json", Jason.encode!(encoded_error))

    assert {:error, %OAuth2.Response{status_code: 400, body: scalar_body}} = refresh(bypass)
    assert RefreshError.from_response(400, [], scalar_body) == {:http_error, 400}
  end

  defp expect_token(bypass, status, content_type, body, headers \\ []) do
    Bypass.expect_once(bypass, "POST", "/oauth/token", fn conn ->
      conn =
        Enum.reduce(headers, conn, fn {name, value}, conn ->
          Plug.Conn.put_resp_header(conn, name, value)
        end)

      conn =
        if content_type,
          do: Plug.Conn.put_resp_header(conn, "content-type", content_type),
          else: conn

      Plug.Conn.resp(conn, status, body)
    end)
  end

  defp refresh(bypass, metadata \\ %{}) do
    Tango.TokenRequest.refresh(
      %{
        client_id: "client-id",
        client_secret: "client-secret",
        token_url: "http://localhost:#{bypass.port}/oauth/token"
      },
      metadata,
      "refresh-token"
    )
  end
end

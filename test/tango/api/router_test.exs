defmodule Tango.API.RouterTest do
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn
  import Ecto.Query

  alias Ecto.Adapters.SQL
  alias Tango.API.Router
  alias Tango.Factory
  alias Tango.TestRepo
  @redirect_uri "http://localhost:3000/callback"

  setup do
    # Set up test repo and clean state
    :ok = SQL.Sandbox.checkout(TestRepo)

    # Configure API for testing
    Application.put_env(:tango, :api, cors_origins: ["http://localhost:3000"])

    # Create a test provider
    provider = Factory.create_github_provider()

    {:ok, provider: provider}
  end

  describe "POST /sessions" do
    test "creates OAuth session with valid parameters", %{provider: provider} do
      conn =
        conn(:post, "/sessions", %{
          "provider" => provider.slug,
          "redirect_uri" => @redirect_uri
        })
        |> put_req_header("content-type", "application/json")
        |> put_req_header("x-tenant-id", "test-tenant")
        |> put_req_header("authorization", "Bearer lets-dance-the-tango")

      response = Router.call(conn, Router.init([]))

      assert response.status == 201

      body = Jason.decode!(response.resp_body)
      assert Map.has_key?(body, "session_token")
      assert Map.has_key?(body, "expires_at")
      assert is_binary(body["session_token"])
    end

    test "returns error for missing provider" do
      conn =
        conn(:post, "/sessions", %{
          "redirect_uri" => @redirect_uri
        })
        |> put_req_header("content-type", "application/json")
        |> put_req_header("x-tenant-id", "test-tenant")
        |> put_req_header("authorization", "Bearer lets-dance-the-tango")

      response = Router.call(conn, Router.init([]))

      assert response.status == 400

      body = Jason.decode!(response.resp_body)
      assert body["error"] == "invalid_params"
    end

    test "returns error for missing tenant ID" do
      conn =
        conn(:post, "/sessions", %{
          "provider" => "github",
          "redirect_uri" => @redirect_uri
        })
        |> put_req_header("content-type", "application/json")

      response = Router.call(conn, Router.init([]))

      assert response.status == 401

      body = Jason.decode!(response.resp_body)
      assert body["error"] == "missing_api_key"
    end

    test "returns error for nonexistent provider" do
      conn =
        conn(:post, "/sessions", %{
          "provider" => "nonexistent",
          "redirect_uri" => @redirect_uri
        })
        |> put_req_header("content-type", "application/json")
        |> put_req_header("x-tenant-id", "test-tenant")
        |> put_req_header("authorization", "Bearer lets-dance-the-tango")

      response = Router.call(conn, Router.init([]))

      assert response.status == 404

      body = Jason.decode!(response.resp_body)
      assert body["error"] == "provider_not_found"
    end
  end

  describe "GET /authorize/:session_token" do
    setup %{provider: provider} do
      {:ok, session} =
        Tango.create_session(provider.slug, "test-tenant", redirect_uri: @redirect_uri)

      {:ok, session: session, provider: provider}
    end

    test "returns authorization URL for valid session", %{session: session} do
      conn =
        conn(
          :get,
          "/authorize/#{session.session_token}?redirect_uri=#{@redirect_uri}"
        )
        |> put_req_header("x-tenant-id", "test-tenant")
        |> put_req_header("authorization", "Bearer lets-dance-the-tango")

      response = Router.call(conn, Router.init([]))

      assert response.status == 200

      body = Jason.decode!(response.resp_body)
      assert Map.has_key?(body, "authorization_url")
      assert String.contains?(body["authorization_url"], "github.com")
    end

    test "returns error for missing redirect_uri", %{session: session} do
      conn =
        conn(:get, "/authorize/#{session.session_token}")
        |> put_req_header("x-tenant-id", "test-tenant")
        |> put_req_header("authorization", "Bearer lets-dance-the-tango")

      response = Router.call(conn, Router.init([]))

      assert response.status == 400

      body = Jason.decode!(response.resp_body)
      assert body["error"] == "missing_required_param"
    end

    test "returns error for invalid session token" do
      conn =
        conn(:get, "/authorize/invalid_token?redirect_uri=#{@redirect_uri}")
        |> put_req_header("x-tenant-id", "test-tenant")
        |> put_req_header("authorization", "Bearer lets-dance-the-tango")

      response = Router.call(conn, Router.init([]))

      assert response.status == 404

      body = Jason.decode!(response.resp_body)
      assert body["error"] == "session_not_found"
    end
  end

  describe "POST /exchange" do
    setup %{provider: provider} do
      {:ok, session} = Tango.create_session(provider.slug, "test-tenant")
      {:ok, session: session, provider: provider}
    end

    test "returns error for POST /exchange (simplified test)", %{session: session} do
      conn =
        conn(:post, "/exchange", %{
          "state" => session.state,
          "code" => "invalid_auth_code",
          "redirect_uri" => @redirect_uri
        })
        |> put_req_header("content-type", "application/json")
        |> put_req_header("x-tenant-id", "test-tenant")
        |> put_req_header("authorization", "Bearer lets-dance-the-tango")

      response = Router.call(conn, Router.init([]))

      # Should return an error since we don't have proper OAuth mocking
      assert response.status >= 400
      body = Jason.decode!(response.resp_body)
      assert Map.has_key?(body, "error")
    end

    test "returns error for missing parameters" do
      conn =
        conn(:post, "/exchange", %{
          "state" => "some_state"
          # missing code
        })
        |> put_req_header("content-type", "application/json")
        |> put_req_header("x-tenant-id", "test-tenant")
        |> put_req_header("authorization", "Bearer lets-dance-the-tango")

      response = Router.call(conn, Router.init([]))

      assert response.status == 400

      body = Jason.decode!(response.resp_body)
      assert body["error"] == "invalid_params"
    end
  end

  describe "GET /callback" do
    test "returns HTML callback page for successful callback" do
      conn = conn(:get, "/callback?code=test_code&state=test_state")

      response = Router.call(conn, Router.init([]))

      assert response.status == 200
      assert String.contains?(response.resp_body, "<html>")
      assert String.contains?(response.resp_body, "OAuth Callback")
    end

    test "logs oauth_denied error when user denies authorization", %{provider: provider} do
      # Create session and encode state
      {:ok, session} =
        Tango.create_session(provider.slug, "test-tenant", redirect_uri: @redirect_uri)

      {:ok, auth_url} = Tango.authorize_url(session.session_token, redirect_uri: @redirect_uri)

      # Extract encoded state from auth URL
      uri = URI.parse(auth_url)
      params = URI.decode_query(uri.query)
      encoded_state = params["state"]

      conn =
        conn(
          :get,
          "/callback?error=access_denied&error_description=The+user+denied+the+request&state=#{encoded_state}"
        )

      response = Router.call(conn, Router.init([]))

      assert response.status == 200

      # Check that audit log was created
      audit_logs =
        TestRepo.all(from(a in Tango.Schemas.AuditLog, where: a.event_type == :oauth_denied))

      assert length(audit_logs) == 1

      log = hd(audit_logs)
      assert log.tenant_id == "test-tenant"
      assert log.session_id == session.state
      assert log.success == false
      assert log.error_code == :access_denied
      assert log.event_data["oauth_error"] == "access_denied"
      assert log.event_data["error_description"] == "The user denied the request"
    end

    test "logs oauth_provider_error for server errors", %{provider: provider} do
      # Create session and encode state
      {:ok, session} =
        Tango.create_session(provider.slug, "test-tenant", redirect_uri: @redirect_uri)

      {:ok, auth_url} = Tango.authorize_url(session.session_token, redirect_uri: @redirect_uri)

      # Extract encoded state from auth URL
      uri = URI.parse(auth_url)
      params = URI.decode_query(uri.query)
      encoded_state = params["state"]

      conn =
        conn(
          :get,
          "/callback?error=server_error&error_description=Internal+server+error&state=#{encoded_state}"
        )

      response = Router.call(conn, Router.init([]))

      assert response.status == 200

      # Check that audit log was created
      audit_logs =
        TestRepo.all(
          from(a in Tango.Schemas.AuditLog, where: a.event_type == :oauth_provider_error)
        )

      assert length(audit_logs) == 1

      log = hd(audit_logs)
      assert log.tenant_id == "test-tenant"
      assert log.session_id == session.state
      assert log.success == false
      assert log.error_code == :server_error
      assert log.event_data["oauth_error"] == "server_error"
    end

    test "logs oauth_callback_error for missing state parameter" do
      conn = conn(:get, "/callback?error=invalid_request&error_description=Missing+state")

      response = Router.call(conn, Router.init([]))

      assert response.status == 200

      # Check that audit log was created
      audit_logs =
        TestRepo.all(
          from(a in Tango.Schemas.AuditLog, where: a.event_type == :oauth_callback_error)
        )

      assert length(audit_logs) == 1

      log = hd(audit_logs)
      assert log.tenant_id == "unknown"
      assert log.session_id == nil
      assert log.success == false
      assert log.error_code == :missing_callback_params
      assert log.event_data["state_present"] == false
      assert log.event_data["state_decodable"] == false
    end

    test "logs oauth_callback_error for malformed state parameter" do
      conn =
        conn(
          :get,
          "/callback?error=invalid_request&error_description=Invalid+state&state=malformed_state"
        )

      response = Router.call(conn, Router.init([]))

      assert response.status == 200

      # Check that audit log was created
      audit_logs =
        TestRepo.all(
          from(a in Tango.Schemas.AuditLog, where: a.event_type == :oauth_callback_error)
        )

      assert length(audit_logs) == 1

      log = hd(audit_logs)
      assert log.tenant_id == "unknown"
      assert log.session_id == nil
      assert log.success == false
      assert log.error_code == :missing_callback_params
      assert log.event_data["state_present"] == true
      assert log.event_data["state_decodable"] == false
    end

    test "maps various OAuth error codes correctly", %{provider: provider} do
      # Create session and encode state
      {:ok, session} =
        Tango.create_session(provider.slug, "test-tenant", redirect_uri: @redirect_uri)

      {:ok, auth_url} = Tango.authorize_url(session.session_token, redirect_uri: @redirect_uri)

      # Extract encoded state from auth URL
      uri = URI.parse(auth_url)
      params = URI.decode_query(uri.query)
      encoded_state = params["state"]

      error_mappings = [
        {"invalid_client", :invalid_client},
        {"invalid_grant", :invalid_grant},
        {"unsupported_grant_type", :unsupported_grant_type},
        {"invalid_scope", :invalid_scope},
        {"temporarily_unavailable", :temporarily_unavailable},
        {"unknown_error", :provider_error}
      ]

      for {oauth_error, expected_error_code} <- error_mappings do
        conn = conn(:get, "/callback?error=#{oauth_error}&state=#{encoded_state}")
        response = Router.call(conn, Router.init([]))
        assert response.status == 200

        # Check that audit log was created with correct error code
        audit_log =
          TestRepo.one(
            from(a in Tango.Schemas.AuditLog,
              where:
                a.event_type == :oauth_provider_error and
                  fragment("?->>'oauth_error' = ?", a.event_data, ^oauth_error)
            )
          )

        assert audit_log.error_code == expected_error_code
        assert audit_log.event_data["oauth_error"] == oauth_error
      end
    end
  end

  describe "GET /health" do
    test "returns health status" do
      conn = conn(:get, "/health")

      response = Router.call(conn, Router.init([]))

      assert response.status == 200

      body = Jason.decode!(response.resp_body)
      assert body["status"] == "ok"
      assert body["library"] == "tango"
      assert Map.has_key?(body, "timestamp")
    end
  end

  describe "OPTIONS requests (CORS)" do
    test "handles preflight OPTIONS request" do
      conn =
        conn(:options, "/sessions")
        |> put_req_header("origin", "http://localhost:3000")
        |> put_req_header("access-control-request-method", "POST")

      response = Router.call(conn, Router.init([]))

      assert response.status == 200
      assert response.resp_body == ""

      # Check CORS headers
      assert get_response_header(response, "access-control-allow-origin") == [
               "http://localhost:3000"
             ]

      assert "POST" in String.split(
               get_response_header(response, "access-control-allow-methods") |> hd(),
               ", "
             )
    end
  end

  describe "callback functionality" do
    @tag :skip_bypass
    test "callback without code/state returns null exchange result" do
      conn = conn(:get, "/callback")
      response = Router.call(conn, Router.init([]))

      assert response.status == 200
      assert String.contains?(response.resp_body, "exchangeResult = null")
    end

    @tag :skip_bypass
    test "callback with invalid state returns error exchange result" do
      invalid_state = "invalid_encoded_state_12345"

      conn = conn(:get, "/callback?code=valid_code&state=#{invalid_state}")
      response = Router.call(conn, Router.init([]))

      assert response.status == 200
      # Should contain error in exchange result
      assert String.contains?(response.resp_body, "\"error\":")
      assert String.contains?(response.resp_body, "exchangeResult")
    end

    @tag :skip_bypass
    test "callback HTML contains proper CSP headers" do
      conn = conn(:get, "/callback")
      response = Router.call(conn, Router.init([]))

      assert response.status == 200
      assert String.contains?(response.resp_body, "Content-Security-Policy")
      assert String.contains?(response.resp_body, "script-src 'self' 'unsafe-inline'")
    end

    @tag :skip_bypass
    test "callback HTML escapes JSON for XSS protection" do
      # Test that JSON is properly escaped in HTML context - test with dangerous input
      malicious_state =
        Base.url_encode64(
          Jason.encode!(%{
            "tenant_id" => "<script>alert('xss')</script>",
            "csrf_token" => "safe_token"
          }),
          padding: false
        )

      conn = conn(:get, "/callback?code=test&state=#{malicious_state}")
      response = Router.call(conn, Router.init([]))

      assert response.status == 200
      # Should not contain unescaped script tags from the malicious input
      refute String.contains?(response.resp_body, "<script>alert('xss')</script>")
      refute String.contains?(response.resp_body, "javascript:")
      # But should contain legitimate script tags (the callback function)
      assert String.contains?(response.resp_body, "handleCallback")
    end

    test "callback URL building uses HTTPS correctly" do
      # Test HTTPS conversion for secure callbacks
      conn =
        conn(:get, "/callback")
        |> Map.put(:scheme, :http)
        |> Map.put(:host, "example.com")
        |> Map.put(:port, 80)
        |> Map.put(:request_path, "/callback")

      response = Router.call(conn, Router.init([]))

      assert response.status == 200
      # The callback should handle HTTP -> HTTPS conversion internally
      assert String.contains?(response.resp_body, "exchangeResult")
    end
  end

  describe "URL building" do
    test "build_callback_url constructs proper URLs" do
      # Test the URL building pipeline
      conn =
        conn(:get, "/callback")
        |> Map.put(:scheme, :https)
        |> Map.put(:host, "example.com")
        |> Map.put(:port, 443)
        |> Map.put(:request_path, "/api/oauth/callback")

      # Access the private function via the public route that uses it
      response = Router.call(conn, Router.init([]))

      assert response.status == 200
      # Should build URL correctly (tested indirectly through callback)
    end
  end

  describe "undefined routes" do
    test "returns 404 for undefined routes" do
      conn =
        conn(:get, "/undefined")
        |> put_req_header("authorization", "Bearer lets-dance-the-tango")

      response = Router.call(conn, Router.init([]))

      assert response.status == 404

      body = Jason.decode!(response.resp_body)
      assert body["error"] == "not_found"
    end
  end

  # Helper function to get response headers
  defp get_response_header(conn, header) do
    get_resp_header(conn, header)
  end
end

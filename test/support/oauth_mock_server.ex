defmodule Tango.OAuthMockServer do
  @moduledoc """
  HTTP mock server for OAuth provider endpoints using Bypass.

  Provides local HTTP endpoints that mimic GitHub, Google, and other OAuth providers
  to eliminate external API calls during testing.
  """

  @doc """
  Sets up mock GitHub OAuth endpoints on the given Bypass server.

  Mocks:
  - GET /login/oauth/authorize (authorization endpoint)
  - POST /login/oauth/access_token (token endpoint)
  """
  def setup_github_oauth(bypass, opts \\ []) do
    success_response = Keyword.get(opts, :success_response, default_github_token_response())
    should_fail = Keyword.get(opts, :should_fail, false)

    # Note: Authorization endpoint is not mocked as authorize_url() only builds URLs
    # In real OAuth flow, user would be redirected to this URL in a browser

    # Mock token exchange endpoint
    Bypass.expect(bypass, "POST", "/login/oauth/access_token", fn conn ->
      if should_fail do
        # Return form-encoded error response
        error_response = "error=invalid_request&error_description=Invalid+authorization+code"

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Conn.resp(400, error_response)
      else
        # Always return form-encoded response for OAuth2 compatibility
        # (GitHub's OAuth2 API defaults to form-encoded responses)
        form_response = build_form_response(success_response)

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Conn.resp(200, form_response)
      end
    end)
  end

  @doc """
  Sets up mock Google OAuth endpoints on the given Bypass server.

  Mocks:
  - GET /o/oauth2/auth (authorization endpoint) 
  - POST /oauth2/token (token endpoint)
  """
  def setup_google_oauth(bypass, opts \\ []) do
    success_response = Keyword.get(opts, :success_response, default_google_token_response())
    should_fail = Keyword.get(opts, :should_fail, false)

    # Note: Authorization endpoint is not mocked as authorize_url() only builds URLs
    # In real OAuth flow, user would be redirected to this URL in a browser

    # Mock token exchange endpoint
    Bypass.expect(bypass, "POST", "/oauth2/token", fn conn ->
      if should_fail do
        # Return form-encoded error response
        error_response = "error=invalid_grant&error_description=Invalid+authorization+code"

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Conn.resp(400, error_response)
      else
        # Always return form-encoded response for OAuth2 compatibility
        # (Google's OAuth2 API supports both but form-encoded is the default)
        form_response = build_form_response(success_response)

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Conn.resp(200, form_response)
      end
    end)
  end

  @doc """
  Sets up mock generic OAuth endpoints for testing different scenarios.
  """
  def setup_generic_oauth(bypass, provider_name, opts \\ []) do
    success_response =
      Keyword.get(opts, :success_response, default_generic_token_response(provider_name))

    should_fail = Keyword.get(opts, :should_fail, false)
    auth_path = Keyword.get(opts, :auth_path, "/oauth/authorize")
    token_path = Keyword.get(opts, :token_path, "/oauth/token")

    # Mock authorization endpoint
    Bypass.expect(bypass, "GET", auth_path, fn conn ->
      Plug.Conn.resp(conn, 200, "#{provider_name} Authorization page")
    end)

    # Mock token exchange endpoint
    Bypass.expect(bypass, "POST", token_path, fn conn ->
      if should_fail do
        Plug.Conn.resp(
          conn,
          500,
          Jason.encode!(%{
            "error" => "server_error",
            "error_description" => "Internal server error"
          })
        )
      else
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.resp(200, Jason.encode!(success_response))
      end
    end)
  end

  @doc """
  Sets up mock endpoints that simulate network failures.
  """
  def setup_network_failure_endpoints(bypass, failure_type \\ :timeout) do
    case failure_type do
      :timeout ->
        # Simulate timeout by shutting down the server
        # This will cause connection refused, which simulates network failure
        Bypass.down(bypass)

      :connection_refused ->
        # Shut down the server to refuse connections
        Bypass.down(bypass)

      :invalid_response ->
        # Return malformed response
        Bypass.expect(bypass, fn conn ->
          conn
          |> Plug.Conn.put_resp_header("content-type", "text/html")
          |> Plug.Conn.resp(200, "<html>Not JSON</html>")
        end)

      :server_error ->
        # Return 500 error
        Bypass.expect(bypass, fn conn ->
          Plug.Conn.resp(
            conn,
            500,
            Jason.encode!(%{
              "error" => "internal_server_error",
              "error_description" => "Internal server error"
            })
          )
        end)
    end
  end

  @doc """
  Creates URLs pointing to the Bypass server for use in tests.
  """
  def github_urls(bypass) do
    base_url = "http://localhost:#{bypass.port}"

    %{
      "auth_url" => "#{base_url}/login/oauth/authorize",
      "token_url" => "#{base_url}/login/oauth/access_token"
    }
  end

  def google_urls(bypass) do
    base_url = "http://localhost:#{bypass.port}"

    %{
      "auth_url" => "#{base_url}/o/oauth2/auth",
      "token_url" => "#{base_url}/oauth2/token"
    }
  end

  def generic_urls(bypass, opts \\ []) do
    base_url = "http://localhost:#{bypass.port}"
    auth_path = Keyword.get(opts, :auth_path, "/oauth/authorize")
    token_path = Keyword.get(opts, :token_path, "/oauth/token")

    %{
      "auth_url" => "#{base_url}#{auth_path}",
      "token_url" => "#{base_url}#{token_path}"
    }
  end

  # Default response formats based on OAuth provider documentation

  defp default_github_token_response do
    %{
      "access_token" => "gho_mock_github_access_token_#{:rand.uniform(999_999)}",
      "scope" => "user:email,repo",
      "token_type" => "bearer"
      # Note: GitHub OAuth Apps do not provide refresh tokens
      # Only GitHub Apps with user access token expiration enabled provide refresh tokens
    }
  end

  defp default_google_token_response do
    %{
      "access_token" => "ya29.mock_google_access_token_#{:rand.uniform(999_999)}",
      "expires_in" => 3600,
      "token_type" => "Bearer",
      "scope" =>
        "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
      "refresh_token" => "1//mock_google_refresh_token_#{:rand.uniform(999_999)}"
    }
  end

  defp default_generic_token_response(provider_name) do
    %{
      "access_token" => "mock_#{provider_name}_access_token_#{:rand.uniform(999_999)}",
      "expires_in" => 3600,
      "token_type" => "Bearer",
      "scope" => "default:scope",
      "refresh_token" => "mock_#{provider_name}_refresh_token_#{:rand.uniform(999_999)}"
    }
  end

  # Helper function to convert token response map to form-encoded string
  defp build_form_response(response_map) do
    response_map
    # Remove nil values
    |> Enum.filter(fn {_key, value} -> value != nil end)
    |> Enum.map_join("&", fn {key, value} ->
      "#{key}=#{URI.encode_www_form(to_string(value))}"
    end)
  end
end

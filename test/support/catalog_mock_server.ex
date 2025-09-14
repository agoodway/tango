defmodule Tango.CatalogMockServer do
  @moduledoc """
  HTTP mock server for Nango provider catalog using Bypass.

  Provides local HTTP endpoints that serve a small, realistic YAML dataset
  for testing without hitting the real Nango repository.
  """

  @doc """
  Sets up mock Nango provider catalog endpoint on the given Bypass server.

  Returns a small, realistic set of providers that match the real Nango structure.
  """
  def setup_catalog_endpoint(bypass, opts \\ []) do
    should_fail = Keyword.get(opts, :should_fail, false)

    Bypass.expect(bypass, "GET", "/packages/providers/providers.yaml", fn conn ->
      if should_fail do
        Plug.Conn.resp(conn, 500, "Internal server error")
      else
        yaml_content = mock_providers_yaml()

        conn
        |> Plug.Conn.put_resp_header("content-type", "text/plain; charset=utf-8")
        |> Plug.Conn.resp(200, yaml_content)
      end
    end)
  end

  @doc """
  Returns the base URL for the mock catalog server.
  """
  def catalog_url(bypass) do
    "http://localhost:#{bypass.port}/packages/providers/providers.yaml"
  end

  # Private functions

  defp mock_providers_yaml do
    """
    # Mock Nango providers catalog for testing
    github:
        display_name: GitHub
        categories:
            - dev-tools
        auth_mode: OAUTH2
        authorization_url: https://github.com/login/oauth/authorize
        token_url: https://github.com/login/oauth/access_token
        default_scopes:
            - repo
            - user
        docs: https://docs.nango.dev/integrations/all/github

    google:
        display_name: Google
        categories:
            - productivity
        auth_mode: OAUTH2
        authorization_url: https://accounts.google.com/o/oauth2/auth
        token_url: https://oauth2.googleapis.com/token
        default_scopes:
            - https://www.googleapis.com/auth/userinfo.email
            - https://www.googleapis.com/auth/userinfo.profile
        docs: https://docs.nango.dev/integrations/all/google

    stripe:
        display_name: Stripe
        categories:
            - payments
        auth_mode: API_KEY
        proxy:
            base_url: https://api.stripe.com
            headers:
                authorization: Bearer ${apiKey}
        docs: https://docs.nango.dev/integrations/all/stripe

    slack:
        display_name: Slack
        categories:
            - communication
        auth_mode: OAUTH2
        authorization_url: https://slack.com/oauth/v2/authorize
        token_url: https://slack.com/api/oauth.v2.access
        default_scopes:
            - chat:write
            - channels:read
        docs: https://docs.nango.dev/integrations/all/slack

    notion:
        display_name: Notion
        categories:
            - notes
        auth_mode: OAUTH2
        authorization_url: https://api.notion.com/v1/oauth/authorize
        token_url: https://api.notion.com/v1/oauth/token
        default_scopes:
            - read_content
        docs: https://docs.nango.dev/integrations/all/notion

    # Test provider with BASIC auth (represents real-world variety)
    basic-auth-provider:
        display_name: Basic Auth Provider
        categories:
            - other
        auth_mode: BASIC
        proxy:
            base_url: https://api.example.com
            headers:
                authorization: Basic ${base64(username:password)}
        docs: https://docs.nango.dev/integrations/all/basic-auth-provider

    # Test provider with missing optional fields
    minimal-provider:
        display_name: Minimal Provider
        categories:
            - other
        auth_mode: API_KEY
        docs: https://docs.nango.dev/integrations/all/minimal-provider
    """
  end
end

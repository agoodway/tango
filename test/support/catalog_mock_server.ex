defmodule Tango.CatalogMockServer do
  @moduledoc """
  HTTP mock server for Nango provider catalog using Bypass.

  Provides local HTTP endpoints that serve a small, realistic YAML dataset
  for testing without hitting the real Nango repository.
  """

  @doc """
  Sets up mock Nango provider catalog endpoint on the given Bypass server.

  Returns a small, realistic set of providers that match the real Nango structure,
  including the shapes that need special handling: an `alias` entry, an alias
  that switches to a non-OAuth2 auth mode, `${connectionConfig.*}` placeholders
  with and without a `||` fallback, `scope_separator`, `disable_pkce`,
  `token_request_auth_method: basic`, and `authorization_method`/`body_format`.
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
        authorization_params:
            response_type: code
            access_type: offline
            prompt: consent
        default_scopes:
            - https://www.googleapis.com/auth/userinfo.email
            - https://www.googleapis.com/auth/userinfo.profile
        docs: https://docs.nango.dev/integrations/all/google

    # Alias entry: inherits the parent's OAuth2 settings (shallow merge)
    google-calendar:
        display_name: Google Calendar
        alias: google
        categories:
            - calendar
        proxy:
            base_url: https://www.googleapis.com/calendar
        docs: https://docs.nango.dev/integrations/all/google-calendar

    # Alias entry that overrides the parent's auth mode (not OAuth2)
    github-app:
        display_name: GitHub (App)
        alias: github
        auth_mode: APP
        authorization_url: ${connectionConfig.appPublicLink}/installations/new
        token_url: https://api.github.com/app/installations/${connectionConfig.installation_id}/access_tokens
        categories:
            - dev-tools
        docs: https://docs.nango.dev/integrations/all/github-app

    # Connection-config placeholders with a "||" fallback
    salesforce:
        display_name: Salesforce
        categories:
            - marketing
        auth_mode: OAUTH2
        authorization_url: https://${connectionConfig.hostname}/services/oauth2/authorize || https://login.salesforce.com/services/oauth2/authorize
        token_url: https://${connectionConfig.hostname}/services/oauth2/token || https://login.salesforce.com/services/oauth2/token
        authorization_params:
            prompt: consent
        default_scopes:
            - offline_access
        docs: https://docs.nango.dev/integrations/all/salesforce

    # Connection-config placeholders with no fallback
    zendesk:
        display_name: Zendesk
        categories:
            - support
        auth_mode: OAUTH2
        authorization_url: https://${connectionConfig.subdomain}.zendesk.com/oauth/authorizations/new
        token_url: https://${connectionConfig.subdomain}.zendesk.com/oauth/tokens
        docs: https://docs.nango.dev/integrations/all/zendesk

    # Basic client authentication on the token endpoint
    figma:
        display_name: Figma
        categories:
            - design
        auth_mode: OAUTH2
        authorization_url: https://www.figma.com/oauth
        token_url: https://api.figma.com/v1/oauth/token
        token_request_auth_method: basic
        scope_separator: ','
        disable_pkce: true
        docs: https://docs.nango.dev/integrations/all/figma

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
        scope_separator: ','
        token_url: https://slack.com/api/oauth.v2.access
        disable_pkce: true
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
        authorization_params:
            response_type: code
            owner: user
        authorization_method: header
        body_format: json
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

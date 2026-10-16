defmodule Tango.API do
  @moduledoc """
  Ready-to-use OAuth API for Phoenix applications.

  This module provides a complete OAuth API that can be easily mounted in
  Phoenix applications. It includes all necessary endpoints for OAuth flow
  management, connection handling, and provider listing.

  ## Setup

  Add to your Phoenix router:

      ```elixir
      defmodule MyAppWeb.Router do
        use MyAppWeb, :router

        scope "/api/oauth" do
          pipe_through :api
          forward "/", Tango.API.Router
        end
      end
      ```

  ## API Endpoints

  All endpoints are relative to where you mount the router:

  ### Session Management
  - `POST /sessions` - Create OAuth session
  - `GET /authorize/:session_token` - Get authorization URL

  ### Token Exchange
  - `POST /exchange` - Exchange authorization code for connection

  ### System
  - `GET /health` - Health check

  > **Note:** Connection and provider management should be handled by your Phoenix
  > application directly using Tango's programmatic API. This HTTP API focuses
  > on the OAuth flow that external clients (web/mobile apps) need to complete.

  ## Configuration

      config :tango,
        encryption_key: "your-32-byte-encryption-key",
        api_key: "your-secret-api-key"

  ## Authentication

  All API endpoints require:

  1. **API Key** - Provide via `Authorization: Bearer your-api-key` or `X-API-Key: your-api-key` header
  2. **Tenant ID** - Provide via `X-Tenant-ID: user-123` header or `conn.assigns.current_tenant_id`

  ## Calling the API

  > **Warning:** the API key is a server secret. Never put it in browser
  > JavaScript; call Tango's API only from your backend.

  The browser talks to your own backend, which authenticates the user, derives
  the tenant from its session, and calls Tango's API server-side with the key:

      ```elixir
      # Your backend (e.g. a Phoenix controller). The tenant comes from your own
      # authenticated session, never from the browser.
      defmodule MyAppWeb.IntegrationController do
        use MyAppWeb, :controller

        @tango_api "https://yourapp.com/api/oauth"
        @redirect_uri "https://yourapp.com/integrations/callback"

        def connect(conn, %{"provider" => provider}) do
          tenant_id = to_string(conn.assigns.current_user.id)

          with {:ok, %{status: 201, body: session}} <-
                 Req.post("\#{@tango_api}/sessions",
                   headers: tango_headers(tenant_id),
                   json: %{provider: provider, redirect_uri: @redirect_uri}
                 ),
               {:ok, %{status: 200, body: %{"authorization_url" => url}}} <-
                 Req.get("\#{@tango_api}/authorize/\#{session["session_token"]}",
                   headers: tango_headers(tenant_id),
                   params: [redirect_uri: @redirect_uri]
                 ) do
            redirect(conn, external: url)
          else
            _ -> send_resp(conn, 502, "Could not start OAuth")
          end
        end

        def callback(conn, %{"state" => state, "code" => code}) do
          tenant_id = to_string(conn.assigns.current_user.id)

          case Req.post("\#{@tango_api}/exchange",
                 headers: tango_headers(tenant_id),
                 json: %{state: state, code: code, redirect_uri: @redirect_uri}
               ) do
            {:ok, %{status: 200}} -> redirect(conn, to: "/integrations")
            _ -> send_resp(conn, 400, "OAuth exchange failed")
          end
        end

        defp tango_headers(tenant_id) do
          [
            {"authorization", "Bearer \#{System.fetch_env!("TANGO_API_KEY")}"},
            {"x-tenant-id", tenant_id}
          ]
        end
      end
      ```

  The browser only navigates to your backend's routes and never sees the key:

      ```javascript
      // Start OAuth: your backend creates the session and redirects to the provider.
      function startOAuth(provider) {
        window.location.href = `/integrations/${encodeURIComponent(provider)}/connect`;
      }
      ```

  If your backend is the same Phoenix app that mounts Tango, skip HTTP and call
  `Tango.create_session/3`, `Tango.authorize_url/2`, and `Tango.exchange_code/4`
  directly. For browser popups, see the authorization completion guide
  (`docs/AUTHORIZATION.md`).

  ### cURL Examples (server-side)

      ```bash
      # Create OAuth session
      curl -X POST http://localhost:4000/api/oauth/sessions \\
        -H "Authorization: Bearer $TANGO_API_KEY" \\
        -H "Content-Type: application/json" \\
        -H "X-Tenant-ID: user-123" \\
        -d '{"provider": "github", "redirect_uri": "http://localhost:3000/callback"}'

      # Get authorization URL
      curl "http://localhost:4000/api/oauth/authorize/SESSION_TOKEN?redirect_uri=http://localhost:3000/callback" \\
        -H "Authorization: Bearer $TANGO_API_KEY" \\
        -H "X-Tenant-ID: user-123"

      # Exchange code for connection
      curl -X POST http://localhost:4000/api/oauth/exchange \\
        -H "Authorization: Bearer $TANGO_API_KEY" \\
        -H "Content-Type: application/json" \\
        -H "X-Tenant-ID: user-123" \\
        -d '{"state": "STATE_FROM_CALLBACK", "code": "AUTH_CODE", "redirect_uri": "http://localhost:3000/callback"}'
      ```

  ## Error Handling

  All endpoints return consistent JSON error responses:

      {
        "error": "error_code",
        "message": "Human readable error message",
        "details": {} // Optional additional error details
      }

  Common error codes:
  - `provider_not_found` - OAuth provider not configured
  - `session_not_found` - OAuth session not found or expired
  - `session_expired` - OAuth session has expired
  - `invalid_state` - Invalid or mismatched state parameter
  - `invalid_session` - Session cannot be exchanged here; sessions created with
    `Tango.create_authorization_session/3` complete only through the popup callback
    and trusted server code
  - `oauth_error` - The provider rejected the code; `category` holds a stable category
    and the provider's response is never returned
  - `tenant_id_required` - Tenant ID could not be extracted
  - `invalid_params` - Missing or invalid request parameters
  - `validation_failed` - Request validation failed

  ## Security Considerations

  - All OAuth sessions expire after 30 minutes
  - PKCE (Proof Key for Code Exchange) is used unless the provider's catalog
    entry sets `disable_pkce`
  - Multi-tenant isolation prevents cross-tenant data access
  - CORS is configurable for cross-origin request security
  - Comprehensive input validation prevents injection attacks

  ## Production Checklist

  1. **Configure CORS origins** to match your frontend domains
  2. **Implement robust tenant ID extraction** with proper authentication
  3. **Set up HTTPS** for all OAuth redirect URIs in production
  4. **Monitor API usage** and implement rate limiting if needed
  5. **Set up proper logging** for OAuth events and errors
  6. **Test OAuth flows** thoroughly in your staging environment

  """
end

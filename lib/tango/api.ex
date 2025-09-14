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

  ## Usage Examples

  ### JavaScript Usage

      ```javascript
      const API_BASE = '/api/oauth';
      const TENANT_ID = 'user-123';
      const API_KEY = 'your-secret-api-key';

      // Create OAuth session
      async function createOAuthSession(provider, redirectUri, scopes = []) {
        const response = await fetch(`${API_BASE}/sessions`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Tenant-ID': TENANT_ID,
            'Authorization': `Bearer ${API_KEY}`
          },
          body: JSON.stringify({
            provider,
            redirect_uri: redirectUri,
            scopes
          })
        });
        return response.json();
      }

      // Get authorization URL
      async function getAuthorizationUrl(sessionToken, redirectUri, scopes = []) {
        const params = new URLSearchParams({
          redirect_uri: redirectUri,
          scopes: scopes.join(' ')
        });

        const response = await fetch(`${API_BASE}/authorize/${sessionToken}?${params}`, {
          headers: { 
            'X-Tenant-ID': TENANT_ID,
            'Authorization': `Bearer ${API_KEY}`
          }
        });
        return response.json();
      }

      // Exchange authorization code for connection
      async function exchangeAuthCode(state, code, redirectUri) {
        const response = await fetch(`${API_BASE}/exchange`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Tenant-ID': TENANT_ID,
            'Authorization': `Bearer ${API_KEY}`
          },
          body: JSON.stringify({
            state,
            code,
            redirect_uri: redirectUri
          })
        });
        return response.json();
      }

      // Example OAuth flow
      async function initiateOAuth() {
        const session = await createOAuthSession('github', 'http://localhost:3000/callback');
        const authUrl = await getAuthorizationUrl(
          session.session_token,
          'http://localhost:3000/callback',
          ['user:email']
        );
        window.location.href = authUrl.authorization_url;
      }

      // Handle OAuth callback
      async function handleCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');

        if (code && state) {
          const connection = await exchangeAuthCode(state, code, 'http://localhost:3000/callback');
          console.log('OAuth connection established:', connection);
          // Your Phoenix app can now manage this connection using Tango's API
        }
      }
      ```

  ### cURL Examples

      ```bash
      # Create OAuth session
      curl -X POST http://localhost:4000/api/oauth/sessions \\
        -H "Content-Type: application/json" \\
        -H "X-Tenant-ID: user-123" \\
        -d '{"provider": "github", "redirect_uri": "http://localhost:3000/callback"}'

      # Get authorization URL
      curl "http://localhost:4000/api/oauth/authorize/SESSION_TOKEN?redirect_uri=http://localhost:3000/callback" \\
        -H "X-Tenant-ID: user-123"

      # Exchange code for connection
      curl -X POST http://localhost:4000/api/oauth/exchange \\
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
  - `tenant_id_required` - Tenant ID could not be extracted
  - `invalid_params` - Missing or invalid request parameters
  - `validation_failed` - Request validation failed

  ## Security Considerations

  - All OAuth sessions expire after 30 minutes
  - PKCE (Proof Key for Code Exchange) is used for enhanced security
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

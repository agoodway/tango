# Ready-to-use OAuth API

Tango includes a complete OAuth API router that can be mounted in Phoenix applications with a single line.

## Setup

1. Configure API key in your application:

```elixir
# config/config.exs  
config :tango,
  encryption_key: System.get_env("TANGO_ENCRYPTION_KEY"),
  api_key: System.get_env("TANGO_API_KEY")
```

2. Add the API router to your Phoenix router:

```elixir
# router.ex
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  scope "/api/oauth" do
    pipe_through :api
    forward "/", Tango.API.Router
  end
end
```

## Available Endpoints

The mounted API provides these endpoints:

- `POST /api/oauth/sessions` - Create OAuth session
- `GET /api/oauth/authorize/:session_token` - Get authorization URL  
- `POST /api/oauth/exchange` - Exchange authorization code for a connection (direct flow; returns status and scopes, never credentials)
- `GET /api/oauth/callback` - Popup callback; posts the completion handle to the session's completion origin
- `GET /api/oauth/health` - Health check

## Calling the API

This example uses the direct flow with `/sessions`, `/authorize`, and `/exchange`. For browser popups, use [authorization completion](AUTHORIZATION.md).

> **Warning:** `TANGO_API_KEY` is a server secret. Never put it in browser JavaScript; call Tango's API only from your backend.

The browser talks to your own backend, which authenticates the user, derives the tenant from its session, and calls Tango's API server-side with the key:

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
           Req.post("#{@tango_api}/sessions",
             headers: tango_headers(tenant_id),
             json: %{provider: provider, redirect_uri: @redirect_uri}
           ),
         {:ok, %{status: 200, body: %{"authorization_url" => url}}} <-
           Req.get("#{@tango_api}/authorize/#{session["session_token"]}",
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

    case Req.post("#{@tango_api}/exchange",
           headers: tango_headers(tenant_id),
           json: %{state: state, code: code, redirect_uri: @redirect_uri}
         ) do
      {:ok, %{status: 200}} -> redirect(conn, to: "/integrations")
      _ -> send_resp(conn, 400, "OAuth exchange failed")
    end
  end

  defp tango_headers(tenant_id) do
    [
      {"authorization", "Bearer #{System.fetch_env!("TANGO_API_KEY")}"},
      {"x-tenant-id", tenant_id}
    ]
  end
end
```

The browser only navigates to your backend's routes and never sees the API key:

```javascript
// Start OAuth: your backend creates the session and redirects to the provider.
function startOAuth(provider) {
  window.location.href = `/integrations/${encodeURIComponent(provider)}/connect`;
}
```

If your backend is the same Phoenix app that mounts Tango, skip HTTP entirely and call `Tango.create_session/3`, `Tango.authorize_url/2`, and `Tango.exchange_code/4` directly (see [USAGE.md](USAGE.md)).

## Connection Management

Use Tango's programmatic API in your Phoenix application to manage connections:

```elixir
# List connections for a user
connections = Tango.list_connections(user_id)

# Get connection for API calls
{:ok, connection} = Tango.get_connection_for_provider("github", user_id)
headers = [{"Authorization", "Bearer #{connection.access_token}"}]

# With auto-refresh, an expired token that cannot be refreshed returns
# {:error, {:refresh_failed, reason}}.
{:ok, connection} = Tango.get_connection_for_provider("github", user_id, auto_refresh: true)

# Revoke connection
{:ok, _revoked} = Tango.revoke_connection(connection, user_id)
```

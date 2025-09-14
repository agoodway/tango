# 💃 Tango - OAuth Integration Library

*Tango handles the OAuth dance for third-party integrations.*

**Tango** is an Elixir OAuth integration library for Phoenix applications that provides drop-in OAuth support for third-party integrations. Inspired by [Nango](https://github.com/NangoHQ/nango) (previously [Pizzly](https://dev.to/bearer/introducing-pizzly-an-open-sourced-free-fast-simple-api-integrations-manager-4jog)) and compatible with Nango's provider configuration format, Tango leverages the extensive Nango provider catalog while providing a library-first approach for Phoenix applications.

## Key Features

- **Complete OAuth2 flows**: Session creation, authorization URL generation, code exchange, token refresh, and revocation
- **Multi-tenant isolation**: Tenant-scoped queries for all connections with automatic session lifecycle management
- **Security-first design**: AES-GCM encryption for tokens, PKCE implementation, and secure random token generation
- **Comprehensive audit trail**: Structured logging for OAuth events, token operations, and system activities

## Core Modules

```
lib/tango/
├── auth.ex                    # Main OAuth flow orchestrator
├── provider.ex                # Provider configuration management
├── connection.ex              # Token lifecycle and refresh
├── vault.ex                   # AES-GCM encryption
└── schemas/                   # Ecto schemas
    ├── provider.ex            # OAuth provider configurations
    ├── connection.ex          # Active OAuth connections
    ├── oauth_session.ex       # Temporary OAuth sessions
    └── audit_log.ex           # Security audit logging
```

## OAuth User Flow

Tango implements a complete OAuth2 Authorization Code Flow:

```
1. Provider Setup
   ├─ Create provider from Nango catalog or custom config
   ├─ Store OAuth endpoints and client credentials
   └─ Encrypt client secrets with AES-GCM

2. Session Creation
   ├─ Create OAuth session with secure tokens
   ├─ Generate PKCE parameters (64-byte verifier → SHA256 challenge)
   └─ Store with 30-minute expiration and CSRF state

3. Authorization URL Generation
   ├─ Retrieve session and decrypt provider configuration
   ├─ Build authorization URL with PKCE challenge
   └─ Return URL for user redirect

4. Token Exchange
   ├─ Validate CSRF state and prevent cross-tenant attacks
   ├─ Exchange authorization code for access tokens
   ├─ Encrypt and store tokens with AES-GCM
   └─ Create persistent connection with status tracking

5. Connection Management
   ├─ Automatic refresh with 5-minute expiration buffer
   ├─ Exponential backoff with 3-attempt limits
   └─ Batch operations for background refresh jobs
```

Each step includes comprehensive audit logging, multi-tenant isolation, and security validations.

## Installation

Add `tango` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:tango, "~> 0.1.0"}
  ]
end
```

Install dependencies:

```bash
mix deps.get
```

## Configuration

Configure Tango in your application:

```elixir
# config/config.exs
config :tango,
  repo: MyApp.Repo,
  schema_prefix: "tango", # Optional
  encryption_key: System.get_env("TANGO_ENCRYPTION_KEY")

```

Run migrations:

```bash
mix ecto.migrate
```

## OAuth Providers

Providers are sourced from the [Nango catalog](https://docs.nango.dev/integrations/overview) with pre-configured OAuth endpoints and settings.

```bash
# List available providers
mix tango.providers.list

# Show provider details
mix tango.providers.show github

# Create provider from catalog
mix tango.providers.create github --client-id=xxx --client-secret=yyy
mix tango.providers.create stripe --api-key=sk_live_xxx

# Sync providers from catalog to database
mix tango.providers.sync
```

## Quick Start

### 1. Set up OAuth Provider

```elixir
# Create OAuth2 provider
mix tango.providers.create github --client-id=your_client_id --client-secret=your_secret

# Create API key provider
mix tango.providers.create stripe --api-key=sk_live_xxx

# Or programmatically
{:ok, provider} = Tango.create_provider(%{
  name: "github",
  config: %{
    "client_id" => "your_client_id",
    "auth_url" => "https://github.com/login/oauth/authorize",
    "token_url" => "https://github.com/login/oauth/access_token"
  },
  client_secret: "your_client_secret"
})
```

### 2. OAuth Flow Implementation

```elixir
# Start OAuth session
{:ok, session} = Tango.create_session("github", tenant_id,
  redirect_uri: "https://yourapp.com/auth/callback",
  scopes: ["user:email", "repo"]
)

# Generate authorization URL
{:ok, auth_url} = Tango.authorize_url(session.session_token,
  redirect_uri: "https://yourapp.com/auth/callback"
)
# Redirect user to auth_url

# Handle callback - exchange code for tokens
{:ok, connection} = Tango.exchange_code(state, authorization_code,
  redirect_uri: "https://yourapp.com/auth/callback"
)
```

### 3. Use OAuth Connection

```elixir
# Get active connection for API calls
{:ok, connection} = Tango.get_connection_for_provider("github", tenant_id)

# Use connection.access_token in your API requests
headers = [{"Authorization", "Bearer #{connection.access_token}"}]

# Mark connection as used (updates last_used_at)
Tango.mark_connection_used(connection)
```

## LiveView

### TODO

## API Routes for External Clients

For web or mobile clients, set up these Phoenix routes:

```elixir
# router.ex
scope "/api/oauth", MyAppWeb do
  pipe_through :api

  post "/sessions", OAuthController, :create_session
  get "/authorize/:session_token", OAuthController, :authorize_url
  post "/exchange", OAuthController, :exchange_code
  get "/connections", OAuthController, :list_connections
  delete "/connections/:provider", OAuthController, :revoke_connection
end
```

Example controller:

```elixir
defmodule MyAppWeb.OAuthController do
  use MyAppWeb, :controller

  def create_session(conn, %{"provider" => provider, "redirect_uri" => redirect_uri}) do
    tenant_id = get_current_tenant_id(conn)

    case Tango.create_session(provider, tenant_id, redirect_uri: redirect_uri) do
      {:ok, session} ->
        json(conn, %{session_token: session.session_token})
      {:error, reason} ->
        conn |> put_status(400) |> json(%{error: reason})
    end
  end

  def authorize_url(conn, %{"session_token" => token} = params) do
    opts = [redirect_uri: params["redirect_uri"], scopes: params["scopes"] || []]

    case Tango.authorize_url(token, opts) do
      {:ok, url} -> json(conn, %{authorization_url: url})
      {:error, reason} -> conn |> put_status(400) |> json(%{error: reason})
    end
  end

  def exchange_code(conn, %{"state" => state, "code" => code} = params) do
    opts = [redirect_uri: params["redirect_uri"]]

    case Tango.exchange_code(state, code, opts) do
      {:ok, connection} ->
        json(conn, %{
          provider: connection.provider.name,
          status: connection.status,
          scopes: connection.granted_scopes
        })
      {:error, reason} ->
        conn |> put_status(400) |> json(%{error: reason})
    end
  end

  defp get_current_tenant_id(conn) do
    # Extract tenant ID from JWT, session, etc.
    conn.assigns.current_user.id
  end
end
```

## Testing

**Requirements**: PostgreSQL running locally with `postgres:postgres` credentials.

```bash
# Run all tests
mix test

# Run with coverage report
mix coveralls

# Generate HTML coverage report
mix coveralls.html

# Run quality checks (format, credo, tests)
mix quality
```

## Planned Features

- **Drop-in API plug for clients**: Simplified Phoenix plug for OAuth endpoints
- **TypeScript client library**: Client SDK for web or OAuth flows
- **Phoenix LiveView components**: Pre-built UI component for OAuth flows
- **Token Refresh Automation**: Background job integration with automatic token refresh scheduling
- **Rate Limiting**: Built-in OAuth endpoint protection and request throttling
- **OAuth1 Support**: Legacy OAuth support for older providers

## Documentation

Documentation is available on [HexDocs](https://hexdocs.pm/tango) or generate locally:

```bash
mix docs
```
# 💃 Tango - OAuth Integrations Library

> Tango handles the OAuth dance between third-party services and your Phoenix application.

**Tango** is an Elixir OAuth integration library for Phoenix applications that provides drop-in OAuth support for third-party integrations. Inspired by [Nango](https://github.com/NangoHQ/nango) (previously [Pizzly](https://dev.to/bearer/introducing-pizzly-an-open-sourced-free-fast-simple-api-integrations-manager-4jog)) and compatible with Nango's provider configuration format, Tango leverages the extensive Nango [provider catalog](https://docs.nango.dev/integrations/all/1password-scim) while providing a library-first approach for Phoenix applications.

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
  encryption_key: System.get_env("TANGO_ENCRYPTION_KEY"),
  api_key: System.get_env("TANGO_API_KEY")
```

### Migrations

If using Ecto for migrations, generate and run the Tango migration:

```bash
# Generate migration file
mix ecto.gen.migration add_tango_tables

# Edit the generated migration file to call Tango.Migration:
# priv/repo/migrations/YYYYMMDDHHMMSS_add_tango_tables.exs
defmodule MyApp.Repo.Migrations.AddTangoTables do
  use Ecto.Migration

  def up do
    Tango.Migration.up()
  end

  def down do
    Tango.Migration.down()
  end
end

# Run migrations
mix ecto.migrate
```

Otherwise, if not using Ecto migrations, you can copy the SQL from `priv/repo/sql/versions/v01/v01_up.sql` and add it to your migration tool of choice (be sure to replace the schema prefix with "public" or your custom prefix).

## OAuth Providers

Providers are sourced from the [Nango catalog](https://docs.nango.dev/integrations/overview) with pre-configured OAuth endpoints and settings.

```bash
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

## Ready-to-Use OAuth API

Tango includes a complete OAuth API router that can be mounted in Phoenix applications with a single line.

### Setup

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

### Available Endpoints

The mounted API provides these endpoints:

- `POST /api/oauth/sessions` - Create OAuth session
- `GET /api/oauth/authorize/:session_token` - Get authorization URL  
- `POST /api/oauth/exchange` - Exchange authorization code for connection
- `GET /api/oauth/health` - Health check

### JavaScript Usage

```javascript
const API_BASE = '/api/oauth';
const TENANT_ID = 'user-123';
const API_KEY = 'your-secret-api-key';

// Start OAuth flow
async function startOAuth(provider, redirectUri, scopes = []) {
  // Create session
  const session = await fetch(`${API_BASE}/sessions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Tenant-ID': TENANT_ID,
      'Authorization': `Bearer ${API_KEY}`
    },
    body: JSON.stringify({ provider, redirect_uri: redirectUri, scopes })
  }).then(r => r.json());

  // Get authorization URL
  const authUrl = await fetch(
    `${API_BASE}/authorize/${session.session_token}?redirect_uri=${redirectUri}&scopes=${scopes.join(' ')}`,
    { 
      headers: { 
        'X-Tenant-ID': TENANT_ID,
        'Authorization': `Bearer ${API_KEY}`
      } 
    }
  ).then(r => r.json());

  // Redirect to OAuth provider
  window.location.href = authUrl.authorization_url;
}

// Handle OAuth callback
async function handleCallback() {
  const params = new URLSearchParams(window.location.search);
  const state = params.get('state');
  const code = params.get('code');
  
  if (state && code) {
    const connection = await fetch(`${API_BASE}/exchange`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': TENANT_ID,
        'Authorization': `Bearer ${API_KEY}`
      },
      body: JSON.stringify({
        state,
        code,
        redirect_uri: window.location.origin + '/callback'
      })
    }).then(r => r.json());

    console.log('OAuth connection established:', connection);
  }
}
```

### Connection Management

Use Tango's programmatic API in your Phoenix application to manage connections:

```elixir
# List connections for a user
connections = Tango.list_connections(user_id)

# Get connection for API calls
{:ok, connection} = Tango.get_connection_for_provider("github", user_id)
headers = [{"Authorization", "Bearer #{connection.access_token}"}]

# Revoke connection
{:ok, _revoked} = Tango.revoke_connection(connection, user_id)
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
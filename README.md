# 💃 Tango

[![Hex.pm](https://img.shields.io/hexpm/v/tango.svg)](https://hex.pm/packages/tango)
[![Hex Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/tango)
[![License](https://img.shields.io/hexpm/l/tango.svg)](https://github.com/agoodway/tango/blob/main/LICENSE)

> OAuth integrations for Phoenix — sessions, encrypted tokens, and multi-tenant connections.

Tango is an Elixir library for third-party OAuth in Phoenix apps. It is
compatible with [Nango's provider catalog](https://docs.nango.dev/integrations)
and stores tokens encrypted in Postgres via your host Ecto repo.

## Why Tango?

- **OAuth2 authorization code flow** with PKCE, CSRF state, and tenant isolation
- **Encrypted tokens** (AES-GCM) plus structured audit logging
- **Credential-free browser callback** (0.2.0) — completion handle only; verify and finalize on your server
- **Optional LiveView component** and mountable OAuth API router
- **Nango-compatible providers** from catalog or custom config (the catalog's OAuth2 authorization-code entries; see [PROVIDERS.md](docs/PROVIDERS.md#supported-catalog-entries))

## Prerequisites

- Elixir 1.15+
- PostgreSQL
- An Ecto SQL repo

## Installation

Add `tango` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:tango, "~> 0.4.0"}
  ]
end
```

Then fetch dependencies:

```bash
mix deps.get
```

## Quick Start

### 1. Configure

```elixir
# config/config.exs
config :tango,
  repo: MyApp.Repo,
  encryption_key: System.get_env("TANGO_ENCRYPTION_KEY"),
  api_key: System.get_env("TANGO_API_KEY")
```

Generate an encryption key:

```bash
openssl rand -base64 32
```

### 2. Install the schema

`mix tango.setup` writes a host-owned wrapper migration; `mix ecto.migrate`
applies it. Use setup for the **initial install only** — upgrades need a
separate pinned migration (see [SETUP.md](docs/SETUP.md)).

```bash
mix tango.setup
mix ecto.migrate
```

### 3. Create a provider

```bash
mix tango.providers.create github \
  --client-id=your_client_id \
  --client-secret=your_client_secret
```

### 4. Run a direct OAuth flow

```elixir
tenant_id = "user-123"
redirect_uri = "https://yourapp.com/auth/callback"

{:ok, session} =
  Tango.create_session("github", tenant_id,
    redirect_uri: redirect_uri,
    scopes: ["user:email", "repo"]
  )

{:ok, auth_url} =
  Tango.authorize_url(session.session_token, redirect_uri: redirect_uri)

# Redirect the user to auth_url. After the provider returns state + code:

{:ok, connection} =
  Tango.exchange_code(state, code, tenant_id, redirect_uri: redirect_uri)

{:ok, connection} = Tango.get_connection_for_provider("github", tenant_id)
headers = [{"Authorization", "Bearer #{connection.access_token}"}]
```

For browser popups, see [AUTHORIZATION.md](docs/AUTHORIZATION.md).

## Documentation

- [SETUP.md](docs/SETUP.md): config options, migrations, upgrading an install, non-Ecto setups
- [PROVIDERS.md](docs/PROVIDERS.md): catalog mix tasks, supported catalog options, programmatic providers
- [USAGE.md](docs/USAGE.md): direct server-side OAuth, connections, refresh errors and retry behavior
- [AUTHORIZATION.md](docs/AUTHORIZATION.md): browser popup completion, verifiers, token retention
- [API.md](docs/API.md): mountable HTTP router and JavaScript examples
- [UPGRADING.md](docs/UPGRADING.md): what changed in each release and what to do

## Testing

Requires local PostgreSQL with `postgres:postgres` credentials. Consumer tests
can insert providers and connections with `Tango.Testing`.

```bash
mix test
mix coveralls
mix quality
```

## License

See [LICENSE](LICENSE).

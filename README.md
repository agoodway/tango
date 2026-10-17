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

## Further reading

- [SETUP.md](docs/SETUP.md) — config options, upgrades, non-Ecto installs
- [PROVIDERS.md](docs/PROVIDERS.md) — catalog mix tasks and programmatic providers
- [USAGE.md](docs/USAGE.md) — direct server-side OAuth and connection usage
- [AUTHORIZATION.md](docs/AUTHORIZATION.md) — browser popup completion (0.2.0)
- [API.md](docs/API.md) — mountable HTTP router and JavaScript examples

## Prerequisites

- Elixir 1.15+
- PostgreSQL
- An Ecto SQL repo

## Installation

Add `tango` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:tango, "~> 0.3.0"}
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

For browser popups (credential-free completion handle), see
[AUTHORIZATION.md](docs/AUTHORIZATION.md). More connection helpers:
[USAGE.md](docs/USAGE.md). Mount the HTTP API: [API.md](docs/API.md).

## Upgrading to 0.3.0

0.3.0 changes refresh error values and when an on-demand refresh may still
return a usable access token. The database schema stays **V03**. Installations
already on 0.2.0 do not run a new migration. Older installations still apply
the existing V03 migration in [SETUP.md](docs/SETUP.md) before using 0.3.0.
There is no migration away from V03.

`record_auth_failure/3` and `record_auth_success/2` are unchanged. Resource
API strings such as `"http_401"` are not refresh errors.

### Refresh errors

`Tango.refresh_connection/1` returns `{:error, reason}`. These on-demand
entries return `{:error, {:refresh_failed, reason}}` unless the active,
still-valid token fallback below applies:

- `Tango.Connection.refresh_if_needed/1`
- `Tango.get_active_connection/3` with `auto_refresh: true`
- `Tango.get_connection_for_provider/3` with `auto_refresh: true`

`Tango` does not define refresh_if_needed/1. `Tango.refresh_expiring_connections/0`
still returns `{:ok, success_count}`. Missing and inactive rows stay
`{:error, :not_found}`, outside the reason union.

`reason` is a `Tango.RefreshError` term. HTTP status wins over the body: 429
is `{:rate_limited, seconds | nil}`, and 408 or 5xx is `{:http_error, status}`,
even when the body says `invalid_grant`. Other 4xx responses use an allowlisted
OAuth code (`{:oauth_error, :invalid_grant | :invalid_client |
:unauthorized_client | :invalid_request | :invalid_scope |
:unsupported_grant_type | :temporarily_unavailable | :server_error}`) or
`{:http_error, status}` when the code is absent or unknown. Transport failures
are `{:transport_error, :timeout | :network_error}`. Local failures include
`:no_refresh_token`, `:refresh_not_allowed`, `:provider_not_found`,
`:invalid_config`, `:persistence_failed`, and `:transaction_failed`.

Database failures that Tango returns are only those two atoms. A changeset never
leaves a refresh path. Raised database exceptions are not rescued and are not
classified as transport errors.

Serialize with `Tango.RefreshError.to_storage/1` at audit, log, telemetry, and
JSON boundaries. Examples: `"oauth_error:invalid_grant"`, `"rate_limited:30"`,
`"rate_limited"`, `"http_error:503"`, `"transport_error:timeout"`,
`"persistence_failed"`. Unknown terms become `"unknown_refresh_error"`. Do not
match stored `last_refresh_failure` strings, including values written before
0.3.0. Those strings stay informational. They are not migrated and they do not
affect retry.

### Retry, fallback, and scheduling

| Class | Effect |
| --- | --- |
| `:credential` (`invalid_grant`) | One attempt, then `status: :expired` and `refresh_exhausted: true` immediately |
| `:client`, `:request` | Increment attempts; expire and exhaust at 3 |
| `:transient` | Keep attempts, status, and exhaustion; set `next_refresh_at` |
| `:persistence_failed`, `:transaction_failed` | No attempt write and no token fallback |

Named local eligibility failures such as `:no_refresh_token` and
`:refresh_not_allowed` do not write a new attempt. Success clears
`next_refresh_at`. A failure never revives an expired or revoked row and never
clears exhaustion.

Delay is the numeric `Retry-After` seconds, otherwise 300, and never more than
3600. `next_refresh_at` delays **sweeps only**. Explicit and on-demand refresh
ignore it, so a request can still reach the provider during backoff.

Fallback to the current access token is allowed only while the row stays
`:active` and the token is unexpired (`expires_at` in the future, or `nil`).
Credential expiry and the third client or request failure return the error even
when the access token still has time left. Later active getters then return
`{:error, :not_found}`. Client and request exhaustion means the retry budget
ended. It does not by itself prove the user revoked consent.

Rows that are already expired or refresh-exhausted stay that way after
upgrade. Reconnect them through the ordinary authorization flow. A future
`next_refresh_at` now delays sweeps. A 0.2.0 worker ignores that column. Avoid
running mixed refresh-worker versions when backoff must hold immediately.

### Reads, locks, revoke, and tests

- `Tango.get_connection_info/2` and `Tango.list_connection_infos/2` return
  `%Tango.ConnectionInfo{}` with no tokens. Listing defaults to `status:
  :active` and accepts `:expired`, `:revoked`, `:any`, or a list. Both include
  inactive providers. `Tango.get_provider/1` remains active-only.
- `Tango.lock_connection_generations/3` locks one tenant's provider slugs
  inside the caller's Tango transaction. The `opts` argument defaults to
  `missing: :error`. Inactive providers are locked. `missing: :skip` ignores
  unknown slugs. Order is provider id, then tenant binary, for the whole outer
  transaction. Take the full set once before nested Tango calls.
- `Tango.revoke_connection/2` accepts a struct or an integer id. The struct
  clause still returns `{:error, :not_authorized}` on a tenant mismatch. The id
  clause returns `{:error, :not_found}` for a missing, wrong-tenant, or
  already-revoked row. Active and expired rows can be revoked.
  `revoke_provider_connections/1` still looks up an active provider.
- `Tango.Testing.insert_provider!/1` and `Tango.Testing.insert_connection!/3`
  insert fixtures. Both attribute arguments default to `%{}`. They are for test
  suites. Authorization candidates, row aging, and cleanup stay in the host
  test suite.

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

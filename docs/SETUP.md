# Setup

## Configuration

```elixir
# config/config.exs
config :tango,
  repo: MyApp.Repo,
  schema_prefix: "tango", # Optional
  encryption_key: System.get_env("TANGO_ENCRYPTION_KEY"),
  api_key: System.get_env("TANGO_API_KEY")
```

Generate an encryption key:

```bash
openssl rand -base64 32
```

For browser popup completion (0.2.0+), also configure exact origins — see
[AUTHORIZATION.md](AUTHORIZATION.md#exact-origin-setup).

## Migrations

`mix tango.setup` writes a wrapper migration to `priv/repo/migrations/`;
`mix ecto.migrate` applies it.

```bash
mix tango.setup
mix ecto.migrate
```

`mix tango.setup` is for the **initial install only** — its generated `down`
calls `Tango.Migration.down()`, which targets version 0 and drops every Tango
table. Never rerun it to pick up a new schema version.

### Upgrading an existing install

When a Tango release ships a new schema version, write a fresh migration in
your application pinning the version range explicitly, so rolling it back
returns to the previous version instead of dropping the schema.

**Tango 0.2.0 ships schema version 3 (V03).** It adds the
`tango_authorizations` table for authorization candidates, binding columns on
`tango_oauth_sessions` (completion origin, intent reference, expected
connection and subject, authorization parameters, OAuth client), and
`account_subject` / `oauth_client_id` on `tango_connections`. Upgrading from
0.1.x:

```elixir
defmodule MyApp.Repo.Migrations.UpgradeTangoV03 do
  use Ecto.Migration

  def up, do: Tango.Migration.up(version: 3)
  def down, do: Tango.Migration.down(version: 2)
end
```

Run `mix ecto.migrate` before deploying code that uses authorization completion.

**Tango 0.4 ships schema version 4 (V04).** It adds
`tango_authorizations.provider_data`, a JSONB object column (default `'{}'`)
holding token-response metadata for staged candidates. V04 is required before
running 0.4 for all providers, and builds on V03. Upgrading from 0.2.x or 0.3.x
(apply V03 first if you are on 0.1.x):

```elixir
defmodule MyApp.Repo.Migrations.UpgradeTangoV04 do
  use Ecto.Migration

  def up, do: Tango.Migration.up(version: 4)
  def down, do: Tango.Migration.down(version: 3)
end
```

Run `mix ecto.migrate` before deploying 0.4 code.

### Without Ecto migrations

Copy the SQL from `priv/repo/sql/versions/<version>/` into your migration tool
of choice (replace the `$SCHEMA$` placeholder with `"public"` or your custom
prefix), and stamp the version marker EctoEvolver would have written, so
`Tango.Migration.migrated_version/1` agrees with the physical schema:

```sql
COMMENT ON TABLE "$SCHEMA$".tango_providers IS 'Tango version=4';
```

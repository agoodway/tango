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

**Tango 0.4.1 ships revised schema version 4 (V04), with no V05.** It retains
`tango_authorizations.provider_data`, a JSONB object column (default `'{}'`)
holding token-response metadata, and adds completion mode columns and checks to
both sessions and candidates. Existing rows default to connection mode. V04 is
required for all providers and both completion modes, and builds on V03.
Upgrading a V03 database with 0.4.1 installed (apply V03 first on older databases):

```elixir
defmodule MyApp.Repo.Migrations.UpgradeTangoV04 do
  use Ecto.Migration

  def up, do: Tango.Migration.up(version: 4)
  def down, do: Tango.Migration.down(version: 3)
end
```

Run `mix ecto.migrate` before deploying 0.4.1 code. For a fresh install, install
0.4.1 and apply through revised V04. Dependency installation alone applies no DDL.
The bundled demo's `UpgradeTangoV04` wrapper pins this same up-to-4/down-to-3 range.

### Checking an already-applied V04

V04 was explicitly authorized to change in place because 0.4.0 has no external
consumers. Known developer databases can therefore report version 4 while
lacking the revised schema. Neither re-running an applied wrapper nor the version
marker proves readiness. Inspect both columns and constraints in the actual
schema before running 0.4.1 code. These read-only queries use `public`; substitute
your configured schema prefix:

```sql
SELECT table_name, column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name IN ('tango_oauth_sessions', 'tango_authorizations')
  AND column_name IN ('completion_mode', 'provider_data')
ORDER BY table_name, column_name;

SELECT c.relname AS table_name, con.conname,
       pg_get_constraintdef(con.oid) AS definition
FROM pg_constraint con
JOIN pg_class c ON c.oid = con.conrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname IN ('tango_oauth_sessions', 'tango_authorizations')
  AND con.contype = 'c'
ORDER BY c.relname, con.conname;
```

Require both `completion_mode` columns to be text, NOT NULL, default
`'connection'`, with mode checks allowing only `connection` and `consume`.
Require `tango_oauth_sessions_consume_connection_check` to forbid non-null
`expected_connection_id` for consume sessions, and
`tango_authorizations_consume_connection_check` to forbid non-null
`expected_connection_id` or `verified_connection_id` for consume candidates.
Also retain `tango_authorizations.provider_data` as JSONB, NOT NULL, default
`'{}'`, and its JSON-object check. Check definitions as well as constraint names
against the bundled `priv/repo/sql/versions/v04/v04_up.sql`.

If shape differs and data must be retained, use a reviewed targeted host migration
to reconcile the missing DDL. For a disposable developer database, recreate it
fresh and apply migrations through revised V04. The current V04 down migration
cannot run against the original V04 schema: its rollback guard queries the
missing `completion_mode` columns before DDL. Do not use the current wrapper to
roundtrip that original schema. Tango does not repair schemas at runtime. Do not
rerun the full V04 SQL over an applied schema: its added columns and constraints
are not all idempotent. See
[Revised V04 deployment exception](UPGRADING.md#revised-v04-deployment-exception)
and the [V04 rollback guard](UPGRADING.md#v04-rollback-guard) before any rollback.
Pending consume sessions/candidates block rollback before DDL under table locks;
manual rollback must keep the guard and DDL in one transaction.

### Without Ecto migrations

Copy the SQL from `priv/repo/sql/versions/<version>/` into your migration tool
of choice (replace the `$SCHEMA$` placeholder with `"public"` or your custom
prefix), and stamp the version marker EctoEvolver would have written, so
`Tango.Migration.migrated_version/1` agrees with the physical schema:

```sql
COMMENT ON TABLE "$SCHEMA$".tango_providers IS 'Tango version=4';
```

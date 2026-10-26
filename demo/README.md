# Tango 0.4.1 demo

This Phoenix app connects a GitHub account through Tango's staged authorization
flow, verifies its account identity on the server, and displays the profile and
audit trail. The browser receives an opaque completion handle, never OAuth tokens.

The demo uses the parent checkout through `{:tango, path: ".."}`. Its package
version is 0.4.1, which requires Tango schema V04. The migration wrapper
`priv/repo/migrations/20261026120000_upgrade_tango_v04.exs` installs it for a
fresh V03 database. An already-applied V04 does not rerun: inspect both completion
mode columns and checks using the parent [setup guide](../docs/SETUP.md#checking-an-already-applied-v04).
The [upgrade guide](../docs/UPGRADING.md#v04-rollback-guard) describes the pending
consume rollback guard and table locks. This demo keeps credential connection
completion; generic consume examples live in the parent [authorization guide](../docs/AUTHORIZATION.md#server-verify-and-consume-a-proof).

Connection identity and display data come from `Tango.list_connection_infos/2`.
Only the server's GitHub API call requests a credential-bearing connection, using
`Tango.get_active_connection/3` with `auto_refresh: true`.

Refresh errors display `Tango.RefreshError.to_storage/1` codes. An outage keeps an
active connection available, while an expired connection restores the connect
button. Existing valid-token fallback and retry policy remain owned by Tango.

## Local setup

Configure a GitHub OAuth provider using the parent project's
[provider guide](../docs/PROVIDERS.md). Use
`http://localhost:4000/api/oauth/callback` as its callback URL. With local
PostgreSQL available, `mix setup` installs dependencies and prepares the demo
database. `mix phx.server` serves the app at `http://localhost:4000`.

The fixed tenant `demo-user-1`, sample encryption key, and sample API key are for
local demonstration. A host application supplies authenticated tenant identity
and its own secrets.

## Verification

Run `mix format` and `mix quality` from this directory. The quality command
compiles with warnings as errors, checks formatting, and runs the full demo test
suite. Its test alias creates the test database if absent and applies pending
migrations.

Tests use `demo_test` on `localhost:5432`. With that database already migrated,
run affected tests without the demo's database setup alias:

```sh
MIX_ENV=test mix run --no-start -e 'Mix.Tasks.Test.run(System.argv())' -- test/demo_web/live/demo_live_test.exs test/demo/github_connect_test.exs test/demo/github_verifier_test.exs test/demo_web/components/tango_logs_component_test.exs
```

The test fixture uses `Tango.Testing.insert_provider!/1` for ordinary provider
setup. Candidate tests retain the real public staged authorization flow.

# Upgrading

Newest version first. For new installs, see [SETUP.md](SETUP.md).

## Upgrading to 0.4.1

Use `{:tango, "~> 0.4.1"}`. Ordinary direct credential connections and staged
connection finalization remain supported, with connection completion the default.
Opt-in `completion_mode: :consume` uses the same staged verification contract and
`Tango.Authorization.multi_consume_authorization/5` to commit a safe identity proof
without retaining a connection. See [Authorization completion](AUTHORIZATION.md)
for account-link and organization administrator examples, exact return/errors,
and host revalidation responsibilities.

### Revised V04 deployment exception

0.4.1 retains schema version 4 and revises V04 in place under the explicitly
authorized assumption that 0.4.0 has no external consumers. There is no V05.
Besides the existing `provider_data` column/check, V04 now installs
`completion_mode TEXT NOT NULL DEFAULT 'connection'` on both
`tango_oauth_sessions` and `tango_authorizations`, checks both modes against
`connection`/`consume`, and forbids connection bindings on consume rows. Existing
rows default to connection mode. Every 0.4.1 deployment requires this shape even
when consume mode is unused.

- Fresh installs apply migrations through revised V04 with 0.4.1 installed.
- Databases at V03 use the pinned V04 wrapper below, with 0.4.1 installed before
  applying the migration. Apply V03 first for older databases.
- Known developer databases already reporting version 4 need an explicit
  [schema-shape check](SETUP.md#checking-an-already-applied-v04). A version marker
  alone is insufficient. The wrapper does not rerun applied V04, and installing
  a dependency does not apply DDL. Reconcile missing columns/checks with a reviewed
  targeted host migration when retaining data, or recreate a disposable developer
  database fresh and apply migrations through revised V04. The current wrapper's
  down migration cannot run on the original V04 shape because its guard queries
  the missing `completion_mode` columns. Do not use it to roundtrip that schema.
  Tango adds no automatic runtime schema repair.

### V04 rollback guard

V04 rollback takes `ACCESS EXCLUSIVE` locks on `tango_oauth_sessions`, then
`tango_authorizations`, held through migration completion. It checks for pending
consume work before any DDL and fails if an unexpired consume session has not
been exchanged or an unexpired consume candidate is unconsumed. This prevents
pending consent from being reinterpreted as connection creation. These locks
block concurrent activity on those tables; schedule host migrations accordingly.

Complete pending operations or let them expire, then run the normal authorization
and session cleanup APIs before retrying. Consumed or expired temporary rows may
be removed by those APIs. Never revoke stored connections to bypass the guard.
Manual SQL rollback must keep every statement in one transaction so locks remain
held through DDL. This rollback requires the revised V04 schema, including both
`completion_mode` columns; it is not a reconciliation path for original V04.
Rollback also removes `provider_data`; assess that data loss before rolling back.

## Upgrading to 0.4

V04 is mandatory for every 0.4 install, whether or not a provider uses
token-response metadata, because the schema selects the new column. It adds
`tango_authorizations.provider_data` (JSONB, default `'{}'`, checked to be an
object). Apply it before running 0.4 code:

```elixir
defmodule MyApp.Repo.Migrations.UpgradeTangoV04 do
  use Ecto.Migration

  def up, do: Tango.Migration.up(version: 4)
  def down, do: Tango.Migration.down(version: 3)
end
```

See [SETUP.md](SETUP.md#upgrading-an-existing-install) for installs
without Ecto migrations.

0.4 honors two more provider `metadata` keys under Nango's catalog names, so
catalog imports pick them up. Defaults are unchanged when the keys are absent:

- `token_response_metadata`: see [Token-response metadata](PROVIDERS.md#token-response-metadata).
- `"authorization_method" => "body"`: see
  [Body client authentication](PROVIDERS.md#body-client-authentication).

The code exchange also rejects responses that are not a token response; see
[Token exchange response checks](USAGE.md#token-exchange-response-checks).

Before deploying, check existing provider rows. 0.3 ignored
`"authorization_method" => "body"` and any value other than `"header"`; 0.4
sends body-only client credentials for `"body"` and rejects other values on the
next provider update. `mix tango.providers.sync --update-metadata` merges the
catalog's metadata over local values, including `nil` for keys the catalog
omits, so re-apply hand-set `token_response_metadata` or `authorization_method`
values after syncing.

## Upgrading to 0.3.0

0.3.0 changes refresh error values and when an on-demand refresh may still
return a usable access token. 0.3.0 itself adds no migration: installations
already on 0.2.0 run nothing new for it, and older installations apply the V03
migration in [SETUP.md](SETUP.md). Tango 0.4 requires V04; see
[Upgrading to 0.4](#upgrading-to-04).

`record_auth_failure/3` and `record_auth_success/2` are unchanged. Resource
API strings such as `"http_401"` are not refresh errors.

What changed and where it is documented:

- Refresh error values and fallback: [Refresh errors](USAGE.md#refresh-errors).
- Backoff, expiry and scheduling: [Retry, fallback, and scheduling](USAGE.md#retry-fallback-and-scheduling).
- Token-free reads, generation locks, revoke by id, and test helpers:
  [Reads, locks, revoke, and tests](USAGE.md#reads-locks-revoke-and-tests).

Rows that are already expired or refresh-exhausted stay that way after
upgrade. Reconnect them through the ordinary authorization flow. A future
`next_refresh_at` now delays sweeps. A 0.2.0 worker ignores that column. Avoid
running mixed refresh-worker versions when backoff must hold immediately.

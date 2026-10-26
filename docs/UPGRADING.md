# Upgrading

Newest version first. For new installs, see [SETUP.md](SETUP.md).

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

# Usage

Browser popup flows use [authorization completion](AUTHORIZATION.md). The
direct server-side flow below suits integrations where your server handles the
redirect itself.

## Direct OAuth flow

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

# Handle callback — exchange code for tokens
{:ok, connection} = Tango.exchange_code(state, authorization_code, tenant_id,
  redirect_uri: "https://yourapp.com/auth/callback"
)
```

## Using a connection

```elixir
{:ok, connection} = Tango.get_connection_for_provider("github", tenant_id)
headers = [{"Authorization", "Bearer #{connection.access_token}"}]

Tango.mark_connection_used(connection)

# On-demand refresh returns {:error, {:refresh_failed, reason}} when the
# current token cannot be served. `reason` is a Tango.RefreshError term.
# Credential failure and an exhausted client or request budget do not return
# the old access token. Timeouts, 429, and 5xx may still return it while the
# row stays active and unexpired. Tango.refresh_connection/1 always returns
# {:error, reason} for a failed refresh. Sweep backoff does not apply here.
{:ok, connection} =
  Tango.get_connection_for_provider("github", tenant_id, auto_refresh: true)

# Log or store a failure with Tango.RefreshError.to_storage/1.
# Do not match old last_refresh_failure strings.

{:ok, _revoked} = Tango.revoke_connection(connection, tenant_id)
{:ok, info} = Tango.get_connection_info(connection.id, tenant_id)
```

## Reporting provider auth outcomes

Report a 401 when the credentials themselves were rejected. Do **not**
blanket-report 403: providers use it for insufficient scope, resource policy,
and quota. Three consecutive rejections (tune with `:max_failures`) expire the
connection.

```elixir
case call_the_provider(connection) do
  {:ok, result} ->
    Tango.record_auth_success(connection)
    {:ok, result}

  {:error, {:http_error, 401, _body}} ->
    Tango.record_auth_failure(connection, "http_401", max_failures: 3)
    {:error, :unauthorized}
end
```

## Token exchange response checks

The code exchange rejects responses that are not a token response:

- A 3xx redirect and a 2xx JSON object with an `error` key are treated as
  provider errors and categorized like other OAuth errors (for example
  `{:oauth_error, :access_denied}`).
- A 2xx HTML page, JSON scalar or undecodable body fails with
  `:invalid_token_response`.
- A 2xx empty body fails with `:empty_access_token`.

`Tango.exchange_code/4` returns these as bare atoms (`{:error,
:invalid_token_response}`). The staged popup flow wraps them as `{:error,
{:oauth_error, :invalid_token_response}}` and posts the code string to the
callback. `:invalid_grant_metadata` (retained token-response metadata over
4 KiB) occurs only on the staged flow, since `exchange_code/4` does not retain
metadata. Audit records store `:invalid_token_response` and
`:invalid_grant_metadata` as error codes.

## Refresh errors

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

## Retry, fallback, and scheduling

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

## Reads, locks, revoke, and tests

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

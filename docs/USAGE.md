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

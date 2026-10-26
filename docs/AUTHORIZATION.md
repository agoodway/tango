# Authorization completion

Staged authorization supports two server-selected lifecycles. The default
`completion_mode: :connection` verifies identity and finalizes a stored credential
connection. Optional `completion_mode: :consume` verifies identity and atomically
consumes a safe proof without creating or replacing a connection. The callback
page posts a completion handle and intent reference only; no credential or raw
provider payload reaches the browser.

```
1. Server creates an authorization session
   └─ binds provider, scopes, redirect URI, completion origin, and intent reference
2. Popup consent; provider redirects to Tango /callback
   └─ code exchange stores an encrypted candidate (10-minute lifetime)
3. Callback posts { completion_handle, intent_reference } to the completion origin
4. Browser forwards the handle to an authenticated app endpoint
5. App verifies identity, then completes in its Ecto.Multi
   └─ connection or consumed proof and app records commit together or not at all
```

## Server: verify and finalize a connection

Verification and finalization are server-only. Browser input cannot choose the
verifier module or its options.

A verifier receives the candidate's ephemeral access token, the granted scopes,
any token-response metadata the provider is configured to retain, and options
that only your server code supplies. The credential is always
`%{access_token: binary, granted_scopes: [String.t()], provider_data: map}`.
`provider_data` holds the scalar fields listed in the provider's
`token_response_metadata` (for example Salesforce's `instance_url` or Slack's
`team.id`) and is `%{}` when none are configured or present. Hosts must allowlist
only non-secret identity attributes: a key without the word token is not
automatically safe. It exists only
while the candidate is staged: `verify_connection_identity/3` receives
`provider_data: %{}`. A verifier returns a stable account
subject and a small allowlist of identity claims. Never return tokens, headers,
or raw provider payloads from it.

```elixir
defmodule MyApp.ExampleVerifier do
  @behaviour Tango.AuthorizationVerifier

  @impl true
  def verify(_provider, %{access_token: access_token, granted_scopes: _scopes, provider_data: _data}, opts) do
    case MyApp.ExampleClient.fetch_account(access_token) do
      {:ok, %{"id" => id, "display_name" => display_name}} ->
        {:ok,
         %{
           subject: to_string(id),
           claims: %{"display_name" => display_name},
           continuity: continuity(opts)
         }}

      _ ->
        {:error, :invalid_identity}
    end
  end

  # :initial for a first connection, {:connection, id} when upgrading one
  defp continuity(opts) do
    case Keyword.get(opts, :connection_id) do
      nil -> :initial
      connection_id -> {:connection, connection_id}
    end
  end
end
```

Tango validates the returned claims: JSON-compatible, at most 4 KiB encoded,
and no token-like keys at any depth. When the session was started to upgrade an
existing connection, the returned subject must equal the expected subject and
the proof must be `{:connection, expected_connection_id}`.

Complete the authorization in a request handled by your authenticated
application. The tenant comes from your session, never from the browser:

```elixir
def complete(handle, intent_reference, tenant_id, expected_connection_id \\ nil) do
  verifier = {MyApp.ExampleVerifier, connection_id: expected_connection_id}

  # HTTP verification runs before the database transaction opens.
  with {:ok, identity} <-
         Tango.verify_authorization(handle, tenant_id, verifier,
           intent_reference: intent_reference,
           provider: "example"
         ) do
    Ecto.Multi.new()
    |> Tango.multi_finalize_authorization(:authorization, handle, tenant_id,
      required_scopes: ["accounts.read", "records.write"],
      require_refresh_token: true,
      intent_reference: intent_reference,
      provider: "example",
      expected_connection_id: expected_connection_id
    )
    |> Ecto.Multi.insert(:link, fn %{authorization: %{connection: connection}} ->
      MyApp.AccountLink.changeset(%MyApp.AccountLink{}, %{
        tenant_id: tenant_id,
        tango_connection_id: connection.id,
        subject: identity.subject
      })
    end)
    |> MyApp.Repo.transaction()
    |> case do
      {:ok, %{authorization: %{connection: connection}, link: link}} -> {:ok, connection, link}
      {:error, _step, reason, _changes} -> {:error, reason}
    end
  end
end
```

Requirements and behavior:

- **Same Repo.** The Multi must run on the Repo configured as `config :tango, repo: ...`. A different Repo returns `{:error, :repo_mismatch}`.
- **`required_scopes`** are the API scopes your consumer needs. Do not list protocol hints that providers omit from granted scopes (for example `offline_access`). A shortfall returns `{:error, :missing_scopes}`.
- **`require_refresh_token: true`** returns `{:error, :refresh_token_required}` when the provider issued none and there is no existing refresh token to retain.
- The finalized operation returns `%{connection: connection, authorization: summary}`. `summary` holds the provider slug, subject, claims, granted scopes, and intent reference.
- A handle works once. Replays return `{:error, :completion_consumed}`, expired candidates `:expired_completion`, and unknown or cross-tenant handles `:invalid_completion`.
- Other errors are atoms: `:invalid_session`, `:verification_required`, `:account_mismatch`, `:stale_connection`, `:client_changed`, `:intent_mismatch`, and `:token_expired`. OAuth failures are sanitized `{:oauth_error, category}` tuples. No exception or raw provider body is returned.

To start a flow without the LiveView component, create the session on your
server and open the authorization URL in a popup:

```elixir
{:ok, session} =
  Tango.create_authorization_session("example", tenant_id,
    scopes: ["accounts.read", "records.write"],
    redirect_uri: "https://app.example.com/api/oauth/callback",
    completion_origin: "https://app.example.com",
    intent_reference: intent_reference,
    # Optional: bind a reauthorization to an existing connection
    expected_connection_id: existing_connection_id,
    expected_subject: existing_subject,
    auth_params: %{"prompt" => "consent"}
  )

{:ok, url} = Tango.Auth.authorization_url(session)
```

The session's scopes and authorization parameters are authoritative. The
`redirect_uri` must be registered with the provider and routed to Tango's
`/callback` endpoint (see [Ready-to-Use OAuth API](API.md)).

## Server: verify and consume a proof

Create the session from authenticated server code, selecting consume mode before
consent. The provider slug below identifies a synthetic example provider:

```elixir
{:ok, session} =
  Tango.create_authorization_session("example", tenant_id,
    completion_mode: :consume,
    scopes: ["records.read"],
    redirect_uri: "https://app.example.com/api/oauth/callback",
    completion_origin: "https://app.example.com",
    intent_reference: intent,
    expected_subject: known_subject
  )

{:ok, url} = Tango.Auth.authorization_url(session)
```

`expected_subject` may be omitted for account discovery or be a nonblank string
bound independently of a connection. Consume mode rejects any non-nil
`expected_connection_id` with `:invalid_completion_options`. Invalid modes return
`:invalid_completion_mode`. `Tango.create_session/3` supports direct credential
connections and rejects consume mode. The callback stages an ordinary encrypted
token response, still requiring an access token. Browser data, authorization URL
parameters, and token-response metadata cannot select or override the mode.

The account-link pattern uses the authenticated tenant and a server-selected
verifier. `AccountVerifier`, `AccountLinks`, and `MyApp.Repo` are host-owned example
modules, not Tango APIs. The verifier uses the same subject/claims/continuity
contract shown above, with `continuity: :initial` for consume mode:

```elixir
with {:ok, _identity} <-
       Tango.verify_authorization(handle, tenant_id, {AccountVerifier, []},
         provider: provider_slug,
         intent_reference: intent
       ) do
  Ecto.Multi.new()
  |> Tango.Authorization.multi_consume_authorization(:proof, handle, tenant_id,
    provider: provider_slug,
    intent_reference: intent,
    required_scopes: ["records.read"]
  )
  |> Ecto.Multi.run(:association, fn repo, %{proof: proof} ->
    AccountLinks.insert_verified(repo, tenant_id, proof.subject)
  end)
  |> MyApp.Repo.transaction()
end
```

`AccountLinks.insert_verified/3` must lock and revalidate the host's pending
operation and the authenticated actor's permission in this same transaction.
Capture the authenticated actor and intent in host code as needed. Likewise, an
organization onboarding write must check cancellation, operation freshness, actor
permissions, and any reconnect/version binding under the appropriate host locks.
If host validation or a later write fails, the transaction rolls back consumption
and credential erasure, allowing completion to be retried without another code
exchange. Provider HTTP verification runs before opening the transaction.

### Organization administrator example

This second verifier checks active administrator membership for one
server-selected organization, returning only its ID and role. All module names
in this example are host-owned. `OrganizationClient.fetch_membership/3` is a
host-defined adapter that performs a bounded, read-only authenticated provider
request, normalizes the response to the synthetic shape below, and returns a
sanitized error on failure. Its options, including the client module and
organization ID, must come from trusted server code:

```elixir
defmodule OrganizationAdminVerifier do
  @behaviour Tango.AuthorizationVerifier

  @impl true
  def verify(_provider, %{access_token: access_token}, opts) do
    organization_id = Keyword.fetch!(opts, :organization_id)
    client = Keyword.fetch!(opts, :client)

    with {:ok,
          %{
            "account_id" => subject,
            "organization_id" => ^organization_id,
            "state" => "active",
            "role" => "admin"
          }} <- client.fetch_membership(access_token, organization_id, opts),
         true <- is_binary(subject) and byte_size(subject) > 0 do
      {:ok,
       %{
         subject: subject,
         claims: %{"organization_id" => organization_id, "role" => "admin"},
         continuity: :initial
       }}
    else
      _ -> {:error, :invalid_identity}
    end
  end
end

verifier =
  {OrganizationAdminVerifier,
   client: OrganizationClient, organization_id: organization_id}

with {:ok, _identity} <-
       Tango.verify_authorization(handle, tenant_id, verifier,
         provider: provider_slug,
         intent_reference: intent
       ) do
  Ecto.Multi.new()
  |> Tango.Authorization.multi_consume_authorization(:proof, handle, tenant_id,
    provider: provider_slug,
    intent_reference: intent,
    required_scopes: ["records.read"]
  )
  |> Ecto.Multi.run(:onboarding, fn repo, %{proof: proof} ->
    OrganizationOnboarding.insert_verified(repo, tenant_id, proof)
  end)
  |> MyApp.Repo.transaction()
end
```

`OrganizationOnboarding.insert_verified/3` performs the host revalidation described
above. The executable synthetic example in `authorization_consume_test.exs` uses
the same verifier logic with Bypass, and rejects inactive administrators and
active non-administrators. No provider-specific behavior is built into Tango.

### Consume result and errors

The named Multi step returns exactly five keys:

```elixir
%{
  provider: provider_slug,
  subject: verified_subject,
  claims: safe_claims,
  granted_scopes: granted_scopes,
  intent_reference: intent
}
```

There is no connection, credential, raw provider data, or completion handle in
this proof. The preceding `Tango.verify_authorization/4` result remains a
verification summary with these five identity fields plus
`expected_connection_id` and `has_refresh_token`; consume mode does not change
that summary's shape. Use the committed proof for host writes.

`multi_consume_authorization/5` returns an `Ecto.Multi`, not a standalone proof.
With the example's step name, `Repo.transaction/1` returns
`{:ok, results}` on success (`results.proof` is the proof) or
`{:error, :proof, reason, changes_so_far}` on consume failure. A later host step
failure uses that step's name. Run the transaction on the configured Tango Repo.
Only `provider`, `intent_reference`, and optional `required_scopes` are accepted.
Provider and intent are required nonempty strings; scopes default to `[]` and
must be a list of valid nonblank scope strings. Connection/refresh options,
`completion_mode`, `expected_subject`, and all other options are rejected even
when their values are nil or false.

Consume errors are:

- `:repo_mismatch`: transaction Repo differs from the configured Tango Repo.
- `:invalid_completion_options`: malformed options or unsupported keys.
- `:invalid_scopes`: malformed scope list.
- `:invalid_completion`: malformed, unknown, or cross-tenant handle; missing
  required provider/intent; wrong provider; or inactive provider.
- `:completion_mode_mismatch`: wrong completion API or altered session/candidate
  mode or bindings. It does not consume the candidate.
- `:intent_mismatch`: intent does not match the staged candidate.
- `:client_changed`: the provider's OAuth client changed.
- `:completion_consumed`: a handle was already consumed. After cleanup removes
  its row, replay can return `:invalid_completion` instead.
- `:expired_completion`: the candidate expired.
- `:verification_required`: no verified subject is stored.
- `:token_expired`: the staged token expired.
- `:account_mismatch`: the verified subject differs from the bound subject.
- `:missing_scopes`: granted scopes do not cover the required scopes.

Concurrent completion permits one committed consume; another attempt returns
`:completion_consumed` while the row remains. Existing unrelated credential
connections are neither replaced nor blockers. Connection finalization rejects
consume candidates and consumption rejects connection candidates.

Verification is point-in-time and proves only the verifier's actual checks. It
does not certify fresh password entry, MFA, future membership, or continuing
access. Consume mode retains no credentials for refresh or background import.
Nango catalog compatibility covers configuration and OAuth transport; retention
is a host-selected Tango lifecycle. There is no documented equivalent Nango
consume API.

## Browser: consume the completion handle

The callback page posts exactly one of these messages to the session's
completion origin:

```javascript
{ type: "oauth_complete", completion_handle: "...", intent_reference: "..." }
{ type: "oauth_error", error: "access_denied", intent_reference: "..." }
```

With `Tango.Live.OAuthComponent` and the `TangoOAuth` hook, validation and
forwarding are built in. Your LiveView receives only the handle:

```heex
<.live_component
  module={Tango.Live.OAuthComponent}
  id="example-oauth"
  provider="example"
  tenant_id={@tenant_id}
  scopes={["accounts.read", "records.write"]}
  callback_url="https://app.example.com/api/oauth/callback"
  completion_origin="https://app.example.com"
  on_connect="oauth_connected"
  on_error="oauth_error"
/>
```

```elixir
@completion_keys [:provider, :tenant_id, :completion_handle, :intent_reference]

def handle_info({"oauth_connected", %{completion_handle: handle, intent_reference: intent} = message}, socket) do
  # Reject any other key, such as a credential, before doing any work.
  # tenant_id comes from the socket, never from the message.
  with true <- Enum.all?(Map.keys(message), &(&1 in @completion_keys)),
       {:ok, _connection, _link} <-
         MyApp.Integrations.complete(handle, intent, socket.assigns.tenant_id) do
    {:noreply, assign(socket, :connected, true)}
  else
    _error -> {:noreply, put_flash(socket, :error, "Could not verify the connection")}
  end
end
```

Reject any other shape. A message that includes `access_token` (or any
credential) is a 0.1.x payload and must connect nothing.

Without LiveView, accept the message only from the popup you opened and from
the exact origin of your Tango callback page, then post the handle to your own
authenticated endpoint:

```javascript
window.addEventListener("message", async (event) => {
  if (event.source !== popup) return;
  if (event.origin !== CALLBACK_ORIGIN) return;

  const data = event.data;
  if (!data || data.intent_reference !== pendingIntent) return;

  if (data.type === "oauth_complete" && typeof data.completion_handle === "string") {
    await fetch("/integrations/complete", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: JSON.stringify({
        completion_handle: data.completion_handle,
        intent_reference: data.intent_reference
      })
    });
  }
});
```

## Token retention policy

- Tango stores access and refresh tokens only in encrypted columns (AES-GCM). A candidate in `tango_authorizations` lives at most ten minutes and its handle is stored only as a SHA-256 hash.
- Candidate access and refresh token columns are set to `NULL` and `provider_data`
  to `%{}` in the same transaction as finalization or consumption, and again by
  cleanup before the row is deleted. Safe identity fields remain until cleanup.
  This erases live application records, not backups/WAL, and does not guarantee
  memory zeroization. Local erasure is distinct from provider-side revocation;
  consume mode does not revoke the provider authorization.
- The verifier sees the candidate's access token for the duration of one call. Do not store it, log it, or include it in claims.
- Ecto SQL logs and telemetry metadata for Tango's token writes carry an opaque placeholder, not the token. Audit rows never contain tokens, codes, provider bodies, raw state, or the completion handle.
- The `connection` returned by `multi_finalize_authorization/5` holds usable plaintext tokens. Persist only `connection.id` and the identity summary in your own tables. Do not copy tokens into your records, job arguments, logs, error reports, or browser responses.
- Read credentials when you call the provider with `Tango.get_active_connection(connection_id, tenant_id, auto_refresh: true)`. A missing or inactive generation is `{:error, :not_found}`. A refresh that cannot fall back to an active, unexpired token is `{:error, {:refresh_failed, reason}}`, where `reason` is a `Tango.RefreshError` term. Put `Tango.RefreshError.to_storage/1` in logs and JSON. Do not treat a stored `last_refresh_failure` string as proof of `invalid_grant`. `Tango.refresh_connection/1` returns the bare `{:error, reason}`.
- Recheck an existing connection's identity with `Tango.verify_connection_identity(connection_id, tenant_id, {MyApp.ExampleVerifier, []})`.

## Cleanup

Tango starts no scheduler. Run both cleanup functions from your own job runner
(Oban, Quantum, a timer process, and so on), authorizations first, so candidate
credentials are wiped before their sessions are deleted:

```elixir
def perform(_job) do
  {:ok, _candidates} = Tango.cleanup_expired_authorizations()
  {:ok, _sessions} = Tango.cleanup_expired_sessions()
  :ok
end
```

Both return `{:ok, deleted_count}`. Every few minutes keeps the candidate table small.

## Exact origin setup

List every page origin that may host the connect button. Tango compares the
configured string exactly, so a session whose `completion_origin` is not listed
fails with `{:error, :invalid_completion_origin}`:

```elixir
# config/runtime.exs
config :tango,
  allowed_completion_origins: ["https://app.example.com"]
```

- An origin is `scheme://host[:port]`: no path, query, fragment, user info, or wildcard.
- `https` is required. `http` is accepted only for `localhost` and loopback hosts, which keeps local development working.
- The callback page posts to this origin only. Without an allowed origin it posts nothing.
- `completion_origin` is the origin of the page that hosts the button, which may differ from the origin serving Tango's `/callback`. The hook checks `event.origin` against the callback origin and `event.source` against the popup it opened.

## Migrating a 0.1.x callback to 0.2.0

1. Update the dependency to `{:tango, "~> 0.2.0"}`, run `mix deps.update tango`, and apply the [V03 migration](SETUP.md#upgrading-an-existing-install).
2. Configure `allowed_completion_origins` and pass `completion_origin` to `Tango.Live.OAuthComponent` (now required). Register the `TangoOAuth` hook from the updated `assets/tango_oauth_hook.js`.
3. Change the `on_connect` handler. 0.1.x delivered a token and connection details to the browser and parent. 0.2.0 delivers `%{provider, tenant_id, completion_handle, intent_reference}`. Call your server-side verify and finalize flow, using the tenant from your own session.
4. Replace any custom JavaScript that read `connection` or token fields from the `oauth_complete` message. Read `completion_handle` and `intent_reference`, check `event.origin` and `event.source`, and send the handle to an authenticated endpoint.
5. Remove code that copied tokens from the browser or logged callback payloads. Credentials no longer arrive there.
6. Expect these behavior changes:
   - The popup `/callback` stages only. It completes sessions created with `Tango.create_authorization_session/3`, not direct-flow sessions from `Tango.create_session/3`.
   - `POST /exchange` ignores `include_token`, never returns credentials, and rejects staged sessions. Staged sessions cannot be completed by `Tango.exchange_code/4` either.
   - `Tango.exchange_code/4` returns `{:oauth_error, category}` instead of a raw `%OAuth2.Response{}` on provider errors.
   - Callback audit rows store a hash of the session state and an error category, not the raw error, description, or state.
7. Schedule `Tango.cleanup_expired_authorizations/0` alongside `Tango.cleanup_expired_sessions/0`.

Direct server-side flows that use `create_session/3`, `authorize_url/2`, and
`exchange_code/4` without a browser popup keep working.

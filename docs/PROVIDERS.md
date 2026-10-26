# OAuth Providers

Providers are sourced from the [Nango catalog](https://docs.nango.dev/integrations/overview)
with pre-configured OAuth endpoints and settings.

## Mix tasks

```bash
# Show provider details from catalog
mix tango.providers.show github

# Create OAuth2 provider with single scope
mix tango.providers.create github --client-id=your_client_id --client-secret=your_secret

# Create OAuth2 provider with multiple scopes (individual --scope flags)
mix tango.providers.create microsoft \
  --client-id="your_azure_client_id" \
  --client-secret="your_azure_client_secret" \
  --scope="Calendars.Read" \
  --scope="Calendars.ReadWrite" \
  --scope="User.Read" \
  --scope="offline_access"

# Create OAuth2 provider with comma-separated scopes
mix tango.providers.create google \
  --client-id="your_google_client_id" \
  --client-secret="your_google_client_secret" \
  --scopes="https://www.googleapis.com/auth/calendar,https://www.googleapis.com/auth/userinfo.email"

# Refresh configured providers from the catalog (see "Syncing" below)
mix tango.providers.sync --dry-run --force --update-metadata
```

## Supported catalog entries

Tango implements the OAuth2 authorization-code flow only, so it supports a
subset of the Nango catalog:

- **OAUTH2 only.** Entries with any other `auth_mode` (`API_KEY`, `BASIC`,
  `APP`, `OAUTH2_CC`, `OAUTH1`, `MCP_OAUTH2`, `JWT`, ...) are rejected when the
  provider is created, with an `auth_mode ... is not supported` error.
  `mix tango.providers.create --api-key=...` is rejected too, and
  `Tango.Provider.create_provider/1` rejects an `api_key` attribute or an
  `"api_key"` entry in `config`, so an API key is never silently dropped or
  stored in plaintext.
- **Aliases are resolved.** Entries such as `google-calendar`, `google-mail`,
  `outlook`, `microsoft-teams` or `zoho-crm` only name a parent with
  `alias:`. `Tango.Catalog` merges the parent's config under the entry's own
  keys (a shallow merge, as Nango does), so they get the parent's URLs, auth
  mode, scopes and params. An alias can switch auth mode: `github-app` is an
  `APP` entry and is rejected.
- **Connection configuration is not supported.** Nango fills
  `${connectionConfig.*}` placeholders per connection; Tango has one set of
  URLs per provider. For `a || b` templates Tango uses the alternative Nango
  uses when no connection configuration is given (the `b` side), so
  `salesforce` uses `https://login.salesforce.com/...`. URLs that still need a
  placeholder (for example a customer subdomain) make creation fail with
  `requires connection configuration, which Tango does not support` unless you
  pass the URLs explicitly:

  ```bash
  mix tango.providers.create zendesk --client-id=xxx --client-secret=yyy \
    --auth-url=https://acme.zendesk.com/oauth/authorizations/new \
    --token-url=https://acme.zendesk.com/oauth/tokens
  ```

  Entries whose `authorization_params`, `token_params` or `refresh_params`
  need connection configuration are rejected; URL overrides do not help there.

### Catalog options Tango honors

These are recorded in the provider's `metadata` when it is created (and by
`sync --update-metadata`), with Nango's defaults when the catalog omits them:

| Catalog field                      | Effect in Tango                                                                                                                                       |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `default_scopes`                   | Provider `default_scopes` (unless you pass scopes)                                                                                                    |
| `scope_separator`                  | Joins scopes in the authorization URL (default `" "`)                                                                                                 |
| `authorization_params`             | Extra authorization URL params (`metadata["auth_params"]`)                                                                                            |
| `disable_pkce`                     | No `code_challenge` on the authorization URL and no `code_verifier` on the exchange                                                                   |
| `token_request_auth_method: basic` | Client credentials in the Basic header and in the token request body                                                                                  |
| `authorization_method: header`     | Client credentials only in the Basic header                                                                                                           |
| `authorization_method: body`       | Client credentials only in the request body, for both code exchange and refresh; with `token_request_auth_method: basic` the Basic header is kept too |
| `body_format: json`                | Code exchange and refresh bodies are JSON instead of a form                                                                                           |
| `token_params`                     | Extra code-exchange params; also sent on refresh when there are no `refresh_params`                                                                   |
| `refresh_params`                   | Extra refresh params                                                                                                                                  |
| `token_response_metadata`          | Scalar token-response fields (dotted paths allowed) kept as `provider_data` on the staged candidate and passed to the verifier                        |

The catalog's `grant_type` values are not sent as extra params; Tango always
uses `authorization_code` for the exchange and `refresh_token` for refresh.

Without these options (and for providers created by hand) the token requests
keep Tango's default: client credentials in a Basic header plus `client_id` in
the code-exchange body, form-encoded. Nango's default puts both credentials in
the body instead; select `authorization_method: body` explicitly when the
provider requires body-only authentication.

Not supported: `refresh_url` (Nango uses it only for a few providers with
custom clients), `token_url` objects keyed by auth mode,
`authorization_url_skip_encode`, `authorization_url_replacements`,
`authorization_url_fragment`, and
`alternate_access_token_response_path` (Slack user tokens).

### Token-response metadata

Some providers return account details next to the token, such as Salesforce's
`instance_url` or Slack's `team.id`. List the fields to keep in
`token_response_metadata`:

```elixir
metadata: %{"token_response_metadata" => ["instance_url"]}
# or, for a nested field, a dotted path
metadata: %{"token_response_metadata" => ["team.id"]}
```

When a staged authorization is created, Tango reads the listed fields from the
token response and stores them on the candidate as `provider_data`, a map keyed
by the configured names (dotted paths stay as the dotted key, for example
`%{"team.id" => "T012AB3C4"}`). Retention rules:

- Only scalar values (string, number, boolean) are kept. Absent, `null` and
  nested map or list values are skipped without an error, so `provider_data` can
  be `%{}`.
- Secret-like field names (as decided by `Tango.Validation.sensitive_key?/1`,
  for example names containing `secret`, `token`, `password`, `signature`,
  `assertion`, `jwt` or `nonce`) are never retained, even if listed. The standard token fields `access_token`,
  `refresh_token`, `expires_in` and `token_type` are consumed by the OAuth
  client first and can never be retained.
- The encoded `provider_data` may not exceed 4 KiB. A larger result fails the
  exchange with `{:error, :invalid_grant_metadata}`.
- `token_response_metadata` must be a list of non-blank strings; provider
  configuration rejects anything else.

Your `Tango.AuthorizationVerifier` receives the data with the credential:
`%{access_token: token, granted_scopes: scopes, provider_data: data}`. A
verifier can, for example, check Slack's `team.id` against the workspace the
tenant expects before returning its verified subject.

`provider_data` lives only on the staged candidate. Tango resets it to `%{}`
when the candidate is consumed or expired, and it is never copied to the
connection. `verify_connection_identity/3` runs against an existing connection,
so its credential always carries `provider_data: %{}`.

### Body client authentication

By default Tango sends client credentials in a Basic header and `client_id` in
the code-exchange body. For providers that require credentials in the POST body
only, set Nango's `authorization_method`:

```elixir
metadata: %{"authorization_method" => "body"}
```

`client_id` and `client_secret` are then sent in the request body without an
`Authorization` header, on both code exchange and refresh, as a form or as JSON
when `body_format` is `"json"`. If `"token_request_auth_method" => "basic"` is
also set, the Basic header is sent as well. Valid values for
`authorization_method` are `"header"` and `"body"`. Set `"disable_pkce" => true`
only when the provider does not support PKCE. Authorization code exchanges are
not retried.

## Syncing

`mix tango.providers.sync` never creates providers: a provider is only usable
once it has OAuth credentials, so catalog entries you have not configured are
listed with a hint to run `mix tango.providers.create`. Existing providers
(active or inactive) are matched to catalog entries by `slug`.

- No flags: report only; nothing is written.
- `--force`: merge the catalog `auth_url`, `token_url` and `auth_mode` into the
  existing `config`. `client_id`, custom config keys, `client_secret`,
  `default_scopes` and `active` are kept. Catalog values that are missing or
  templated (`${...}` placeholders, including `a || b` fallbacks) are skipped,
  so a URL you resolved or overrode locally is never replaced.
- `--update-metadata`: set `name` from the catalog display name and merge the
  catalog categories, docs URL, proxy config and the request options above
  into `metadata`.
- `--only github,slack` limits the run to those slugs; `--dry-run` previews.

## Programmatic creation

```elixir
# OAuth2 provider using catalog configuration (aliases already resolved)
{:ok, nango_config} = Tango.Catalog.get_provider("github")

{:ok, provider} =
  Tango.Provider.create_provider_from_nango("github", nango_config,
    client_id: "your_github_client_id",
    client_secret: "your_github_client_secret",
    default_scopes: ["user:email", "repo"]
  )

# Catalog entry whose URLs need connection configuration
{:ok, nango_config} = Tango.Catalog.get_provider("zendesk")

{:ok, provider} =
  Tango.Provider.create_provider_from_nango("zendesk", nango_config,
    client_id: "your_client_id",
    client_secret: "your_client_secret",
    auth_url: "https://acme.zendesk.com/oauth/authorizations/new",
    token_url: "https://acme.zendesk.com/oauth/tokens"
  )

# Custom provider without catalog
{:ok, provider} = Tango.Provider.create_provider(%{
  name: "Custom API",
  slug: "custom_api",
  client_secret: "your_client_secret",
  config: %{
    "client_id" => "your_client_id",
    "auth_url" => "https://api.example.com/oauth/authorize",
    "token_url" => "https://api.example.com/oauth/token",
    "auth_mode" => "OAUTH2"
  },
  default_scopes: ["read", "write"],
  active: true
})
```

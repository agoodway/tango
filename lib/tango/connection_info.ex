defmodule Tango.ConnectionInfo do
  @moduledoc """
  Credential-free view of a stored OAuth connection.

  Carries identity and lifecycle fields only. Omits tokens, client secrets,
  raw provider payloads, provider configuration, and retry state. A read does
  not refresh tokens or take locks, and an `:active` status does not promise
  the access token is still usable or unchanged.
  """

  @enforce_keys [:id, :tenant_id, :provider_slug, :status]
  defstruct [
    :id,
    :tenant_id,
    :provider_slug,
    :status,
    :account_subject,
    :granted_scopes,
    :expires_at
  ]

  @type status :: :active | :expired | :revoked

  @type t :: %__MODULE__{
          id: integer(),
          tenant_id: String.t(),
          provider_slug: String.t(),
          status: status(),
          account_subject: String.t() | nil,
          granted_scopes: [String.t()] | nil,
          expires_at: DateTime.t() | nil
        }
end

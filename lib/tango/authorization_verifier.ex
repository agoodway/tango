defmodule Tango.AuthorizationVerifier do
  @moduledoc """
  Verifies the identity represented by an ephemeral OAuth credential.

  Implementations run on the trusted server. Returned claims must be a small,
  JSON-compatible map containing only identity fields safe for consumers.

  Consume-mode candidates use `continuity: :initial` because they do not replace
  a stored connection. Tango independently checks any expected subject bound to
  the session against the verified subject. Both connection and consume modes use
  this same verifier contract; the host selects the verifier and its options.

  Verification is point-in-time: it proves only the checks the verifier performs,
  not fresh password entry, MFA, future membership, or continuing authorization.
  Make bounded, read-only provider calls outside the host transaction. Host writes
  must revalidate actor permissions and operation freshness in the transaction
  that finalizes or consumes the authorization. Never retain or log credentials.

  The credential carries the access token, the granted scopes, and
  `provider_data`: the token response fields the provider's
  `"token_response_metadata"` retains (see `Tango.TokenResponseMetadata`), for
  example `%{"instance_url" => "https://example.my.salesforce.com"}`. Retained
  fields must be explicitly allowlisted non-secret identity attributes. A key
  without the word token is not automatically safe; the host owns this review.
  These fields exist only while the authorization candidate is staged, so
  `Tango.verify_connection_identity/3` always passes `provider_data: %{}`.
  """

  alias Tango.Schemas.Provider

  @type credential :: %{
          access_token: String.t(),
          granted_scopes: [String.t()],
          provider_data: map()
        }
  @type continuity :: :initial | {:connection, pos_integer()}
  @type verification :: %{
          subject: String.t(),
          claims: map(),
          continuity: continuity()
        }

  @callback verify(Provider.t(), credential(), keyword()) ::
              {:ok, verification()} | {:error, atom()}
end

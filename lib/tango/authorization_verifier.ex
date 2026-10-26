defmodule Tango.AuthorizationVerifier do
  @moduledoc """
  Verifies the identity represented by an ephemeral OAuth credential.

  Implementations run on the trusted server. Returned claims must be a small,
  JSON-compatible map containing only identity fields safe for consumers.

  The credential carries the access token, the granted scopes, and
  `provider_data`: the token response fields the provider's
  `"token_response_metadata"` retains (see `Tango.TokenResponseMetadata`), for
  example `%{"instance_url" => "https://example.my.salesforce.com"}`. Retained
  fields exist only while the authorization candidate is staged, so
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

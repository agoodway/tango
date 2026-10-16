defmodule Tango.AuthorizationVerifier do
  @moduledoc """
  Verifies the identity represented by an ephemeral OAuth credential.

  Implementations run on the trusted server. Returned claims must be a small,
  JSON-compatible map containing only identity fields safe for consumers.
  """

  alias Tango.Schemas.Provider

  @type credential :: %{access_token: String.t(), granted_scopes: [String.t()]}
  @type continuity :: :initial | {:connection, pos_integer()}
  @type verification :: %{
          subject: String.t(),
          claims: map(),
          continuity: continuity()
        }

  @callback verify(Provider.t(), credential(), keyword()) ::
              {:ok, verification()} | {:error, atom()}
end

defmodule Tango.Schemas.Authorization do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  @type t :: %__MODULE__{
          id: integer() | nil,
          provider_id: integer() | nil,
          provider: Tango.Schemas.Provider.t() | Ecto.Association.NotLoaded.t() | nil,
          oauth_session_id: integer() | nil,
          oauth_session: Tango.Schemas.OAuthSession.t() | Ecto.Association.NotLoaded.t() | nil,
          tenant_id: String.t() | nil,
          handle_hash: binary() | nil,
          access_token: String.t() | nil,
          refresh_token: String.t() | nil,
          token_type: String.t() | nil,
          token_expires_at: DateTime.t() | nil,
          granted_scopes: [String.t()],
          completion_mode: :connection | :consume,
          expected_connection_id: integer() | nil,
          expected_subject: String.t() | nil,
          oauth_client_id: String.t() | nil,
          intent_reference: String.t() | nil,
          completion_origin: String.t() | nil,
          account_subject: String.t() | nil,
          identity_claims: map(),
          provider_data: map(),
          verified_connection_id: integer() | nil,
          verified_at: DateTime.t() | nil,
          expires_at: DateTime.t() | nil,
          consumed_at: DateTime.t() | nil,
          inserted_at: NaiveDateTime.t() | nil,
          updated_at: NaiveDateTime.t() | nil
        }

  @primary_key {:id, :id, autogenerate: true}
  @foreign_key_type :id
  @schema_prefix Application.compile_env(:tango, :schema_prefix, nil)

  @fields [
    :provider_id,
    :oauth_session_id,
    :tenant_id,
    :handle_hash,
    :access_token,
    :refresh_token,
    :token_type,
    :token_expires_at,
    :granted_scopes,
    :completion_mode,
    :expected_connection_id,
    :expected_subject,
    :oauth_client_id,
    :intent_reference,
    :completion_origin,
    :account_subject,
    :identity_claims,
    :provider_data,
    :verified_connection_id,
    :verified_at,
    :expires_at,
    :consumed_at
  ]

  @required_fields [
    :completion_mode,
    :provider_id,
    :oauth_session_id,
    :tenant_id,
    :handle_hash,
    :oauth_client_id,
    :intent_reference,
    :completion_origin,
    :expires_at
  ]

  schema "tango_authorizations" do
    belongs_to(:provider, Tango.Schemas.Provider)
    belongs_to(:oauth_session, Tango.Schemas.OAuthSession)
    field(:tenant_id, :string)
    field(:handle_hash, :binary)
    field(:access_token, Tango.Types.EncryptedBinary, redact: true)
    field(:refresh_token, Tango.Types.EncryptedBinary, redact: true)
    field(:token_type, :string)
    field(:token_expires_at, :utc_datetime)
    field(:granted_scopes, {:array, :string}, default: [])
    field(:completion_mode, Ecto.Enum, values: [:connection, :consume], default: :connection)
    field(:expected_connection_id, :integer)
    field(:expected_subject, :string)
    field(:oauth_client_id, :string)
    field(:intent_reference, :string)
    field(:completion_origin, :string)
    field(:account_subject, :string)
    field(:identity_claims, :map, default: %{})
    field(:provider_data, :map, default: %{})
    field(:verified_connection_id, :integer)
    field(:verified_at, :utc_datetime)
    field(:expires_at, :utc_datetime)
    field(:consumed_at, :utc_datetime)

    timestamps()
  end

  @doc false
  def changeset(authorization, attrs) do
    authorization
    |> cast(attrs, @fields)
    |> validate_required(@required_fields)
    |> validate_length(:tenant_id, min: 1)
    |> validate_length(:oauth_client_id, min: 1)
    |> validate_length(:intent_reference, min: 1)
    |> validate_length(:completion_origin, min: 1)
    |> validate_length(:handle_hash,
      is: 32,
      count: :bytes,
      message: "must be a 32-byte SHA-256 digest"
    )
    |> foreign_key_constraint(:provider_id)
    |> foreign_key_constraint(:oauth_session_id)
    |> unique_constraint(:oauth_session_id)
    |> unique_constraint(:handle_hash)
    |> check_constraint(:completion_mode,
      name: :tango_authorizations_completion_mode_check,
      message: "must be connection or consume"
    )
    |> check_constraint(:completion_mode,
      name: :tango_authorizations_consume_connection_check,
      message: "must not bind a connection in consume mode"
    )
    |> check_constraint(:access_token,
      name: :tango_authorizations_unconsumed_access_token_check,
      message: "must be present until the authorization is consumed"
    )
    |> check_constraint(:provider_data,
      name: :tango_authorizations_provider_data_check,
      message: "must be a JSON object"
    )
  end
end

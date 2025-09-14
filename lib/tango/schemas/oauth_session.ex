defmodule Tango.Schemas.OAuthSession do
  @moduledoc """
  Temporary OAuth flow sessions with PKCE support.

  Manages temporary OAuth sessions during authorization flow with CSRF protection
  and PKCE (Proof Key for Code Exchange) support for enhanced security.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @schema_prefix Application.compile_env(:tango, :schema_prefix, nil)

  @fields [
    :provider_id,
    :tenant_id,
    :session_token,
    :state,
    :code_verifier,
    :redirect_uri,
    :scopes,
    :expires_at,
    :metadata
  ]
  @required_fields [:provider_id, :tenant_id, :session_token, :state, :expires_at]

  schema "tango_oauth_sessions" do
    belongs_to(:provider, Tango.Schemas.Provider)
    field(:tenant_id, :string)
    field(:session_token, :string)
    field(:state, :string)
    field(:code_verifier, :string)
    field(:redirect_uri, :string)
    field(:scopes, {:array, :string}, default: [])
    field(:expires_at, :utc_datetime)
    field(:metadata, :map, default: %{})

    timestamps()
  end

  @doc "Creates a changeset for OAuth session creation"
  def changeset(session, attrs) do
    session
    |> cast(attrs, @fields)
    |> validate_required(@required_fields)
    |> validate_length(:session_token, min: 32)
    |> validate_length(:state, min: 32)
    |> validate_length(:code_verifier, min: 43, max: 128)
    |> unique_constraint(:session_token)
    |> foreign_key_constraint(:provider_id)
    |> validate_expires_at()
  end

  @doc "Creates new OAuth session with PKCE support"
  def create_session(provider_id, tenant_id, opts \\ []) do
    session_token = generate_session_token()
    state = generate_state_token()
    code_verifier = generate_code_verifier()
    expires_at = DateTime.add(DateTime.utc_now(), session_timeout(), :second)

    attrs = %{
      provider_id: provider_id,
      tenant_id: tenant_id,
      session_token: session_token,
      state: state,
      code_verifier: code_verifier,
      redirect_uri: opts[:redirect_uri],
      scopes: opts[:scopes] || [],
      expires_at: expires_at,
      metadata: build_session_metadata(opts)
    }

    %__MODULE__{}
    |> changeset(attrs)
  end

  @doc "Generates PKCE code challenge from verifier"
  def generate_code_challenge(%__MODULE__{code_verifier: code_verifier})
      when is_binary(code_verifier) do
    :crypto.hash(:sha256, code_verifier)
    |> Base.url_encode64(padding: false)
  end

  def generate_code_challenge(_), do: nil

  @doc "Validates OAuth state parameter"
  def validate_state(%__MODULE__{state: expected_state}, received_state) do
    if Plug.Crypto.secure_compare(expected_state, received_state) do
      :ok
    else
      {:error, :invalid_state}
    end
  end

  @doc "Checks if session is expired"
  def expired?(%__MODULE__{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) != :lt
  end

  @doc "Checks if session is valid for use"
  def valid?(%__MODULE__{} = session) do
    not expired?(session)
  end

  defp validate_expires_at(changeset) do
    case get_field(changeset, :expires_at) do
      nil ->
        changeset

      expires_at ->
        if DateTime.compare(expires_at, DateTime.utc_now()) == :gt do
          changeset
        else
          add_error(changeset, :expires_at, "must be in the future")
        end
    end
  end

  defp generate_session_token do
    :crypto.strong_rand_bytes(32)
    |> Base.url_encode64(padding: false)
  end

  defp generate_state_token do
    # Generate 24 bytes to ensure 32+ characters after Base64 encoding
    :crypto.strong_rand_bytes(24)
    |> Base.url_encode64(padding: false)
  end

  defp generate_code_verifier do
    # PKCE code verifier: 43-128 URL-safe characters
    :crypto.strong_rand_bytes(64)
    |> Base.url_encode64(padding: false)
  end

  defp session_timeout do
    # Default 30 minutes
    Application.get_env(:tango, :session_timeout, 30 * 60)
  end

  defp build_session_metadata(opts) do
    opts
    |> Keyword.take([:scopes, :redirect_uri, :ip_address, :user_agent])
    |> Enum.into(%{})
    |> Map.put(:created_at, DateTime.utc_now())
  end
end

defmodule Tango.Schemas.Provider do
  @moduledoc """
  OAuth provider configuration schema.

  Manages OAuth provider configurations with support for Nango-compatible templates.
  Supports OAuth2 and API key authentication modes with flexible configuration.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @type t :: %__MODULE__{
          id: integer() | nil,
          slug: String.t() | nil,
          name: String.t() | nil,
          config: map(),
          client_secret: binary() | nil,
          default_scopes: [String.t()],
          active: boolean(),
          metadata: map(),
          connections: [Tango.Schemas.Connection.t()] | Ecto.Association.NotLoaded.t(),
          oauth_sessions: [Tango.Schemas.OAuthSession.t()] | Ecto.Association.NotLoaded.t(),
          inserted_at: NaiveDateTime.t() | nil,
          updated_at: NaiveDateTime.t() | nil
        }

  @primary_key {:id, :id, autogenerate: true}
  @foreign_key_type :id
  @schema_prefix Application.compile_env(:tango, :schema_prefix, nil)

  @fields [:slug, :name, :config, :client_secret, :default_scopes, :active, :metadata]

  schema "tango_providers" do
    field(:slug, :string)
    field(:name, :string)
    field(:config, :map, default: %{})
    field(:client_secret, Tango.Types.EncryptedBinary)
    field(:default_scopes, {:array, :string}, default: [])
    field(:active, :boolean, default: true)
    field(:metadata, :map, default: %{})

    has_many(:connections, Tango.Schemas.Connection)
    has_many(:oauth_sessions, Tango.Schemas.OAuthSession)

    timestamps()
  end

  @doc "Creates a changeset for provider configuration"
  def changeset(provider, attrs) do
    provider
    |> cast(attrs, @fields)
    |> validate_required([:slug, :name, :client_secret])
    |> validate_length(:slug, min: 1, max: 255)
    |> validate_length(:name, min: 1, max: 255)
    |> unique_constraint(:slug)
    |> validate_config()
  end

  @doc "Gets configuration map"
  def get_config(%__MODULE__{config: config}) when is_map(config), do: {:ok, config}
  def get_config(%__MODULE__{config: nil}), do: {:ok, %{}}
  def get_config(_), do: {:error, :invalid_config}

  @doc "Gets OAuth client credentials from provider config"
  def get_oauth_credentials(%__MODULE__{client_secret: client_secret} = provider) do
    case get_config(provider) do
      {:ok, config} ->
        {:ok,
         %{
           client_id: config["client_id"],
           client_secret: client_secret,
           auth_url: config["auth_url"],
           token_url: config["token_url"],
           auth_mode: config["auth_mode"]
         }}

      error ->
        error
    end
  end

  @doc "Creates provider from Nango-compatible configuration"
  def from_nango_config(name, nango_config, opts \\ []) do
    {config, client_secret} = build_provider_config(nango_config, opts)

    attrs = %{
      slug: name,
      name: nango_config["display_name"] || name,
      config: config,
      client_secret: client_secret,
      default_scopes:
        Keyword.get(
          opts,
          :default_scopes,
          nango_config["scopes"] || nango_config["default_scopes"] || []
        ),
      active: Keyword.get(opts, :active, true),
      metadata: build_metadata(nango_config)
    }

    %__MODULE__{}
    |> changeset(attrs)
  end

  defp validate_config(changeset) do
    case get_field(changeset, :config) do
      config when is_map(config) -> validate_config_map(changeset, config)
      nil -> changeset
      _ -> add_error(changeset, :config, "must be a map")
    end
  end

  defp validate_config_map(changeset, %{
         "client_id" => id,
         "auth_url" => auth,
         "token_url" => token
       })
       when is_binary(id) and is_binary(auth) and is_binary(token),
       do: changeset

  defp validate_config_map(changeset, %{"auth_mode" => mode}) when mode != "OAUTH2",
    do: changeset

  defp validate_config_map(changeset, %{"client_id" => _, "auth_url" => _, "token_url" => _}) do
    add_error(changeset, :config, "client_id, auth_url, and token_url must be non-nil strings")
  end

  defp validate_config_map(changeset, _config) do
    add_error(changeset, :config, "must contain client_id, auth_url, and token_url")
  end

  defp build_provider_config(nango_config, opts) do
    config = %{
      "client_id" => Keyword.get(opts, :client_id),
      "auth_url" => nango_config["authorization_url"],
      "token_url" => nango_config["token_url"],
      "auth_mode" => nango_config["auth_mode"] || "OAUTH2"
    }

    client_secret = Keyword.get(opts, :client_secret)

    {config, client_secret}
  end

  defp build_metadata(nango_config) do
    %{
      "categories" => nango_config["categories"] || [],
      "docs_url" => nango_config["docs"],
      "auth_params" => nango_config["authorization_params"] || %{},
      "proxy_config" => nango_config["proxy"] || %{}
    }
  end
end

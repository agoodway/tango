defmodule Tango.Schemas.Provider do
  @moduledoc """
  OAuth provider configuration schema.

  Manages OAuth2 provider configurations with support for Nango-compatible templates.

  Tango only implements the OAuth2 authorization-code flow. API-key providers are
  not supported: an `api_key` attribute (or an `"api_key"` entry in `config`) is
  rejected rather than silently dropped or stored in plaintext.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias Tango.Catalog

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

  @api_key_unsupported "API key providers are not supported; Tango only supports OAuth2 providers"

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
    |> validate_metadata()
    |> reject_api_key(attrs)
  end

  defp reject_api_key(changeset, attrs) when is_map(attrs) do
    if Map.has_key?(attrs, :api_key) or Map.has_key?(attrs, "api_key") do
      add_error(changeset, :api_key, @api_key_unsupported)
    else
      changeset
    end
  end

  defp reject_api_key(changeset, _attrs), do: changeset

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

  @doc """
  Creates a provider changeset from a Nango catalog entry (with `alias:`
  already resolved, as `Tango.Catalog` returns it).

  Only `OAUTH2` entries are accepted. `a || b` URL templates use the
  alternative Nango uses without connection configuration; URLs or request
  params that still need `${connectionConfig.*}` values are rejected unless
  explicit URLs are given.

  ## Options

    * `:client_id`, `:client_secret` - OAuth client credentials
    * `:default_scopes` - overrides the catalog's default scopes
    * `:active` - defaults to `true`
    * `:auth_url`, `:token_url` - override the catalog URLs, e.g. for
      providers whose URLs need a customer-specific hostname
  """
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
      metadata: catalog_metadata(nango_config)
    }

    # Pass a supplied api_key through so the changeset rejects it loudly.
    attrs =
      if Keyword.has_key?(opts, :api_key),
        do: Map.put(attrs, :api_key, opts[:api_key]),
        else: attrs

    %__MODULE__{}
    |> changeset(attrs)
  end

  defp validate_config(changeset) do
    case get_field(changeset, :config) do
      %{"api_key" => _} ->
        add_error(changeset, :config, "must not contain api_key; #{@api_key_unsupported}")

      %{api_key: _} ->
        add_error(changeset, :config, "must not contain api_key; #{@api_key_unsupported}")

      config when is_map(config) ->
        validate_config_map(changeset, config)

      nil ->
        changeset

      _ ->
        add_error(changeset, :config, "must be a map")
    end
  end

  defp validate_config_map(changeset, %{"auth_mode" => mode})
       when not is_nil(mode) and mode not in ["OAUTH2", "oauth2"] do
    add_error(
      changeset,
      :config,
      "auth_mode #{mode} is not supported; Tango only supports OAUTH2 (authorization code) providers"
    )
  end

  defp validate_config_map(changeset, %{
         "client_id" => id,
         "auth_url" => auth,
         "token_url" => token
       })
       when is_binary(id) and is_binary(auth) and is_binary(token) do
    Enum.reduce([{"auth_url", auth}, {"token_url", token}], changeset, fn {key, url}, acc ->
      if Catalog.unresolved_template?(url) do
        add_error(
          acc,
          :config,
          "#{key} requires connection configuration, which Tango does not support " <>
            "(#{url}); pass explicit auth_url/token_url overrides"
        )
      else
        acc
      end
    end)
  end

  defp validate_config_map(changeset, %{"client_id" => _, "auth_url" => _, "token_url" => _}) do
    add_error(changeset, :config, "client_id, auth_url, and token_url must be non-nil strings")
  end

  defp validate_config_map(changeset, _config) do
    add_error(changeset, :config, "must contain client_id, auth_url, and token_url")
  end

  # Request params copied from the catalog into metadata. Nango interpolates
  # these with the connection configuration, so a leftover `${...}` means the
  # provider cannot work without one.
  @templated_metadata_params ["auth_params", "token_params", "refresh_params"]

  defp validate_metadata(changeset) do
    case get_field(changeset, :metadata) do
      metadata when is_map(metadata) ->
        @templated_metadata_params
        |> Enum.filter(&templated_params?(metadata[&1]))
        |> Enum.reduce(changeset, fn key, acc ->
          add_error(
            acc,
            :metadata,
            "#{key} requires connection configuration, which Tango does not support"
          )
        end)

      _ ->
        changeset
    end
  end

  defp templated_params?(params) when is_map(params),
    do: Enum.any?(params, fn {_key, value} -> Catalog.unresolved_template?(value) end)

  defp templated_params?(_params), do: false

  defp build_provider_config(nango_config, opts) do
    endpoint_overrides =
      %{"auth_url" => opts[:auth_url], "token_url" => opts[:token_url]}
      |> Map.reject(fn {_key, value} -> is_nil(value) end)

    config =
      nango_config
      |> catalog_endpoints()
      |> Map.merge(endpoint_overrides)
      |> Map.put("client_id", Keyword.get(opts, :client_id))

    client_secret = Keyword.get(opts, :client_secret)

    {config, client_secret}
  end

  @doc """
  Returns the catalog-owned fields of a provider `config` (`auth_url`,
  `token_url`, `auth_mode`) for a Nango catalog entry.

  `a || b` URL templates are resolved with `Tango.Catalog.resolve_template/1`
  (the alternative Nango uses without connection configuration). URLs that
  still contain `${...}` placeholders are returned as-is; the changeset
  rejects them.

  Credentials (`client_id`, `client_secret`) are never part of this map.
  """
  def catalog_endpoints(nango_config) do
    %{
      "auth_url" => Catalog.resolve_template(nango_config["authorization_url"]),
      "token_url" => Catalog.resolve_template(nango_config["token_url"]),
      "auth_mode" => nango_config["auth_mode"] || "OAUTH2"
    }
  end

  @doc """
  Returns the catalog-derived provider `metadata` for a Nango catalog entry.

  Besides descriptive fields it records the request options Tango honors,
  with Nango's defaults when the catalog omits them:

    * `"scope_separator"` - joins scopes in the authorization URL (default `" "`)
    * `"disable_pkce"` - skips the PKCE challenge and verifier (default `false`)
    * `"token_request_auth_method"` - `"basic"` adds the client credentials to
      the token request body as well as the Basic header
    * `"authorization_method"` - `"header"` sends client credentials only in
      the Basic header
    * `"body_format"` - `"json"` sends token requests as JSON instead of a form
    * `"auth_params"`, `"token_params"`, `"refresh_params"` - extra request
      params for the authorization URL, code exchange, and refresh
  """
  def catalog_metadata(nango_config) do
    %{
      "categories" => nango_config["categories"] || [],
      "docs_url" => nango_config["docs"],
      "auth_params" => catalog_params(nango_config["authorization_params"]),
      "token_params" => catalog_params(nango_config["token_params"]),
      "refresh_params" => catalog_params(nango_config["refresh_params"]),
      "proxy_config" => nango_config["proxy"] || %{},
      "scope_separator" => nango_config["scope_separator"] || " ",
      "disable_pkce" => nango_config["disable_pkce"] == true,
      "token_request_auth_method" => nango_config["token_request_auth_method"],
      "authorization_method" => nango_config["authorization_method"],
      "body_format" => nango_config["body_format"]
    }
  end

  defp catalog_params(params) when is_map(params),
    do: Map.new(params, fn {key, value} -> {to_string(key), Catalog.resolve_template(value)} end)

  defp catalog_params(_params), do: %{}
end

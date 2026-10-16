defmodule Tango.Catalog do
  @moduledoc """
  Nango provider catalog integration.

  Fetches and processes provider configurations from the official Nango provider catalog
  hosted on GitHub. Provides functions to integrate with the local Tango provider database.
  """

  require Logger

  @default_nango_providers_url "https://raw.githubusercontent.com/NangoHQ/nango/master/packages/providers/providers.yaml"

  @doc """
  Gets the complete Nango provider catalog from the official GitHub repository.

  Returns a map of provider configurations parsed from the YAML file.

  ## Examples

      iex> Tango.Catalog.get_catalog()
      {:ok, %{"github" => %{...}, "google" => %{...}}}

  """
  def get_catalog do
    case fetch_yaml_content() do
      {:ok, yaml_content} ->
        case parse_yaml_content(yaml_content) do
          {:ok, providers} ->
            processed_catalog = process_providers(providers)
            {:ok, processed_catalog}

          {:error, reason} ->
            Logger.warning("Failed to parse Nango providers YAML: #{inspect(reason)}")
            {:error, :yaml_parse_error}
        end

      {:error, reason} ->
        Logger.warning("Failed to fetch Nango providers catalog: #{inspect(reason)}")
        {:error, :catalog_fetch_failed}
    end
  end

  @doc """
  Gets a specific provider configuration from the catalog.

  ## Examples

      iex> Tango.Catalog.get_provider("github")
      {:ok, %{"display_name" => "GitHub", ...}}

      iex> Tango.Catalog.get_provider("nonexistent")
      {:error, :not_found}

  """
  def get_provider(provider_name) do
    case get_catalog() do
      {:ok, catalog} ->
        case Map.get(catalog, provider_name) do
          nil -> {:error, :not_found}
          config -> {:ok, config}
        end

      error ->
        error
    end
  end

  @doc """
  Suggests similar provider names based on input.

  Uses Jaro distance and substring matching to find similar providers.

  ## Examples

      iex> Tango.Catalog.suggest_similar("git")
      ["github"]

  """
  def suggest_similar(input) do
    case get_catalog() do
      {:ok, catalog} ->
        catalog
        |> Map.keys()
        |> Enum.filter(fn name ->
          String.contains?(name, input) || String.jaro_distance(name, input) > 0.7
        end)
        |> Enum.sort_by(fn name -> String.jaro_distance(name, input) end, :desc)
        |> Enum.take(3)

      {:error, _} ->
        []
    end
  end

  defp fetch_yaml_content do
    url = Application.get_env(:tango, :nango_providers_url, @default_nango_providers_url)

    case Req.get(url,
           retry: :safe_transient,
           max_retries: 3,
           retry_delay: 1000,
           connect_options: [timeout: 10_000],
           receive_timeout: 15_000
         ) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse_yaml_content(yaml_string) do
    YamlElixir.read_from_string(yaml_string)
  end

  @doc """
  Resolves `alias:` entries the way Nango does.

  An entry such as `google-calendar: {alias: google, display_name: ...}` is
  replaced by a shallow merge of its parent's config with its own keys, so the
  child's top-level keys win and nested maps (`proxy`, `authorization_params`)
  are replaced, not merged. This mirrors `loadProvidersYaml/0` in Nango's
  `packages/providers/lib/index.ts` (`{ ...aliasData, ...overrides }`). The
  `alias` key is kept so callers can see where the config came from.

  Alias chains are followed regardless of file order. An entry whose parent is
  missing, or whose chain loops, is returned unchanged; such entries have no
  usable OAuth2 settings and are rejected when a provider is created.
  """
  def resolve_aliases(raw_providers) when is_map(raw_providers) do
    Map.new(raw_providers, fn {name, config} ->
      case resolve_alias(raw_providers, name, config, MapSet.new()) do
        {:ok, resolved} -> {name, resolved}
        :error -> {name, config}
      end
    end)
  end

  defp resolve_alias(raw_providers, name, %{"alias" => parent} = config, seen)
       when is_binary(parent) do
    seen = MapSet.put(seen, name)

    with false <- MapSet.member?(seen, parent),
         parent_config when is_map(parent_config) <- Map.get(raw_providers, parent),
         {:ok, resolved_parent} <- resolve_alias(raw_providers, parent, parent_config, seen) do
      {:ok, Map.merge(resolved_parent, config)}
    else
      _ -> :error
    end
  end

  defp resolve_alias(_raw_providers, _name, config, _seen), do: {:ok, config}

  @doc """
  Resolves a catalog template the way Nango does when a connection has no
  connection configuration.

  Nango's `interpolateStringFromObject/2` (`packages/shared/lib/utils/utils.ts`)
  splits `a || b` on the first `||` only: it keeps the left side when
  interpolating it changed it and otherwise interpolates the right side. With
  no connection configuration nothing on the left can be interpolated, so the
  right side wins. A blank right side yields `nil`.

  Strings without `||` are returned unchanged, including any `${...}`
  placeholders; see `unresolved_template?/1`. Non-strings pass through.

  ## Examples

      iex> Tango.Catalog.resolve_template("https://${connectionConfig.host}/auth || https://login.example.com/auth")
      "https://login.example.com/auth"

      iex> Tango.Catalog.resolve_template("https://example.com/auth")
      "https://example.com/auth"

  """
  def resolve_template(value) when is_binary(value) do
    case String.split(value, "||") do
      [_single] -> value
      [_left, right | _ignored] -> blank_to_nil(String.trim(right))
    end
  end

  def resolve_template(value), do: value

  defp blank_to_nil(""), do: nil
  defp blank_to_nil(value), do: value

  @doc """
  Returns true when a value still contains a `${...}` placeholder that only a
  connection configuration could fill, which Tango does not support.
  """
  def unresolved_template?(value) when is_binary(value), do: String.contains?(value, "${")
  def unresolved_template?(_value), do: false

  defp process_providers(raw_providers) when is_map(raw_providers) do
    raw_providers
    |> resolve_aliases()
    |> Enum.map(fn {provider_name, config} ->
      processed_config =
        config
        |> normalize_config()
        |> add_derived_fields(provider_name)

      {provider_name, processed_config}
    end)
    |> Map.new()
  end

  defp normalize_config(config) when is_map(config) do
    config
    |> Map.new(fn {key, value} -> {to_string(key), value} end)
    |> normalize_auth_urls()
    |> normalize_categories()
  end

  defp normalize_auth_urls(config) do
    config
    |> Map.put("auth_url", config["authorization_url"])
    |> Map.put("token_url", config["token_url"])
  end

  defp normalize_categories(config) do
    categories = config["categories"] || []
    Map.put(config, "categories", categories)
  end

  defp add_derived_fields(config, provider_name) do
    config
    |> Map.put_new("name", provider_name)
    |> Map.put_new("slug", provider_name)
    |> add_docs_url(provider_name)
  end

  defp add_docs_url(config, provider_name) do
    docs_url = config["docs"] || "https://docs.nango.dev/integrations/all/#{provider_name}"
    Map.put(config, "docs", docs_url)
  end
end

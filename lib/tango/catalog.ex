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

  # Private functions

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
    case YamlElixir.read_from_string(yaml_string) do
      {:ok, data} -> {:ok, data}
      {:error, reason} -> {:error, reason}
    end
  end

  defp process_providers(raw_providers) when is_map(raw_providers) do
    raw_providers
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

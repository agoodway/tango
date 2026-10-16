defmodule Mix.Tasks.Tango.Providers.Sync do
  @moduledoc """
  Refreshes locally configured providers from the Nango catalog.

  ## Usage

      mix tango.providers.sync [options]

  ## Options

      --only PROVIDERS      Sync only specified providers (comma-separated slugs)
      --dry-run, -n         Preview changes without applying them
      --force, -f           Merge catalog endpoints (auth_url, token_url, auth_mode)
                            into existing provider configs
      --update-metadata     Update display names and catalog metadata

  ## Examples

      mix tango.providers.sync
      mix tango.providers.sync --only github,slack
      mix tango.providers.sync --dry-run --force
      mix tango.providers.sync --force --update-metadata

  ## Behaviour

  Local providers are matched to catalog entries by `slug` (the catalog key),
  including inactive providers. Sync never creates providers: a provider is
  only usable with OAuth credentials, so catalog entries that are not yet
  configured are listed with a hint to run `mix tango.providers.create`.

  Without `--force` or `--update-metadata` nothing is written. `--force` merges
  the catalog's endpoint fields into the existing `config`, keeping
  `client_id`, any custom keys, and `client_secret` untouched; catalog values
  that are missing or templated (`${...}` placeholders, including `a || b`
  fallbacks) are skipped so resolved or overridden local URLs are not
  replaced. `alias:` entries are resolved through their parent first. `--update-metadata` sets `name` from the
  catalog display name and merges catalog metadata into `metadata`. Neither
  option changes `active`, `default_scopes`, or credentials.
  """

  use Mix.Task
  alias Mix.Shell.IO, as: Shell
  alias Mix.Tasks.Helpers.{ProviderHelper, TaskHelper}
  alias Tango.Schemas.Provider, as: ProviderSchema

  @shortdoc "Refreshes configured providers from the Nango catalog"

  @switches [
    only: :string,
    force: :boolean,
    dry_run: :boolean,
    update_metadata: :boolean
  ]

  @aliases [
    n: :dry_run,
    f: :force
  ]

  @doc "Runs the mix task."
  def run(args) do
    {opts, _args, _} = OptionParser.parse(args, switches: @switches, aliases: @aliases)

    TaskHelper.ensure_started()
    Shell.info("📡 Fetching Nango provider catalog...")

    case Tango.Catalog.get_catalog() do
      {:ok, catalog} ->
        filtered_catalog = filter_catalog(catalog, opts)
        local_providers = Tango.Provider.list_all_providers()

        changes = analyze_changes(filtered_catalog, local_providers, opts)

        Shell.info("Found #{map_size(filtered_catalog)} providers in catalog")
        Shell.info("Analyzing local database (#{length(local_providers)} providers configured)")
        Shell.info("")

        display_changes(changes, opts)

        if opts[:dry_run] do
          Shell.info("🔍 Dry run completed - no changes applied")
        else
          apply_changes(changes)
        end

      {:error, reason} ->
        Shell.error("Failed to fetch catalog: #{inspect(reason)}")
    end
  end

  defp filter_catalog(catalog, opts) do
    case opts[:only] do
      nil ->
        catalog

      only_string ->
        provider_names =
          only_string
          |> String.split(",")
          |> Enum.map(&String.trim/1)

        Map.take(catalog, provider_names)
    end
  end

  defp analyze_changes(catalog, local_providers, opts) do
    local_by_slug = Map.new(local_providers, &{&1.slug, &1})

    {configured, available} =
      catalog
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.split_with(fn {slug, _config} -> Map.has_key?(local_by_slug, slug) end)

    updates =
      configured
      |> Enum.map(fn {slug, config} ->
        local = Map.fetch!(local_by_slug, slug)
        {slug, local, build_update_attrs(config, local, opts)}
      end)
      |> Enum.reject(fn {_slug, _local, attrs} -> attrs == %{} end)

    %{
      configured: Enum.map(configured, &elem(&1, 0)),
      available: Enum.map(available, &elem(&1, 0)),
      updates: updates,
      preserved: Enum.reject(local_providers, &Map.has_key?(catalog, &1.slug))
    }
  end

  defp build_update_attrs(catalog_config, local, opts) do
    %{}
    |> maybe_merge_endpoints(catalog_config, local, opts[:force])
    |> maybe_update_metadata(catalog_config, local, opts[:update_metadata])
  end

  # Catalog fields behind each endpoint key. A templated catalog value (`${...}`,
  # including `a || b` fallbacks) is never merged: the local URL may be a
  # deliberate override such as a customer-specific hostname.
  @endpoint_sources %{"auth_url" => "authorization_url", "token_url" => "token_url"}

  defp maybe_merge_endpoints(attrs, catalog_config, local, true) do
    endpoints =
      catalog_config
      |> ProviderSchema.catalog_endpoints()
      |> Map.filter(fn {key, value} ->
        concrete_value?(value) and concrete_source?(catalog_config, key)
      end)

    merged = Map.merge(local.config || %{}, endpoints)
    put_if_changed(attrs, :config, merged, local.config)
  end

  defp maybe_merge_endpoints(attrs, _catalog_config, _local, _force), do: attrs

  defp maybe_update_metadata(attrs, catalog_config, local, true) do
    metadata = Map.merge(local.metadata || %{}, ProviderSchema.catalog_metadata(catalog_config))

    attrs
    |> put_if_changed(:metadata, metadata, local.metadata)
    |> put_name(catalog_config["display_name"], local.name)
  end

  defp maybe_update_metadata(attrs, _catalog_config, _local, _update), do: attrs

  defp put_name(attrs, name, current) when is_binary(name) and name != "",
    do: put_if_changed(attrs, :name, name, current)

  defp put_name(attrs, _name, _current), do: attrs

  defp put_if_changed(attrs, _key, value, value), do: attrs
  defp put_if_changed(attrs, key, value, _current), do: Map.put(attrs, key, value)

  defp concrete_source?(catalog_config, key) do
    case Map.fetch(@endpoint_sources, key) do
      {:ok, source} -> concrete_value?(catalog_config[source])
      :error -> true
    end
  end

  defp concrete_value?(value) when is_binary(value), do: not String.contains?(value, "${")
  defp concrete_value?(_value), do: false

  defp display_changes(changes, opts) do
    if changes.available != [] do
      Shell.info(
        "#{length(changes.available)} catalog providers are not configured (sync does not create providers)."
      )

      if opts[:only], do: Enum.each(changes.available, &Shell.info("   - #{&1}"))

      Shell.info(
        "   Configure one with: mix tango.providers.create <name> --client-id=xxx --client-secret=yyy"
      )

      Shell.info("")
    end

    if changes.updates != [] do
      Shell.info("Providers to update:")

      Enum.each(changes.updates, fn {slug, _local, attrs} ->
        Shell.info("🔄 #{slug} (#{attrs |> Map.keys() |> Enum.join(", ")})")
      end)

      Shell.info("")
    end

    if changes.preserved != [] do
      Shell.info("Local providers not in catalog (preserved): #{length(changes.preserved)}")
      Shell.info("")
    end
  end

  defp apply_changes(changes) do
    update_count = changes.updates |> Enum.map(&apply_update/1) |> Enum.sum()

    Shell.info("")

    Shell.info(
      "Sync complete: #{update_count} updated, #{length(changes.configured)} configured, " <>
        "#{length(changes.available)} not configured, #{length(changes.preserved)} preserved"
    )
  end

  defp apply_update({slug, local, attrs}) do
    case Tango.Provider.update_provider(local, attrs) do
      {:ok, _provider} ->
        Shell.info("🔄 Updated #{slug}")
        1

      {:error, changeset} ->
        Shell.error("Error: Failed to update #{slug}:")
        ProviderHelper.print_changeset_errors(changeset)
        0
    end
  end
end

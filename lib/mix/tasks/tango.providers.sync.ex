defmodule Mix.Tasks.Tango.Providers.Sync do
  @moduledoc """
  Synchronizes all providers from the Nango catalog to local database.

  ## Usage

      mix tango.providers.sync [options]

  ## Options

      --only PROVIDERS      Sync only specified providers (comma-separated)
      --dry-run, -n         Preview changes without applying them
      --force, -f           Force update existing provider configurations
      --update-metadata     Update display names and metadata only

  ## Examples

      mix tango.providers.sync
      mix tango.providers.sync --only github,slack
      mix tango.providers.sync --dry-run
      mix tango.providers.sync --force

  This command will fetch the Nango provider catalog and create provider
  templates in the local database. Existing providers are preserved unless
  --force is used.
  """

  use Mix.Task
  alias Mix.Shell.IO, as: Shell

  @shortdoc "Syncs providers from Nango catalog to database"

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

  def run(args) do
    {opts, _args, _} = OptionParser.parse(args, switches: @switches, aliases: @aliases)

    ensure_repo_started()
    Shell.info("📡 Fetching Nango provider catalog...")

    case Tango.Catalog.fetch_catalog() do
      {:ok, catalog} ->
        filtered_catalog = filter_catalog(catalog, opts)
        local_providers = get_local_providers()

        changes = analyze_changes(filtered_catalog, local_providers, opts)

        Shell.info("Found #{map_size(filtered_catalog)} providers in catalog")
        Shell.info("Analyzing local database (#{length(local_providers)} providers configured)")
        Shell.info("")

        display_changes(changes)

        if opts[:dry_run] do
          Shell.info("🔍 Dry run completed - no changes applied")
        else
          apply_changes(changes, opts)
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

  defp get_local_providers do
    Tango.Provider.list_all_providers()
  end

  defp analyze_changes(catalog, local_providers, opts) do
    local_names = MapSet.new(local_providers, & &1.name)
    catalog_names = MapSet.new(Map.keys(catalog))

    new_providers =
      MapSet.difference(catalog_names, local_names)
      |> MapSet.to_list()
      |> Enum.map(fn name -> {name, catalog[name]} end)

    updated_providers =
      if opts[:force] or opts[:update_metadata] do
        MapSet.intersection(catalog_names, local_names)
        |> MapSet.to_list()
        |> Enum.map(fn name ->
          local = Enum.find(local_providers, &(&1.name == name))
          {name, catalog[name], local}
        end)
      else
        []
      end

    preserved_providers =
      local_providers
      |> Enum.reject(fn provider -> provider.name in catalog_names end)

    %{
      new_providers: new_providers,
      updated_providers: updated_providers,
      preserved_providers: preserved_providers
    }
  end

  defp display_changes(changes) do
    if length(changes.new_providers) > 0 do
      Shell.info("New providers available:")

      Enum.each(changes.new_providers, fn {name, config} ->
        categories = config["categories"] || []

        category_text =
          if length(categories) > 0, do: " (#{Enum.join(categories, ", ")})", else: ""

        Shell.info("✅ #{name}#{category_text}")
      end)

      Shell.info("")
    end

    if length(changes.updated_providers) > 0 do
      Shell.info("Providers to update:")

      Enum.each(changes.updated_providers, fn {name, _config, _local} ->
        Shell.info("🔄 #{name}")
      end)

      Shell.info("")
    end

    if length(changes.preserved_providers) > 0 do
      Shell.info("Local providers preserved: #{length(changes.preserved_providers)}")
      Shell.info("")
    end
  end

  defp apply_changes(changes, opts) do
    success_count = apply_new_providers(changes.new_providers)
    update_count = apply_updates(changes.updated_providers, opts)

    Shell.info("")

    Shell.info(
      "Sync complete: #{success_count} added, #{update_count} updated, #{length(changes.preserved_providers)} preserved"
    )
  end

  defp apply_new_providers(new_providers) do
    if length(new_providers) > 0 do
      Shell.info("Syncing #{length(new_providers)} new providers...")

      new_providers
      |> Enum.map(fn {name, config} ->
        case Tango.Provider.create_provider_from_nango(name, config) do
          {:ok, _provider} ->
            Shell.info("✅ Created #{name} provider template")
            1

          {:error, changeset} ->
            Shell.error("❌ Failed to create #{name}:")
            print_changeset_errors(changeset)
            0
        end
      end)
      |> Enum.sum()
    else
      0
    end
  end

  defp apply_updates(updated_providers, opts) do
    if length(updated_providers) > 0 do
      Shell.info("Updating #{length(updated_providers)} existing providers...")

      updated_providers
      |> Enum.map(fn {name, config, local_provider} ->
        update_attrs = build_update_attrs(config, local_provider, opts)

        case Tango.Provider.update_provider(local_provider, update_attrs) do
          {:ok, _provider} ->
            Shell.info("🔄 Updated #{name}")
            1

          {:error, changeset} ->
            Shell.error("❌ Failed to update #{name}:")
            print_changeset_errors(changeset)
            0
        end
      end)
      |> Enum.sum()
    else
      0
    end
  end

  defp build_update_attrs(config, _local_provider, opts) do
    base_attrs = %{}

    base_attrs =
      if opts[:update_metadata] do
        Map.merge(base_attrs, %{
          display_name: config["display_name"]
          # Note: We don't update config to preserve credentials
        })
      else
        base_attrs
      end

    if opts[:force] do
      # Force update overwrites config but preserves credentials
      Map.put(base_attrs, :config, config)
    else
      base_attrs
    end
  end

  defp print_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Enum.each(fn {field, messages} ->
      Shell.error("  #{field}: #{Enum.join(messages, ", ")}")
    end)
  end

  defp ensure_repo_started do
    # Start the repo if not already started
    repo = Application.get_env(:tango, :repo, Tango.Repo)

    case repo.start_link() do
      {:ok, _} -> :ok
      {:error, {:already_started, _}} -> :ok
      error -> error
    end
  end
end

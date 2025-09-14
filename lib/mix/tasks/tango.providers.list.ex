defmodule Mix.Tasks.Tango.Providers.List do
  @moduledoc """
  Lists all available providers in the Nango catalog.

  ## Usage

      mix tango.providers.list

  ## Examples

      mix tango.providers.list

  This will display all providers available in the Nango catalog with their
  basic information including display name, categories, and authentication mode.
  """

  use Mix.Task
  alias Mix.Shell.IO, as: Shell

  @shortdoc "Lists all available OAuth providers in catalog"

  def run(_args) do
    Shell.info("📡 Fetching Nango provider catalog...")

    case Tango.Catalog.fetch_catalog() do
      {:ok, catalog} ->
        Shell.info("Found #{map_size(catalog)} providers in catalog\n")

        catalog
        |> Enum.sort_by(fn {name, _} -> name end)
        |> Enum.each(fn {name, config} ->
          categories = config["categories"] || []
          auth_mode = config["auth_mode"] || "OAUTH2"

          Shell.info("* #{name}")
          Shell.info("  Display Name: #{config["display_name"] || String.capitalize(name)}")
          Shell.info("  Categories: #{Enum.join(categories, ", ")}")
          Shell.info("  Auth Mode: #{auth_mode}")
          Shell.info("")
        end)

      {:error, reason} ->
        Shell.error("Failed to fetch catalog: #{inspect(reason)}")
    end
  end
end

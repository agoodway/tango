defmodule Mix.Tasks.Tango.Providers.Show do
  @moduledoc """
  Shows detailed configuration for a specific provider.

  ## Usage

      mix tango.providers.show PROVIDER_NAME

  ## Examples

      mix tango.providers.show github
      mix tango.providers.show slack

  This will display detailed information about the provider including
  OAuth configuration, scopes, and documentation links.
  """

  use Mix.Task
  alias Mix.Shell.IO, as: Shell

  @shortdoc "Shows detailed provider configuration"

  def run([provider_name | _]) when is_binary(provider_name) do
    Shell.info("📡 Fetching provider details for '#{provider_name}'...")

    case Tango.Catalog.fetch_catalog() do
      {:ok, catalog} ->
        case Map.get(catalog, provider_name) do
          nil ->
            Shell.error("Provider '#{provider_name}' not found in catalog")
            suggest_similar_providers(catalog, provider_name)

          config ->
            display_provider_details(provider_name, config)
        end

      {:error, reason} ->
        Shell.error("Failed to fetch catalog: #{inspect(reason)}")
    end
  end

  def run(_args) do
    Shell.error("Provider name required")
    Shell.info("Usage: mix tango.providers.show PROVIDER_NAME")
    Shell.info("Example: mix tango.providers.show github")
  end

  defp display_provider_details(name, config) do
    Shell.info("* #{String.capitalize(name)}")
    Shell.info("")
    Shell.info("Basic Information")
    Shell.info("  Display Name: #{config["display_name"] || String.capitalize(name)}")
    Shell.info("  Categories: #{Enum.join(config["categories"] || [], ", ")}")
    Shell.info("  Auth Mode: #{config["auth_mode"] || "OAUTH2"}")
    Shell.info("")

    if config["auth_mode"] == "OAUTH2" do
      Shell.info("OAuth2 Configuration")
      Shell.info("  Authorization URL: #{config["authorization_url"]}")
      Shell.info("  Token URL: #{config["token_url"]}")
      Shell.info("")

      if config["default_scopes"] && length(config["default_scopes"]) > 0 do
        Shell.info("Default Scopes:")

        Enum.each(config["default_scopes"], fn scope ->
          Shell.info("  - #{scope}")
        end)

        Shell.info("")
      end
    end

    if config["docs"] do
      Shell.info("Documentation:")
      Shell.info("  #{config["docs"]}")
    end
  end

  defp suggest_similar_providers(_catalog, provider_name) do
    suggestions = Tango.Catalog.suggest_similar(provider_name)

    if length(suggestions) > 0 do
      Shell.info("")
      Shell.info("Did you mean one of these?")

      Enum.each(suggestions, fn name ->
        Shell.info("  - #{name}")
      end)
    end
  end
end

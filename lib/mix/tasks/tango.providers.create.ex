defmodule Mix.Tasks.Tango.Providers.Create do
  @moduledoc """
  Creates a provider with OAuth credentials from the Nango catalog.

  ## Usage

      mix tango.providers.create PROVIDER_NAME [options]

  ## Options

      --client-id ID        OAuth2 client ID
      --client-secret SECRET OAuth2 client secret  
      --api-key KEY         API key for API_KEY providers

  ## Examples

      # Create OAuth2 provider
      mix tango.providers.create github --client-id=xxx --client-secret=yyy
      mix tango.providers.create google --client-id=xxx --client-secret=yyy

      # Create API key provider
      mix tango.providers.create stripe --api-key=sk_live_xxx

  This command fetches the provider configuration from the Nango catalog
  and creates a ready-to-use provider with your credentials.
  """

  use Mix.Task
  alias Mix.Shell.IO, as: Shell
  alias Mix.Tasks.Helpers.ProviderHelper

  @shortdoc "Creates a provider with credentials from catalog"

  @switches [
    client_id: :string,
    client_secret: :string,
    api_key: :string
  ]

  def run([provider_name | _] = args) when is_binary(provider_name) do
    {opts, _args, _} = OptionParser.parse(args, switches: @switches)

    ProviderHelper.ensure_repo_started()

    cond do
      opts[:client_id] && opts[:client_secret] ->
        create_oauth2_provider(provider_name, opts)

      opts[:api_key] ->
        create_api_key_provider(provider_name, opts)

      true ->
        ProviderHelper.display_create_usage(provider_name)
    end
  end

  def run(_args) do
    ProviderHelper.display_general_usage()
  end

  defp create_oauth2_provider(provider_name, opts) do
    Shell.info("📡 Fetching provider configuration for '#{provider_name}'...")

    case Tango.Catalog.get_provider(provider_name) do
      {:ok, nango_config} ->
        if nango_config["auth_mode"] == "API_KEY" do
          Shell.error("❌ Provider '#{provider_name}' uses API key authentication")
          Shell.info("   Use: mix tango.providers.create #{provider_name} --api-key=xxx")
        else
          config_with_credentials =
            nango_config
            |> put_in(["client_id"], opts[:client_id])
            |> put_in(["client_secret"], opts[:client_secret])

          case Tango.Provider.create_provider_from_nango(provider_name, config_with_credentials) do
            {:ok, provider} ->
              Shell.info("✅ Created #{provider.name} provider")
              Shell.info("   Display Name: #{provider.display_name}")
              Shell.info("   Status: #{if provider.active, do: "Active", else: "Inactive"}")
              Shell.info("   Auth Mode: OAuth2")

              if provider.default_scopes && length(provider.default_scopes) > 0 do
                Shell.info("   Default Scopes: #{Enum.join(provider.default_scopes, ", ")}")
              end

            {:error, changeset} ->
              Shell.error("❌ Failed to create provider:")
              print_changeset_errors(changeset)
          end
        end

      {:error, :not_found} ->
        Shell.error("Provider '#{provider_name}' not found in catalog")
        suggestions = Tango.Catalog.suggest_similar(provider_name)

        if length(suggestions) > 0 do
          Shell.info("")
          Shell.info("Did you mean one of these?")

          Enum.each(suggestions, fn name ->
            Shell.info("  - #{name}")
          end)
        end

      {:error, reason} ->
        Shell.error("Failed to fetch catalog: #{inspect(reason)}")
    end
  end

  defp create_api_key_provider(provider_name, opts) do
    Shell.info("📡 Checking provider configuration for '#{provider_name}'...")

    case Tango.Catalog.get_provider(provider_name) do
      {:ok, nango_config} ->
        if nango_config["auth_mode"] != "API_KEY" do
          Shell.error("❌ Provider '#{provider_name}' uses OAuth2 authentication")

          Shell.info(
            "   Use: mix tango.providers.create #{provider_name} --client-id=xxx --client-secret=yyy"
          )
        else
          config_with_credentials =
            nango_config
            |> put_in(["api_key"], opts[:api_key])

          case Tango.Provider.create_provider_from_nango(provider_name, config_with_credentials) do
            {:ok, provider} ->
              Shell.info("✅ Created #{provider.name} provider")
              Shell.info("   Display Name: #{provider.display_name}")
              Shell.info("   Status: #{if provider.active, do: "Active", else: "Inactive"}")
              Shell.info("   Auth Mode: API Key")

            {:error, changeset} ->
              Shell.error("❌ Failed to create provider:")
              print_changeset_errors(changeset)
          end
        end

      {:error, :not_found} ->
        # For API key providers not in catalog, create a simple one
        Shell.info("Provider not found in catalog, creating simple API key provider...")

        config = %{
          name: provider_name,
          display_name: String.capitalize(provider_name),
          config: %{
            "auth_mode" => "API_KEY",
            "api_key" => opts[:api_key]
          }
        }

        case Tango.Provider.create_provider(config) do
          {:ok, provider} ->
            Shell.info("✅ Created #{provider.name} API key provider")
            Shell.info("   Display Name: #{provider.display_name}")
            Shell.info("   Status: #{if provider.active, do: "Active", else: "Inactive"}")

          {:error, changeset} ->
            Shell.error("❌ Failed to create provider:")
            print_changeset_errors(changeset)
        end

      {:error, reason} ->
        Shell.error("Failed to fetch catalog: #{inspect(reason)}")
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
end

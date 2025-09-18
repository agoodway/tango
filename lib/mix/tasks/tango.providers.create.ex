defmodule Mix.Tasks.Tango.Providers.Create do
  @moduledoc """
  Creates a provider with OAuth credentials from the Nango catalog.

  ## Usage

      mix tango.providers.create PROVIDER_NAME [options]

  ## Options

      --client-id ID        OAuth2 client ID
      --client-secret SECRET OAuth2 client secret
      --api-key KEY         API key for API_KEY providers
      --scope SCOPE         Single OAuth2 scope (can be specified multiple times)
      --scopes SCOPES       Comma-separated list of OAuth2 scopes

  ## Examples

      # Create OAuth2 provider
      mix tango.providers.create github --client-id=xxx --client-secret=yyy
      mix tango.providers.create google --client-id=xxx --client-secret=yyy

      # Create OAuth2 provider with custom scopes (multiple ways)
      mix tango.providers.create google --client-id=xxx --client-secret=yyy --scope=https://www.googleapis.com/auth/calendar --scope=https://www.googleapis.com/auth/userinfo.email
      mix tango.providers.create google --client-id=xxx --client-secret=yyy --scopes="https://www.googleapis.com/auth/calendar,https://www.googleapis.com/auth/userinfo.email"

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
    api_key: :string,
    scope: :keep,
    scopes: :string
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
          # Parse and combine scopes from catalog and user input
          combined_scopes = ProviderHelper.parse_scopes(nango_config, opts)

          case Tango.Provider.create_provider_from_nango(provider_name, nango_config,
                 client_id: opts[:client_id],
                 client_secret: opts[:client_secret],
                 default_scopes: combined_scopes
               ) do
            {:ok, provider} ->
              ProviderHelper.display_provider_success(provider, "OAuth2")

            {:error, changeset} ->
              ProviderHelper.display_creation_error(changeset)
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
              ProviderHelper.display_provider_success(provider, "API Key")

            {:error, changeset} ->
              ProviderHelper.display_creation_error(changeset)
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
            ProviderHelper.display_provider_success(provider, "API Key (Simple)")

          {:error, changeset} ->
            ProviderHelper.display_creation_error(changeset)
        end

      {:error, reason} ->
        Shell.error("Failed to fetch catalog: #{inspect(reason)}")
    end
  end
end

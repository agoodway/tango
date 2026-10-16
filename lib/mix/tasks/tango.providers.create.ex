defmodule Mix.Tasks.Tango.Providers.Create do
  @moduledoc """
  Creates a provider with OAuth credentials from the Nango catalog.

  ## Usage

      mix tango.providers.create PROVIDER_NAME [options]

  ## Options

      --client-id ID        OAuth2 client ID
      --client-secret SECRET OAuth2 client secret
      --scope SCOPE         Single OAuth2 scope (can be specified multiple times)
      --scopes SCOPES       Comma-separated list of OAuth2 scopes
      --auth-url URL        Authorization URL (overrides the catalog value)
      --token-url URL       Token URL (overrides the catalog value)

  ## Examples

      # Create OAuth2 provider
      mix tango.providers.create github --client-id=xxx --client-secret=yyy
      mix tango.providers.create google --client-id=xxx --client-secret=yyy

      # Create OAuth2 provider with custom scopes (multiple ways)
      mix tango.providers.create google --client-id=xxx --client-secret=yyy --scope=https://www.googleapis.com/auth/calendar --scope=https://www.googleapis.com/auth/userinfo.email
      mix tango.providers.create google --client-id=xxx --client-secret=yyy --scopes="https://www.googleapis.com/auth/calendar,https://www.googleapis.com/auth/userinfo.email"

      # Provider whose catalog URLs need connection configuration
      mix tango.providers.create zendesk --client-id=xxx --client-secret=yyy \\
        --auth-url=https://acme.zendesk.com/oauth/authorizations/new \\
        --token-url=https://acme.zendesk.com/oauth/tokens

  This command fetches the provider configuration from the Nango catalog
  (resolving `alias:` entries through their parent) and creates a
  ready-to-use provider with your credentials.

  Catalog URLs with a `a || b` template use the alternative Nango uses without
  connection configuration. URLs that still need `${connectionConfig.*}`
  values are rejected unless you pass `--auth-url` and `--token-url`.

  Only OAuth2 providers are supported. `--api-key` is rejected with an error:
  Tango has no API-key connection flow, so the key would otherwise be dropped.
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
    scopes: :string,
    auth_url: :string,
    token_url: :string
  ]

  @doc "Runs the mix task."
  def run([provider_name | _] = args) when is_binary(provider_name) do
    {opts, _args, _} = OptionParser.parse(args, switches: @switches)

    ProviderHelper.ensure_repo_started()

    cond do
      Keyword.has_key?(opts, :api_key) ->
        reject_api_key(provider_name)

      opts[:client_id] && opts[:client_secret] ->
        create_oauth2_provider(provider_name, opts)

      true ->
        ProviderHelper.display_create_usage(provider_name)
    end
  end

  @doc false
  def run(_args) do
    ProviderHelper.display_general_usage()
  end

  defp create_oauth2_provider(provider_name, opts) do
    Shell.info("📡 Fetching provider configuration for '#{provider_name}'...")

    case Tango.Catalog.get_provider(provider_name) do
      {:ok, nango_config} -> handle_oauth2_config(provider_name, nango_config, opts)
      {:error, :not_found} -> handle_oauth2_not_found(provider_name)
      {:error, reason} -> Shell.error("Failed to fetch catalog: #{inspect(reason)}")
    end
  end

  defp handle_oauth2_config(provider_name, %{"auth_mode" => mode}, _opts)
       when is_binary(mode) and mode != "OAUTH2" do
    Shell.error(
      "Error: Provider '#{provider_name}' uses #{mode} authentication, which Tango does not support"
    )

    Shell.info("   Tango only supports OAUTH2 (authorization code) providers.")
  end

  defp handle_oauth2_config(provider_name, nango_config, opts) do
    combined_scopes = ProviderHelper.parse_scopes(nango_config, opts)

    case Tango.Provider.create_provider_from_nango(provider_name, nango_config,
           client_id: opts[:client_id],
           client_secret: opts[:client_secret],
           default_scopes: combined_scopes,
           auth_url: opts[:auth_url],
           token_url: opts[:token_url]
         ) do
      {:ok, provider} -> ProviderHelper.display_provider_success(provider, "OAuth2")
      {:error, changeset} -> display_creation_error(changeset)
    end
  end

  defp display_creation_error(changeset) do
    ProviderHelper.display_creation_error(changeset)

    if connection_config_error?(changeset) do
      Shell.info("   Pass the provider's URLs explicitly with --auth-url=... --token-url=...")
    end
  end

  defp connection_config_error?(changeset) do
    Enum.any?(changeset.errors, fn {_field, {message, _opts}} ->
      String.contains?(message, "requires connection configuration")
    end)
  end

  defp handle_oauth2_not_found(provider_name) do
    Shell.error("Provider '#{provider_name}' not found in catalog")
    suggestions = Tango.Catalog.suggest_similar(provider_name)

    if suggestions != [] do
      Shell.info("")
      Shell.info("Did you mean one of these?")
      Enum.each(suggestions, fn name -> Shell.info("  - #{name}") end)
    end
  end

  defp reject_api_key(provider_name) do
    Shell.error(
      "Error: API key providers are not supported; Tango only supports OAuth2 providers."
    )

    Shell.info("   No provider was created and the API key was not stored.")

    Shell.info(
      "   For OAuth2: mix tango.providers.create #{provider_name} --client-id=xxx --client-secret=yyy"
    )
  end
end

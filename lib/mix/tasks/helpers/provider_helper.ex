defmodule Mix.Tasks.Helpers.ProviderHelper do
  @moduledoc """
  Shared functionality for Mix tasks related to provider management.

  This module extracts common patterns from Mix tasks to reduce
  complexity and improve maintainability.
  """

  alias Mix.Shell.IO, as: Shell
  alias Mix.Tasks.Helpers.TaskHelper

  @doc """
  Ensures the repo is started for Mix tasks.

  Delegates to TaskHelper for consistent application startup.
  """
  def ensure_repo_started do
    TaskHelper.ensure_started()
  end

  @doc """
  Fetches provider configuration from catalog with error handling.
  """
  def fetch_provider_config(provider_name) do
    Shell.info("📡 Fetching provider configuration for '#{provider_name}'...")

    case Tango.Catalog.get_provider(provider_name) do
      {:ok, config} ->
        {:ok, config}

      {:error, :not_found} ->
        Shell.error("❌ Provider '#{provider_name}' not found in catalog")
        suggest_similar_providers(provider_name)
        {:error, :not_found}

      {:error, reason} ->
        Shell.error("❌ Failed to fetch catalog: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Suggests similar provider names when provider not found.
  """
  def suggest_similar_providers(provider_name) do
    case Tango.Catalog.suggest_similar(provider_name) do
      [] ->
        Shell.info("   No similar providers found.")
        Shell.info("   Use 'mix tango.providers.show <name>' to view specific provider details.")

      suggestions ->
        Shell.info("   Did you mean one of these?")

        for suggestion <- Enum.take(suggestions, 3) do
          Shell.info("   - #{suggestion}")
        end
    end
  end

  @doc """
  Validates OAuth2 credentials are provided.
  """
  def validate_oauth2_credentials(opts) do
    case {opts[:client_id], opts[:client_secret]} do
      {nil, _} ->
        {:error, "OAuth2 client ID required (--client-id)"}

      {_, nil} ->
        {:error, "OAuth2 client secret required (--client-secret)"}

      {client_id, client_secret} ->
        {:ok, %{client_id: client_id, client_secret: client_secret}}
    end
  end

  @doc """
  Validates API key credentials are provided.
  """
  def validate_api_key_credentials(opts) do
    case opts[:api_key] do
      nil ->
        {:error, "API key required (--api-key)"}

      api_key ->
        {:ok, %{api_key: api_key}}
    end
  end

  @doc """
  Creates OAuth2 provider from catalog configuration.
  """
  def create_oauth2_provider_from_config(provider_name, nango_config, credentials) do
    case Tango.Provider.create_provider_from_nango(provider_name, nango_config,
           client_id: credentials.client_id,
           client_secret: credentials.client_secret
         ) do
      {:ok, provider} ->
        display_provider_success(provider, "OAuth2")
        {:ok, provider}

      {:error, changeset} ->
        Shell.error("❌ Failed to create provider:")
        print_changeset_errors(changeset)
        {:error, changeset}
    end
  end

  @doc """
  Creates API key provider from catalog configuration.
  """
  def create_api_key_provider_from_config(provider_name, nango_config, credentials) do
    config_with_credentials = put_in(nango_config, ["api_key"], credentials.api_key)

    case Tango.Provider.create_provider_from_nango(provider_name, config_with_credentials) do
      {:ok, provider} ->
        display_provider_success(provider, "API Key")
        {:ok, provider}

      {:error, changeset} ->
        Shell.error("❌ Failed to create provider:")
        print_changeset_errors(changeset)
        {:error, changeset}
    end
  end

  @doc """
  Creates a simple API key provider when not found in catalog.
  """
  def create_simple_api_key_provider(provider_name, credentials) do
    Shell.info("Provider not found in catalog, creating simple API key provider...")

    config = %{
      "name" => String.capitalize(provider_name),
      "slug" => provider_name,
      "auth_mode" => "API_KEY",
      "api_config" => %{
        "headers" => %{
          "authorization" => "Bearer ${api_key}"
        }
      }
    }

    case Tango.Provider.create_provider_from_nango(provider_name, config,
           api_key: credentials.api_key
         ) do
      {:ok, provider} ->
        display_provider_success(provider, "API Key (Simple)")
        {:ok, provider}

      {:error, changeset} ->
        Shell.error("❌ Failed to create simple provider:")
        print_changeset_errors(changeset)
        {:error, changeset}
    end
  end

  @doc """
  Displays successful provider creation message.

  Shows provider details including optional default scopes for OAuth2 providers.
  """
  def display_provider_success(provider, auth_type) do
    Shell.info("✅ Created #{provider.name} provider")
    Shell.info("   Display Name: #{provider.name}")
    Shell.info("   Status: #{if provider.active, do: "Active", else: "Inactive"}")
    Shell.info("   Auth Mode: #{auth_type}")

    display_provider_scopes(provider)
  end

  defp display_provider_scopes(provider)
       when is_list(provider.default_scopes) and length(provider.default_scopes) > 0 do
    Shell.info("   Default Scopes: #{Enum.join(provider.default_scopes, ", ")}")
  end

  defp display_provider_scopes(_provider), do: :ok

  @doc """
  Displays provider creation error with formatted changeset errors.
  """
  def display_creation_error(changeset) do
    Shell.error("❌ Failed to create provider:")
    print_changeset_errors(changeset)
  end

  @doc """
  Prints changeset errors in a readable format.
  """
  def print_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Enum.each(fn {field, messages} ->
      messages
      |> List.wrap()
      |> Enum.each(fn message ->
        Shell.info("   #{field}: #{message}")
      end)
    end)
  end

  @doc """
  Displays usage information for provider creation.
  """
  def display_create_usage(provider_name) do
    Shell.error("Provider credentials required.")
    Shell.info("")
    Shell.info("For OAuth2 providers:")

    Shell.info(
      "  mix tango.providers.create #{provider_name} --client-id=xxx --client-secret=yyy"
    )

    Shell.info("")
    Shell.info("For API key providers:")
    Shell.info("  mix tango.providers.create #{provider_name} --api-key=xxx")
  end

  @doc """
  Displays general usage information.
  """
  def display_general_usage do
    Shell.error("Provider name required")
    Shell.info("")
    Shell.info("Usage:")
    Shell.info("  mix tango.providers.create PROVIDER_NAME --client-id=xxx --client-secret=yyy")
    Shell.info("")
    Shell.info("Examples:")
    Shell.info("  mix tango.providers.create github --client-id=xxx --client-secret=yyy")
    Shell.info("  mix tango.providers.create stripe --api-key=sk_live_xxx")
  end
end

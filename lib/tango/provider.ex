defmodule Tango.Provider do
  @moduledoc """
  Context module for OAuth provider configuration management.

  Provides CRUD operations for OAuth providers with support for Nango catalog
  integration, validation, and credential management.
  """

  import Ecto.Query, warn: false
  # Repo will be configured by the host application
  @repo Application.compile_env(:tango, :repo, Tango.Repo)
  alias Tango.Schemas.{AuditLog, Provider}
  alias Tango.Schemas.Provider, as: ProviderSchema

  @doc """
  Returns the list of active providers.

  ## Examples

      iex> list_providers()
      [%Provider{}, ...]

  """
  def list_providers do
    Provider
    |> where([p], p.active == true)
    |> order_by([p], p.name)
    |> @repo.all()
  end

  @doc """
  Returns all providers including inactive ones.

  ## Examples

      iex> list_all_providers()
      [%Provider{}, ...]

  """
  def list_all_providers do
    Provider
    |> order_by([p], [p.active, p.name])
    |> @repo.all()
  end

  @doc """
  Gets a single provider by slug.

  Returns `{:ok, provider}` if found, `{:error, :not_found}` if not found.

  ## Examples

      iex> get_provider("github")
      {:ok, %Provider{}}

      iex> get_provider("nonexistent")
      {:error, :not_found}

  """
  def get_provider(slug) when is_binary(slug) do
    case @repo.get_by(Provider, slug: slug, active: true) do
      nil -> {:error, :not_found}
      provider -> {:ok, provider}
    end
  end

  @doc """
  Gets a single provider by ID.

  Returns `{:ok, provider}` if found, `{:error, :not_found}` if not found.
  """
  def get_provider_by_id(id) do
    case @repo.get(Provider, id) do
      nil -> {:error, :not_found}
      provider -> {:ok, provider}
    end
  end

  @doc """
  Creates a provider.

  ## Examples

      iex> create_provider(%{name: "custom", display_name: "Custom OAuth"})
      {:ok, %Provider{}}

      iex> create_provider(%{})
      {:error, %Ecto.Changeset{}}

  """
  def create_provider(attrs \\ %{}) do
    result =
      %Provider{}
      |> Provider.changeset(attrs)
      |> @repo.insert()

    case result do
      {:ok, provider} ->
        # Log provider creation
        AuditLog.log_provider_event(:provider_created, provider, true)
        |> @repo.insert()

        {:ok, provider}

      error ->
        error
    end
  end

  @doc """
  Creates a provider from Nango configuration.

  ## Examples

      iex> create_provider_from_nango("github", nango_config, client_id: "abc", client_secret: "xyz")
      {:ok, %Provider{}}

  """
  def create_provider_from_nango(name, nango_config, opts \\ []) do
    changeset = Provider.from_nango_config(name, nango_config, opts)

    case @repo.insert(changeset) do
      {:ok, provider} ->
        # Log provider creation
        AuditLog.log_provider_event(:provider_created, provider, true, %{
          source: "nango_catalog",
          nango_provider: name
        })
        |> @repo.insert()

        {:ok, provider}

      error ->
        error
    end
  end

  @doc """
  Updates a provider.

  ## Examples

      iex> update_provider(provider, %{display_name: "New Name"})
      {:ok, %Provider{}}

      iex> update_provider(provider, %{name: nil})
      {:error, %Ecto.Changeset{}}

  """
  def update_provider(%Provider{config: old_config} = provider, attrs) do
    result =
      provider
      |> Provider.changeset(attrs)
      |> @repo.update()

    case result do
      {:ok, updated_provider} ->
        # Log provider update if config changed
        if updated_provider.config != old_config do
          AuditLog.log_provider_event(:provider_updated, updated_provider, true, %{
            config_changed: true
          })
          |> @repo.insert()
        end

        {:ok, updated_provider}

      error ->
        error
    end
  end

  @doc """
  Soft deletes a provider by setting active to false.

  ## Examples

      iex> delete_provider(provider)
      {:ok, %Provider{}}

      iex> delete_provider(provider)
      {:error, %Ecto.Changeset{}}

  """
  def delete_provider(%Provider{} = provider) do
    result =
      provider
      |> Provider.changeset(%{active: false})
      |> @repo.update()

    case result do
      {:ok, updated_provider} ->
        # Log provider deletion
        AuditLog.log_provider_event(:provider_deleted, updated_provider, true)
        |> @repo.insert()

        {:ok, updated_provider}

      error ->
        error
    end
  end

  @doc """
  Activates a previously deactivated provider.

  ## Examples

      iex> activate_provider(provider)
      {:ok, %Provider{}}

  """
  def activate_provider(%Provider{} = provider) do
    result =
      provider
      |> Provider.changeset(%{active: true})
      |> @repo.update()

    case result do
      {:ok, updated_provider} ->
        # Log provider activation
        AuditLog.log_provider_event(:provider_updated, updated_provider, true, %{
          action: "activated"
        })
        |> @repo.insert()

        {:ok, updated_provider}

      error ->
        error
    end
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking provider changes.

  ## Examples

      iex> change_provider(provider)
      %Ecto.Changeset{data: %Provider{}}

  """
  def change_provider(%Provider{} = provider, attrs \\ %{}) do
    Provider.changeset(provider, attrs)
  end

  @doc """
  Gets OAuth client configuration for a provider.

  Returns the OAuth client credentials and endpoints needed for authorization flow.

  ## Examples

      iex> get_oauth_client("github")
      {:ok, %{client_id: "abc", client_secret: "xyz", auth_url: "...", token_url: "..."}}

  """
  def get_oauth_client(provider_name) when is_binary(provider_name) do
    with {:ok, provider} <- get_provider(provider_name) do
      ProviderSchema.get_oauth_credentials(provider)
    end
  end

  def get_oauth_client(%Provider{} = provider) do
    ProviderSchema.get_oauth_credentials(provider)
  end

  @doc """
  Validates provider configuration without saving.

  ## Examples

      iex> validate_provider_config(%{name: "test", config: config_json})
      {:ok, changeset}

      iex> validate_provider_config(%{})
      {:error, changeset}

  """
  def validate_provider_config(attrs) do
    changeset = Provider.changeset(%Provider{}, attrs)

    if changeset.valid? do
      {:ok, changeset}
    else
      {:error, changeset}
    end
  end

  @doc """
  Counts active providers.

  ## Examples

      iex> count_providers()
      5

  """
  def count_providers do
    Provider
    |> where([p], p.active == true)
    |> @repo.aggregate(:count, :id)
  end

  @doc """
  Gets providers by auth mode (OAUTH2, API_KEY, etc.).

  ## Examples

      iex> get_providers_by_auth_mode("OAUTH2")
      [%Provider{}, ...]

  """
  def get_providers_by_auth_mode(auth_mode) do
    from(p in Provider,
      where: p.active == true,
      where: fragment("?->>'auth_mode' = ?", p.config, ^auth_mode),
      order_by: p.name
    )
    |> @repo.all()
  end

  @doc """
  Searches providers by name or display name.

  ## Examples

      iex> search_providers("git")
      [%Provider{name: "github"}, %Provider{name: "gitlab"}]

  """
  def search_providers(search_term) when is_binary(search_term) do
    search_pattern = "%#{search_term}%"

    from(p in Provider,
      where: p.active == true,
      where: ilike(p.name, ^search_pattern) or ilike(p.display_name, ^search_pattern),
      order_by: p.name
    )
    |> @repo.all()
  end
end

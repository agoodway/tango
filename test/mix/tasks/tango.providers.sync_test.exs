defmodule Mix.Tasks.Tango.Providers.SyncTest do
  @moduledoc """
  Tests for `mix tango.providers.sync` against a mocked Nango catalog.
  """

  use Tango.DatabaseCase, async: false

  import ExUnit.CaptureIO

  alias Mix.Tasks.Tango.Providers.Sync
  alias Tango.{CatalogMockServer, Factory}
  alias Tango.Schemas.Provider, as: ProviderSchema

  setup do
    bypass = Bypass.open()
    CatalogMockServer.setup_catalog_endpoint(bypass)

    original_url = Application.get_env(:tango, :nango_providers_url)
    Application.put_env(:tango, :nango_providers_url, CatalogMockServer.catalog_url(bypass))

    on_exit(fn ->
      if original_url do
        Application.put_env(:tango, :nango_providers_url, original_url)
      else
        Application.delete_env(:tango, :nango_providers_url)
      end
    end)

    :ok
  end

  defp run_sync(args) do
    parent = self()

    stdout =
      capture_io(fn ->
        stderr = capture_io(:stderr, fn -> Sync.run(args) end)
        send(parent, {:stderr, stderr})
      end)

    assert_received {:stderr, stderr}
    {stdout, stderr}
  end

  defp create_github(attrs \\ %{}) do
    Factory.create_provider(
      Map.merge(
        %{
          name: "GitHub",
          slug: "github",
          client_secret: "real_secret",
          config: %{
            "client_id" => "real_client_id",
            "auth_url" => "https://old.example.com/authorize",
            "token_url" => "https://old.example.com/token",
            "auth_mode" => "OAUTH2",
            "custom_key" => "keep me"
          },
          default_scopes: ["repo"],
          metadata: %{"custom_meta" => "keep me"}
        },
        attrs
      )
    )
  end

  test "does not create providers that have no credentials" do
    {stdout, stderr} = run_sync(["--only", "github,slack"])

    assert Repo.aggregate(ProviderSchema, :count, :id) == 0
    refute stderr =~ "Failed to create"
    assert stdout =~ "github"
    assert stdout =~ "mix tango.providers.create"
  end

  test "matches existing providers by slug, not display name" do
    _github = create_github()

    {stdout, stderr} = run_sync(["--only", "github"])

    refute stderr =~ "Failed"
    assert Repo.aggregate(ProviderSchema, :count, :id) == 1
    assert stdout =~ "1 configured"
  end

  test "--force merges catalog endpoints without clobbering credentials or custom config" do
    github = create_github()

    {_stdout, stderr} = run_sync(["--only", "github", "--force"])

    refute stderr =~ "Failed"
    updated = Repo.get!(ProviderSchema, github.id)

    assert updated.config["auth_url"] == "https://github.com/login/oauth/authorize"
    assert updated.config["token_url"] == "https://github.com/login/oauth/access_token"
    assert updated.config["client_id"] == "real_client_id"
    assert updated.config["custom_key"] == "keep me"
    assert updated.client_secret == "real_secret"
    assert updated.default_scopes == ["repo"]
    assert updated.name == "GitHub"
    refute Map.has_key?(updated.config, "display_name")
  end

  test "--update-metadata updates the display name and catalog metadata only" do
    github = create_github(%{name: "My GitHub"})

    {_stdout, stderr} = run_sync(["--only", "github", "--update-metadata"])

    refute stderr =~ "Failed"
    updated = Repo.get!(ProviderSchema, github.id)

    assert updated.name == "GitHub"
    assert updated.metadata["categories"] == ["dev-tools"]
    assert updated.metadata["docs_url"] == "https://docs.nango.dev/integrations/all/github"
    assert updated.metadata["custom_meta"] == "keep me"
    assert updated.config == github.config
    assert updated.client_secret == "real_secret"
  end

  defp create_local(slug, config, metadata \\ %{}) do
    Factory.create_provider(%{
      name: slug,
      slug: slug,
      client_secret: "real_secret",
      config: Map.merge(%{"client_id" => "real_client_id", "auth_mode" => "OAUTH2"}, config),
      metadata: metadata
    })
  end

  test "--force resolves alias entries through their parent" do
    local =
      create_local("google-calendar", %{
        "auth_url" => "https://old.example.com/authorize",
        "token_url" => "https://old.example.com/token"
      })

    {_stdout, stderr} = run_sync(["--only", "google-calendar", "--force"])

    refute stderr =~ "Failed"
    updated = Repo.get!(ProviderSchema, local.id)
    assert updated.config["auth_url"] == "https://accounts.google.com/o/oauth2/auth"
    assert updated.config["token_url"] == "https://oauth2.googleapis.com/token"
  end

  test "--force never replaces local URLs with templated catalog URLs" do
    local =
      create_local("salesforce", %{
        "auth_url" => "https://acme.my.salesforce.com/services/oauth2/authorize",
        "token_url" => "https://acme.my.salesforce.com/services/oauth2/token"
      })

    {_stdout, stderr} = run_sync(["--only", "salesforce", "--force"])

    refute stderr =~ "Failed"
    updated = Repo.get!(ProviderSchema, local.id)
    assert updated.config == local.config
  end

  test "--update-metadata records the catalog request options" do
    local =
      create_local("slack", %{
        "auth_url" => "https://slack.com/oauth/v2/authorize",
        "token_url" => "https://slack.com/api/oauth.v2.access"
      })

    {_stdout, stderr} = run_sync(["--only", "slack", "--update-metadata"])

    refute stderr =~ "Failed"
    updated = Repo.get!(ProviderSchema, local.id)
    assert updated.metadata["scope_separator"] == ","
    assert updated.metadata["disable_pkce"] == true
  end

  test "--update-metadata records alias metadata inherited from the parent" do
    local =
      create_local("google-calendar", %{
        "auth_url" => "https://accounts.google.com/o/oauth2/auth",
        "token_url" => "https://oauth2.googleapis.com/token"
      })

    {_stdout, stderr} = run_sync(["--only", "google-calendar", "--update-metadata"])

    refute stderr =~ "Failed"
    updated = Repo.get!(ProviderSchema, local.id)
    assert updated.name == "Google Calendar"
    assert updated.metadata["auth_params"]["access_type"] == "offline"
    assert updated.metadata["categories"] == ["calendar"]
  end

  test "updates inactive providers without reactivating them" do
    github = create_github(%{active: false})

    {_stdout, stderr} = run_sync(["--only", "github", "--force"])

    refute stderr =~ "Failed"
    updated = Repo.get!(ProviderSchema, github.id)
    assert updated.active == false
    assert updated.config["auth_url"] == "https://github.com/login/oauth/authorize"
  end

  test "--dry-run changes nothing" do
    github = create_github()

    {stdout, _stderr} = run_sync(["--only", "github", "--force", "--dry-run"])

    assert stdout =~ "Dry run"
    assert Repo.get!(ProviderSchema, github.id).config == github.config
  end
end

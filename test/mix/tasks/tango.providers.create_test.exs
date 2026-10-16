defmodule Mix.Tasks.Tango.Providers.CreateTest do
  @moduledoc """
  Tests for `mix tango.providers.create` against a mocked Nango catalog.
  """

  use Tango.DatabaseCase, async: false

  import ExUnit.CaptureIO

  alias Mix.Tasks.Tango.Providers.Create
  alias Tango.CatalogMockServer
  alias Tango.Schemas.Provider, as: ProviderSchema

  # --api-key is rejected before the catalog is consulted, so only tests that
  # actually fetch the catalog register the (strict) Bypass expectation.
  setup tags do
    bypass = Bypass.open()

    if tags[:catalog], do: CatalogMockServer.setup_catalog_endpoint(bypass)

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

  defp run_create(args) do
    parent = self()

    stdout =
      capture_io(fn ->
        stderr = capture_io(:stderr, fn -> Create.run(args) end)
        send(parent, {:stderr, stderr})
      end)

    assert_received {:stderr, stderr}
    {stdout, stderr}
  end

  @tag :catalog
  test "creates an OAuth2 provider with encrypted credentials" do
    {stdout, stderr} =
      run_create(["github", "--client-id=abc", "--client-secret=shh"])

    assert stderr == ""
    assert stdout =~ "Created GitHub provider"

    provider = Repo.get_by!(ProviderSchema, slug: "github")
    assert provider.config["client_id"] == "abc"
    assert provider.client_secret == "shh"
  end

  @tag :catalog
  test "creates an alias entry with its parent's OAuth2 settings" do
    {stdout, stderr} =
      run_create(["google-calendar", "--client-id=abc", "--client-secret=shh"])

    assert stderr == ""
    assert stdout =~ "Created Google Calendar provider"

    provider = Repo.get_by!(ProviderSchema, slug: "google-calendar")
    assert provider.config["auth_url"] == "https://accounts.google.com/o/oauth2/auth"
    assert provider.config["token_url"] == "https://oauth2.googleapis.com/token"
    assert provider.config["auth_mode"] == "OAUTH2"
    assert provider.metadata["auth_params"]["access_type"] == "offline"

    assert provider.default_scopes == [
             "https://www.googleapis.com/auth/userinfo.email",
             "https://www.googleapis.com/auth/userinfo.profile"
           ]
  end

  @tag :catalog
  test "uses the default URL of a `||` template" do
    {_stdout, stderr} = run_create(["salesforce", "--client-id=abc", "--client-secret=shh"])

    assert stderr == ""
    provider = Repo.get_by!(ProviderSchema, slug: "salesforce")
    assert provider.config["auth_url"] == "https://login.salesforce.com/services/oauth2/authorize"
    assert provider.config["token_url"] == "https://login.salesforce.com/services/oauth2/token"
  end

  @tag :catalog
  test "records the catalog request options in metadata" do
    {_stdout, stderr} = run_create(["figma", "--client-id=abc", "--client-secret=shh"])

    assert stderr == ""
    provider = Repo.get_by!(ProviderSchema, slug: "figma")
    assert provider.metadata["scope_separator"] == ","
    assert provider.metadata["disable_pkce"] == true
    assert provider.metadata["token_request_auth_method"] == "basic"
  end

  @tag :catalog
  test "rejects connection-config providers without URL overrides" do
    {stdout, stderr} = run_create(["zendesk", "--client-id=abc", "--client-secret=shh"])

    assert stderr =~ "Failed to create provider"
    assert stdout =~ "requires connection configuration, which Tango does not support"
    assert stdout =~ "--auth-url"
    assert Repo.aggregate(ProviderSchema, :count, :id) == 0
  end

  @tag :catalog
  test "creates connection-config providers with --auth-url and --token-url" do
    {_stdout, stderr} =
      run_create([
        "zendesk",
        "--client-id=abc",
        "--client-secret=shh",
        "--auth-url=https://acme.zendesk.com/oauth/authorizations/new",
        "--token-url=https://acme.zendesk.com/oauth/tokens"
      ])

    assert stderr == ""
    provider = Repo.get_by!(ProviderSchema, slug: "zendesk")
    assert provider.config["auth_url"] == "https://acme.zendesk.com/oauth/authorizations/new"
    assert provider.config["token_url"] == "https://acme.zendesk.com/oauth/tokens"
  end

  @tag :catalog
  test "rejects non-OAuth2 catalog entries, including aliases that switch auth mode" do
    for slug <- ["github-app", "stripe"] do
      {_stdout, stderr} = run_create([slug, "--client-id=abc", "--client-secret=shh"])

      assert stderr =~ "authentication, which Tango does not support"
    end

    assert Repo.aggregate(ProviderSchema, :count, :id) == 0
  end

  test "rejects --api-key with a clear error and stores nothing" do
    {_stdout, stderr} = run_create(["stripe", "--api-key=sk_live_xxx"])

    assert stderr =~ "API key providers are not supported"
    assert Repo.aggregate(ProviderSchema, :count, :id) == 0
  end

  test "rejects --api-key for providers missing from the catalog" do
    {_stdout, stderr} = run_create(["not-in-catalog", "--api-key=sk_live_xxx"])

    assert stderr =~ "API key providers are not supported"
    assert Repo.aggregate(ProviderSchema, :count, :id) == 0
  end
end

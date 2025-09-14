defmodule Tango.ProviderIntegrationTest do
  use Tango.DatabaseCase, async: true

  alias Tango.Provider

  describe "Provider CRUD operations" do
    test "creates provider with valid config" do
      attrs = %{
        name: "github",
        slug: "github",
        client_secret: "test_secret",
        config: %{
          "display_name" => "GitHub",
          "client_id" => "test_client_id",
          "auth_url" => "https://github.com/login/oauth/authorize",
          "token_url" => "https://github.com/login/oauth/access_token",
          "auth_mode" => "OAUTH2"
        }
      }

      assert {:ok, provider} = Provider.create_provider(attrs)
      assert provider.name == "github"
      assert provider.config["client_id"] == "test_client_id"
    end

    test "lists active providers" do
      # Create test provider
      attrs = %{
        name: "test-provider",
        slug: "test-provider",
        client_secret: "secret",
        config: %{
          "display_name" => "Test Provider",
          "client_id" => "client_id",
          "auth_url" => "https://example.com/auth",
          "token_url" => "https://example.com/token",
          "auth_mode" => "OAUTH2"
        }
      }

      {:ok, _provider} = Provider.create_provider(attrs)

      providers = Provider.list_providers()
      assert length(providers) == 1
      assert hd(providers).name == "test-provider"
    end

    test "gets provider by name" do
      attrs = %{
        name: "github",
        slug: "github",
        client_secret: "secret",
        config: %{
          "display_name" => "GitHub",
          "client_id" => "client_id",
          "auth_url" => "https://github.com/auth",
          "token_url" => "https://github.com/token",
          "auth_mode" => "OAUTH2"
        }
      }

      {:ok, created_provider} = Provider.create_provider(attrs)

      assert {:ok, found_provider} = Provider.get_provider("github")
      assert found_provider.id == created_provider.id
    end
  end
end

defmodule Tango.Schemas.ProviderTest do
  use Tango.DatabaseCase, async: true

  alias Tango.Schemas.Provider

  describe "changeset/2" do
    test "valid changeset with required fields" do
      attrs = %{
        slug: "github",
        name: "GitHub",
        client_secret: "secret_123",
        config: %{
          "client_id" => "client_123",
          "auth_url" => "https://github.com/login/oauth/authorize",
          "token_url" => "https://github.com/login/oauth/access_token"
        }
      }

      changeset = Provider.changeset(%Provider{}, attrs)
      assert changeset.valid?
    end

    test "invalid changeset without required fields" do
      changeset = Provider.changeset(%Provider{}, %{})
      refute changeset.valid?

      assert %{
               slug: ["can't be blank"],
               name: ["can't be blank"],
               client_secret: ["can't be blank"]
             } = errors_on(changeset)
    end

    test "validates slug length" do
      base_attrs = %{name: "Test", client_secret: "secret"}

      # Too short (empty) - this triggers "can't be blank" not length validation
      changeset = Provider.changeset(%Provider{}, Map.put(base_attrs, :slug, ""))
      errors = errors_on(changeset)
      assert "can't be blank" in errors[:slug]

      # Too long
      long_slug = String.duplicate("a", 256)
      changeset = Provider.changeset(%Provider{}, Map.put(base_attrs, :slug, long_slug))
      errors = errors_on(changeset)
      assert "should be at most 255 character(s)" in errors[:slug]
    end

    test "validates name length" do
      base_attrs = %{slug: "test", client_secret: "secret"}

      # Too short (empty) - this triggers "can't be blank" not length validation
      changeset = Provider.changeset(%Provider{}, Map.put(base_attrs, :name, ""))
      errors = errors_on(changeset)
      assert "can't be blank" in errors[:name]

      # Too long
      long_name = String.duplicate("a", 256)
      changeset = Provider.changeset(%Provider{}, Map.put(base_attrs, :name, long_name))
      errors = errors_on(changeset)
      assert "should be at most 255 character(s)" in errors[:name]
    end

    test "validates config structure" do
      # Missing required config fields
      attrs = %{
        slug: "test",
        name: "Test",
        client_secret: "secret",
        config: %{"client_id" => "123"}
      }

      changeset = Provider.changeset(%Provider{}, attrs)
      refute changeset.valid?
      assert %{config: ["must contain client_id, auth_url, and token_url"]} = errors_on(changeset)
    end

    test "accepts nil config" do
      attrs = %{
        slug: "test",
        name: "Test",
        client_secret: "secret",
        config: nil
      }

      changeset = Provider.changeset(%Provider{}, attrs)
      assert changeset.valid?
    end

    test "validates config must be a map" do
      attrs = %{
        slug: "test",
        name: "Test",
        client_secret: "secret",
        config: "invalid_config"
      }

      changeset = Provider.changeset(%Provider{}, attrs)
      refute changeset.valid?
      errors = errors_on(changeset)
      # The validation message might be "is invalid" for wrong type
      assert "is invalid" in errors[:config] or "must be a map" in errors[:config]
    end

    test "sets default values" do
      # Valid changeset to test defaults
      changeset =
        Provider.changeset(%Provider{}, %{
          slug: "test",
          name: "Test",
          client_secret: "secret",
          config: %{
            "client_id" => "test_client",
            "auth_url" => "https://example.com/auth",
            "token_url" => "https://example.com/token"
          }
        })

      assert changeset.valid?

      # Verify struct defaults
      provider = %Provider{}
      assert provider.config == %{}
      assert provider.default_scopes == []
      assert provider.active == true
      assert provider.metadata == %{}
    end
  end

  describe "get_config/1" do
    test "returns config map when present" do
      config = %{"client_id" => "123", "auth_url" => "https://example.com"}
      provider = %Provider{config: config}

      assert {:ok, ^config} = Provider.get_config(provider)
    end

    test "returns empty map when config is nil" do
      provider = %Provider{config: nil}

      assert {:ok, %{}} = Provider.get_config(provider)
    end

    test "returns error for invalid provider" do
      assert {:error, :invalid_config} = Provider.get_config("invalid")
      assert {:error, :invalid_config} = Provider.get_config(nil)
    end
  end

  describe "get_oauth_credentials/1" do
    test "returns OAuth credentials from config" do
      config = %{
        "client_id" => "client_123",
        "auth_url" => "https://github.com/oauth/authorize",
        "token_url" => "https://github.com/oauth/token",
        "auth_mode" => "OAUTH2"
      }

      provider = %Provider{
        config: config,
        client_secret: "secret_123"
      }

      assert {:ok, credentials} = Provider.get_oauth_credentials(provider)
      assert credentials.client_id == "client_123"
      assert credentials.client_secret == "secret_123"
      assert credentials.auth_url == "https://github.com/oauth/authorize"
      assert credentials.token_url == "https://github.com/oauth/token"
      assert credentials.auth_mode == "OAUTH2"
    end

    test "handles provider with nil config" do
      provider = %Provider{config: nil, client_secret: "secret"}

      assert {:ok, credentials} = Provider.get_oauth_credentials(provider)
      assert credentials.client_id == nil
      assert credentials.client_secret == "secret"
    end
  end

  describe "from_nango_config/3" do
    test "creates changeset from Nango configuration" do
      nango_config = %{
        "display_name" => "GitHub OAuth",
        "authorization_url" => "https://github.com/login/oauth/authorize",
        "token_url" => "https://github.com/login/oauth/access_token",
        "auth_mode" => "OAUTH2",
        "scopes" => ["user:email", "repo"],
        "categories" => ["Developer Tools"],
        "docs" => "https://docs.github.com/oauth"
      }

      opts = [client_id: "github_client", client_secret: "github_secret"]

      changeset = Provider.from_nango_config("github", nango_config, opts)

      assert changeset.valid?
      assert get_change(changeset, :slug) == "github"
      assert get_change(changeset, :name) == "GitHub OAuth"
      assert get_change(changeset, :default_scopes) == ["user:email", "repo"]
      # active defaults to true, so get_change returns nil unless explicitly changed
      assert get_field(changeset, :active) == true

      config = get_change(changeset, :config)
      assert config["client_id"] == "github_client"
      assert config["auth_url"] == "https://github.com/login/oauth/authorize"
      assert config["token_url"] == "https://github.com/login/oauth/access_token"
      assert config["auth_mode"] == "OAUTH2"

      metadata = get_change(changeset, :metadata)
      assert metadata["categories"] == ["Developer Tools"]
      assert metadata["docs_url"] == "https://docs.github.com/oauth"
    end

    test "handles minimal Nango config" do
      nango_config = %{
        "authorization_url" => "https://example.com/oauth/authorize",
        "token_url" => "https://example.com/oauth/token"
      }

      opts = [client_id: "test_client", client_secret: "test_secret"]

      changeset = Provider.from_nango_config("test-provider", nango_config, opts)

      assert changeset.valid?
      assert get_change(changeset, :slug) == "test-provider"
      # Falls back to slug when no display_name
      assert get_change(changeset, :name) == "test-provider"
      # default_scopes defaults to [], so get_change returns nil unless explicitly changed
      assert get_field(changeset, :default_scopes) == []

      config = get_change(changeset, :config)
      # Default auth_mode
      assert config["auth_mode"] == "OAUTH2"

      metadata = get_change(changeset, :metadata)
      assert metadata["categories"] == []
    end

    test "respects options for active flag" do
      nango_config = %{
        "authorization_url" => "https://example.com/oauth/authorize",
        "token_url" => "https://example.com/oauth/token"
      }

      opts = [client_id: "test", client_secret: "secret", active: false]

      changeset = Provider.from_nango_config("test", nango_config, opts)
      assert get_field(changeset, :active) == false
    end
  end

  # Helper function to extract errors (similar to Phoenix's errors_on/1)
  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end

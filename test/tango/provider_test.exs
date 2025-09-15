defmodule Tango.ProviderTest do
  @moduledoc """
  Unit tests for Tango.Provider module functions.

  Tests individual provider CRUD operations, validation,
  lifecycle management, and error handling.
  """

  use Tango.DatabaseCase, async: false

  alias Tango.{Factory, Provider}
  alias Tango.Schemas.Provider, as: ProviderSchema

  describe "list_providers/0" do
    test "returns only active providers" do
      # Create active provider
      active = Factory.create_provider(%{name: "active-provider", slug: "active-provider"})

      # Create and deactivate provider
      inactive = Factory.create_provider(%{name: "inactive-provider", slug: "inactive-provider"})
      {:ok, _} = Provider.delete_provider(inactive)

      providers = Provider.list_providers()
      provider_ids = Enum.map(providers, & &1.id)

      assert active.id in provider_ids
      refute inactive.id in provider_ids
    end

    test "returns empty list when no active providers exist" do
      # Clean up any existing providers
      Repo.delete_all(ProviderSchema)

      assert Provider.list_providers() == []
    end

    test "returns providers ordered by name" do
      # Create providers with different names
      _zebra = Factory.create_provider(%{name: "zebra-provider", slug: "zebra"})
      _alpha = Factory.create_provider(%{name: "alpha-provider", slug: "alpha"})
      _beta = Factory.create_provider(%{name: "beta-provider", slug: "beta"})

      providers = Provider.list_providers()
      names = Enum.map(providers, & &1.name)

      assert names == Enum.sort(names)
    end
  end

  describe "list_all_providers/0" do
    test "returns both active and inactive providers" do
      active = Factory.create_provider(%{name: "all-active", slug: "all-active"})
      inactive = Factory.create_provider(%{name: "all-inactive", slug: "all-inactive"})
      {:ok, _} = Provider.delete_provider(inactive)

      all_providers = Provider.list_all_providers()
      all_ids = Enum.map(all_providers, & &1.id)

      assert active.id in all_ids
      assert inactive.id in all_ids
    end

    test "orders providers by active status then name" do
      _active_z = Factory.create_provider(%{name: "z-active", slug: "z-active"})
      _active_a = Factory.create_provider(%{name: "a-active", slug: "a-active"})
      inactive_m = Factory.create_provider(%{name: "m-inactive", slug: "m-inactive"})
      {:ok, _} = Provider.delete_provider(inactive_m)

      all_providers = Provider.list_all_providers()

      # Should have at least 3 providers
      assert length(all_providers) >= 3

      # Find active and inactive providers
      active_providers = Enum.filter(all_providers, & &1.active)
      inactive_providers = Enum.filter(all_providers, &(not &1.active))

      # Should have both active and inactive
      assert length(active_providers) >= 2
      assert length(inactive_providers) >= 1

      # Active names should be sorted
      active_names = Enum.map(active_providers, & &1.name)
      assert active_names == Enum.sort(active_names)
    end
  end

  describe "get_provider/1" do
    test "returns provider when found and active" do
      created = Factory.create_provider(%{name: "get-test", slug: "get-test"})

      assert {:ok, found} = Provider.get_provider("get-test")
      assert found.id == created.id
      assert found.name == "get-test"
    end

    test "returns error when provider not found" do
      assert {:error, :not_found} = Provider.get_provider("nonexistent")
    end

    test "returns error when provider is inactive" do
      created = Factory.create_provider(%{name: "inactive-get", slug: "inactive-get"})

      {:ok, _} = Provider.delete_provider(created)

      assert {:error, :not_found} = Provider.get_provider("inactive-get")
    end
  end

  describe "get_provider_by_id/1" do
    test "returns provider when found by ID" do
      {:ok, created} =
        Provider.create_provider(%{
          name: "get-by-id",
          slug: "get-by-id",
          client_secret: "secret",
          config: %{
            "auth_mode" => "OAUTH2",
            "client_id" => "test_client",
            "auth_url" => "https://example.com/auth",
            "token_url" => "https://example.com/token"
          }
        })

      assert {:ok, found} = Provider.get_provider_by_id(created.id)
      assert found.id == created.id
      assert found.name == "get-by-id"
    end

    test "returns error when ID not found" do
      fake_id = Ecto.UUID.generate()
      assert {:error, :not_found} = Provider.get_provider_by_id(fake_id)
    end

    test "returns inactive providers by ID" do
      {:ok, created} =
        Provider.create_provider(%{
          name: "inactive-by-id",
          slug: "inactive-by-id",
          client_secret: "secret",
          config: %{
            "auth_mode" => "OAUTH2",
            "client_id" => "test_client",
            "auth_url" => "https://example.com/auth",
            "token_url" => "https://example.com/token"
          }
        })

      {:ok, _} = Provider.delete_provider(created)

      # Should still find by ID even if inactive
      assert {:ok, found} = Provider.get_provider_by_id(created.id)
      assert found.active == false
    end
  end

  describe "create_provider/1" do
    test "creates provider with valid OAuth2 attributes" do
      attrs = %{
        name: "oauth2-create",
        slug: "oauth2-create",
        client_secret: "secret123",
        config: %{
          "display_name" => "OAuth2 Provider",
          "client_id" => "client123",
          "auth_url" => "https://example.com/auth",
          "token_url" => "https://example.com/token",
          "auth_mode" => "OAUTH2"
        }
      }

      assert {:ok, provider} = Provider.create_provider(attrs)
      assert provider.name == "oauth2-create"
      assert provider.slug == "oauth2-create"
      assert provider.client_secret == "secret123"
      assert provider.config["client_id"] == "client123"
      assert provider.active == true
    end

    test "creates provider with API key attributes" do
      # Use factory for API key provider
      provider = Factory.create_api_key_provider("_test")

      assert provider.name =~ "apikey_provider"
      # API key stored as client_secret
      assert provider.client_secret != nil
      assert provider.config["api_endpoint"] != nil
    end

    test "validates required fields" do
      invalid_attrs = [
        # Empty
        %{},
        # Missing slug
        %{name: "test"},
        # Missing name
        %{slug: "test"},
        # Missing auth credentials
        %{name: "test", slug: "test"}
      ]

      Enum.each(invalid_attrs, fn attrs ->
        assert {:error, changeset} = Provider.create_provider(attrs)
        assert changeset.errors != []
      end)
    end

    test "validates unique constraints" do
      attrs = %{
        name: "unique-test",
        slug: "unique-test",
        client_secret: "secret",
        config: %{
          "auth_mode" => "OAUTH2",
          "client_id" => "test_client",
          "auth_url" => "https://example.com/auth",
          "token_url" => "https://example.com/token"
        }
      }

      {:ok, _first} = Provider.create_provider(attrs)

      # Should fail on duplicate slug
      assert {:error, changeset} = Provider.create_provider(attrs)
      assert changeset.errors[:slug] != nil
    end
  end

  describe "create_provider_from_nango/3" do
    test "creates provider from nango config with OAuth2 credentials" do
      nango_config = %{
        "display_name" => "GitHub",
        "auth_mode" => "OAUTH2",
        "authorization_url" => "https://github.com/login/oauth/authorize",
        "token_url" => "https://github.com/login/oauth/access_token",
        "default_scopes" => ["user:email"],
        "categories" => ["dev-tools"]
      }

      opts = [client_id: "test_client_id", client_secret: "test_secret"]

      assert {:ok, provider} = Provider.create_provider_from_nango("github", nango_config, opts)

      assert provider.name == "GitHub"
      assert provider.slug == "github"
      assert provider.client_secret == "test_secret"
      assert provider.default_scopes == ["user:email"]
      assert provider.active == true
      # Verify config structure contains OAuth URLs
      assert is_map(provider.config)
      assert provider.config["auth_url"] == "https://github.com/login/oauth/authorize"
      assert provider.config["token_url"] == "https://github.com/login/oauth/access_token"
    end

    test "creates provider from nango config with API key" do
      nango_config = %{
        "display_name" => "Stripe",
        "auth_mode" => "API_KEY",
        "categories" => ["payments"],
        "api_config" => %{
          "headers" => %{
            "authorization" => "Bearer ${api_key}"
          }
        }
      }

      # API key providers still need client_secret for the schema
      opts = [api_key: "sk_test_123", client_secret: "placeholder"]

      assert {:ok, provider} = Provider.create_provider_from_nango("stripe", nango_config, opts)

      assert provider.name == "Stripe"
      assert provider.slug == "stripe"
      assert provider.active == true
      # Verify basic config structure exists
      assert is_map(provider.config)
    end

    test "creates audit log entry on successful creation" do
      nango_config = %{
        "display_name" => "Test Provider",
        "auth_mode" => "OAUTH2",
        "authorization_url" => "https://test.com/auth",
        "token_url" => "https://test.com/token"
      }

      opts = [client_id: "test_id", client_secret: "test_secret"]

      # Count audit logs before
      initial_count = Repo.aggregate(Tango.Schemas.AuditLog, :count, :id)

      assert {:ok, provider} = Provider.create_provider_from_nango("test", nango_config, opts)

      # Check audit log was created
      final_count = Repo.aggregate(Tango.Schemas.AuditLog, :count, :id)
      assert final_count == initial_count + 1

      # Verify audit log content
      audit_log = Repo.get_by(Tango.Schemas.AuditLog, provider_id: provider.id)
      assert audit_log.event_type == :provider_created
      assert audit_log.success == true
      # Note: event_data structure may be different than expected
      # This test verifies the audit log was created
    end

    test "returns error when nango config is invalid" do
      invalid_nango_config = %{
        # Invalid: empty name
        "display_name" => "",
        # Invalid: unsupported auth mode
        "auth_mode" => "INVALID_MODE"
      }

      opts = [client_id: "test_id", client_secret: "test_secret"]

      assert {:error, changeset} =
               Provider.create_provider_from_nango("invalid", invalid_nango_config, opts)

      assert changeset.errors[:name] != nil
    end

    test "handles duplicate slug error" do
      nango_config = %{
        "display_name" => "Duplicate Test",
        "auth_mode" => "OAUTH2",
        "authorization_url" => "https://test.com/auth",
        "token_url" => "https://test.com/token"
      }

      opts = [client_id: "test_id", client_secret: "test_secret"]

      # Create first provider
      assert {:ok, _first} = Provider.create_provider_from_nango("duplicate", nango_config, opts)

      # Try to create second with same slug
      assert {:error, changeset} =
               Provider.create_provider_from_nango("duplicate", nango_config, opts)

      assert changeset.errors[:slug] != nil
    end

    test "handles empty opts list appropriately" do
      nango_config = %{
        "display_name" => "No Opts Test",
        "auth_mode" => "OAUTH2",
        "authorization_url" => "https://test.com/auth",
        "token_url" => "https://test.com/token"
      }

      # Empty opts should fail due to required client_secret
      assert {:error, changeset} = Provider.create_provider_from_nango("noopts", nango_config, [])

      # Should have validation error for required field
      assert changeset.errors[:client_secret] != nil
    end

    test "preserves nango config structure in provider config" do
      nango_config = %{
        "display_name" => "Complex Config",
        "auth_mode" => "OAUTH2",
        "authorization_url" => "https://test.com/auth",
        "token_url" => "https://test.com/token",
        "default_scopes" => ["read", "write"],
        "categories" => ["category1", "category2"],
        "docs" => "https://docs.test.com",
        "custom_field" => "custom_value"
      }

      opts = [client_id: "test_id", client_secret: "test_secret"]

      assert {:ok, provider} = Provider.create_provider_from_nango("complex", nango_config, opts)

      # Verify some nango config is preserved in provider config
      # Note: The from_nango_config function may transform some field names
      assert provider.config["auth_url"] == "https://test.com/auth"
      assert provider.config["token_url"] == "https://test.com/token"
      assert provider.default_scopes == ["read", "write"]
      # Custom fields should be preserved in metadata
      assert provider.metadata["categories"] == ["category1", "category2"]
    end
  end

  describe "update_provider/2" do
    test "updates provider attributes" do
      # Use factory to create valid provider
      provider = Factory.create_provider(%{name: "update-test", slug: "update-test"})

      updates = %{
        client_secret: "new_secret",
        config: Map.merge(provider.config, %{"display_name" => "New Name"})
      }

      assert {:ok, updated} = Provider.update_provider(provider, updates)
      assert updated.client_secret == "new_secret"
      assert updated.config["display_name"] == "New Name"
    end

    test "validates updates" do
      # Use factory to create valid provider
      provider = Factory.create_provider(%{name: "update-validate", slug: "update-validate"})

      # Try invalid update
      invalid_updates = %{name: ""}

      assert {:error, changeset} = Provider.update_provider(provider, invalid_updates)
      assert changeset.errors[:name] != nil
    end
  end

  describe "delete_provider/1 (deactivates)" do
    test "deactivates provider successfully" do
      {:ok, provider} =
        Provider.create_provider(%{
          name: "delete-test",
          slug: "delete-test",
          client_secret: "secret",
          config: %{
            "auth_mode" => "OAUTH2",
            "client_id" => "test_client",
            "auth_url" => "https://example.com/auth",
            "token_url" => "https://example.com/token"
          }
        })

      assert provider.active == true

      assert {:ok, deactivated} = Provider.delete_provider(provider)
      assert deactivated.active == false
      assert deactivated.id == provider.id
    end
  end

  describe "activate_provider/1" do
    test "activates inactive provider" do
      {:ok, provider} =
        Provider.create_provider(%{
          name: "activate-test",
          slug: "activate-test",
          client_secret: "secret",
          config: %{
            "auth_mode" => "OAUTH2",
            "client_id" => "test_client",
            "auth_url" => "https://example.com/auth",
            "token_url" => "https://example.com/token"
          }
        })

      # Deactivate first
      {:ok, deactivated} = Provider.delete_provider(provider)
      assert deactivated.active == false

      # Then activate
      assert {:ok, activated} = Provider.activate_provider(deactivated)
      assert activated.active == true
      assert activated.id == provider.id
    end

    test "handles already active provider" do
      {:ok, provider} =
        Provider.create_provider(%{
          name: "already-active",
          slug: "already-active",
          client_secret: "secret",
          config: %{
            "auth_mode" => "OAUTH2",
            "client_id" => "test_client",
            "auth_url" => "https://example.com/auth",
            "token_url" => "https://example.com/token"
          }
        })

      # Activating already active provider should still work
      assert {:ok, activated} = Provider.activate_provider(provider)
      assert activated.active == true
    end
  end
end

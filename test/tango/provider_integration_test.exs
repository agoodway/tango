defmodule Tango.ProviderIntegrationTest do
  @moduledoc """
  Integration tests for provider workflows and audit logging.

  Tests provider lifecycle workflows, audit trail creation,
  and integration scenarios across multiple operations.
  """

  use Tango.DatabaseCase, async: false

  import Ecto.Query

  alias Tango.{Factory, Provider}
  alias Tango.Schemas.AuditLog

  describe "provider lifecycle workflow with audit logging" do
    test "complete provider lifecycle creates comprehensive audit trail" do
      initial_audit_count = Repo.aggregate(AuditLog, :count, :id)

      # Step 1: Create provider using factory
      attrs = %{
        name: "lifecycle-test",
        slug: "lifecycle-test",
        client_secret: "secret123",
        config: %{
          "display_name" => "Lifecycle Test Provider",
          "client_id" => "lifecycle_client_id",
          "auth_url" => "https://example.com/auth",
          "token_url" => "https://example.com/token",
          "auth_mode" => "OAUTH2"
        }
      }

      {:ok, provider} = Provider.create_provider(attrs)

      # Should create audit log for creation
      creation_audit =
        Repo.one(
          from(a in AuditLog,
            where: a.event_type == :provider_created and a.provider_id == ^provider.id,
            limit: 1
          )
        )

      assert creation_audit != nil
      assert creation_audit.provider_id == provider.id
      assert creation_audit.event_type == :provider_created

      # Step 2: Update provider
      updates = %{
        config: %{
          "display_name" => "Updated Provider Name",
          "client_id" => "new_client_id",
          "auth_url" => "https://example.com/auth",
          "token_url" => "https://example.com/token",
          "auth_mode" => "OAUTH2"
        }
      }

      {:ok, _updated_provider} = Provider.update_provider(provider, updates)

      # Should create audit log for update
      update_audit =
        Repo.one(
          from(a in AuditLog,
            where: a.event_type == :provider_updated and a.provider_id == ^provider.id,
            limit: 1
          )
        )

      assert update_audit != nil
      assert update_audit.provider_id == provider.id

      # Step 3: Deactivate provider
      {:ok, deactivated} = Provider.delete_provider(provider)
      assert deactivated.active == false

      # Should create audit log for deactivation
      deactivation_audit =
        Repo.one(
          from(a in AuditLog,
            where: a.event_type == :provider_deleted and a.provider_id == ^provider.id,
            limit: 1
          )
        )

      assert deactivation_audit != nil

      # Step 4: Reactivate provider
      {:ok, reactivated} = Provider.activate_provider(deactivated)
      assert reactivated.active == true

      # Should create audit log for activation
      activation_audit =
        Repo.one(
          from(a in AuditLog,
            where: a.event_type == :provider_updated and a.provider_id == ^provider.id,
            order_by: [desc: a.inserted_at],
            limit: 1
          )
        )

      assert activation_audit != nil

      final_audit_count = Repo.aggregate(AuditLog, :count, :id)

      # Should have created audit logs for operations
      assert final_audit_count > initial_audit_count
    end

    test "provider creation with OAuth connections workflow" do
      # Create provider using factory
      provider = Factory.create_github_provider("_workflow")

      # Create OAuth connection for this provider
      tenant_id = "tenant-workflow-test"
      conn = Factory.create_github_connection(provider, tenant_id, "_workflow")

      # Verify provider is correctly associated
      assert conn.provider_id == provider.id

      # Provider should still be active
      {:ok, active_provider} = Provider.get_provider("github_test_workflow")
      assert active_provider.active == true

      # Should be listed in active providers
      active_providers = Provider.list_providers()
      assert Enum.any?(active_providers, &(&1.id == provider.id))

      # Deactivating provider with active connections should be handled
      # (business logic determines if this should be allowed or prevented)
      result = Provider.delete_provider(provider)
      # Assuming deactivation is allowed
      assert {:ok, _} = result

      # Connection should still exist but provider is inactive
      updated_conn = Repo.get!(Tango.Schemas.Connection, conn.id)
      assert updated_conn.provider_id == provider.id

      # Provider should not appear in active list
      active_providers_after = Provider.list_providers()
      refute Enum.any?(active_providers_after, &(&1.id == provider.id))

      # But should appear in all providers list
      all_providers = Provider.list_all_providers()
      assert Enum.any?(all_providers, &(&1.id == provider.id))
    end

    test "bulk provider operations maintain data consistency" do
      initial_audit_count = Repo.aggregate(AuditLog, :count, :id)

      # Create multiple providers
      provider_names = ["bulk-test-1", "bulk-test-2", "bulk-test-3"]

      providers =
        Enum.map(provider_names, fn name ->
          Factory.create_github_provider("_#{name}")
        end)

      # All should be active initially
      active_providers = Provider.list_providers()
      provider_ids = MapSet.new(providers, & &1.id)
      active_ids = MapSet.new(active_providers, & &1.id)

      assert MapSet.subset?(provider_ids, active_ids)

      # Deactivate all providers (use provider structs)
      Enum.each(providers, fn provider ->
        {:ok, _} = Provider.delete_provider(provider)
      end)

      # None should appear in active list
      active_after_deactivation = Provider.list_providers()
      active_ids_after = MapSet.new(active_after_deactivation, & &1.id)

      assert MapSet.disjoint?(provider_ids, active_ids_after)

      # All should appear in complete list
      all_providers = Provider.list_all_providers()
      all_ids = MapSet.new(all_providers, & &1.id)

      assert MapSet.subset?(provider_ids, all_ids)

      final_audit_count = Repo.aggregate(AuditLog, :count, :id)

      # Should have created audit logs for operations
      assert final_audit_count > initial_audit_count
    end
  end

  describe "provider configuration workflow" do
    test "provider configuration validation workflow" do
      # Test OAuth2 provider creation using factory
      oauth2_provider = Factory.create_github_provider("_config_oauth2")
      assert oauth2_provider.config["auth_url"] =~ "github.com"

      # Test API key provider creation using factory
      api_key_provider = Factory.create_api_key_provider("_config_api")
      # API key stored as client_secret
      assert api_key_provider.client_secret != nil

      # Both should appear in provider listings
      all_providers = Provider.list_providers()
      provider_ids = Enum.map(all_providers, & &1.id)

      assert oauth2_provider.id in provider_ids
      assert api_key_provider.id in provider_ids
    end
  end
end

defmodule Tango.Migrations do
  @moduledoc """
  Manages database migrations for Tango.

  ## Usage

  In your Phoenix application, create a migration:

      mix ecto.gen.migration add_tango_tables

  Then in the generated migration file:

      defmodule MyApp.Repo.Migrations.AddTangoTables do
        use Ecto.Migration

        def up do
          Tango.Migrations.up()
        end

        def down do
          Tango.Migrations.down()
        end
      end
  """

  use Ecto.Migration

  def up(opts \\ []) do
    prefix = get_prefix(opts)

    # Create custom schema if configured and not using default "public"
    if prefix != "public" do
      execute("CREATE SCHEMA IF NOT EXISTS \"#{prefix}\"")
    end

    # Providers table
    create table(:tango_providers, primary_key: false, prefix: prefix) do
      add(:id, :uuid, primary_key: true, default: fragment("gen_random_uuid()"))
      add(:slug, :string, null: false)
      add(:name, :string, null: false)
      add(:config, :map, default: %{})
      add(:client_secret, :binary)
      add(:default_scopes, {:array, :string}, default: [])
      add(:active, :boolean, default: true, null: false)
      add(:metadata, :map, default: %{})

      timestamps()
    end

    create(unique_index(:tango_providers, [:slug], prefix: prefix))
    create(index(:tango_providers, [:active], prefix: prefix))

    # OAuth sessions table
    create table(:tango_oauth_sessions, primary_key: false, prefix: prefix) do
      add(:id, :uuid, primary_key: true, default: fragment("gen_random_uuid()"))

      add(:provider_id, references(:tango_providers, type: :uuid, on_delete: :delete_all),
        null: false
      )

      add(:tenant_id, :string, null: false)
      add(:session_token, :string, null: false)
      add(:state, :string, null: false)
      add(:code_verifier, :string)
      add(:redirect_uri, :text)
      add(:scopes, {:array, :string}, default: [])
      add(:metadata, :map, default: %{})
      add(:expires_at, :timestamptz, null: false)

      timestamps()
    end

    create(unique_index(:tango_oauth_sessions, [:session_token], prefix: prefix))
    create(unique_index(:tango_oauth_sessions, [:state, :tenant_id], prefix: prefix))
    create(index(:tango_oauth_sessions, [:provider_id], prefix: prefix))
    create(index(:tango_oauth_sessions, [:tenant_id], prefix: prefix))
    create(index(:tango_oauth_sessions, [:tenant_id, :provider_id], prefix: prefix))
    create(index(:tango_oauth_sessions, [:expires_at], prefix: prefix))
    create(index(:tango_oauth_sessions, [:expires_at, :tenant_id], prefix: prefix))

    # Connections table
    create table(:tango_connections, primary_key: false, prefix: prefix) do
      add(:id, :uuid, primary_key: true, default: fragment("gen_random_uuid()"))

      add(:provider_id, references(:tango_providers, type: :uuid, on_delete: :delete_all),
        null: false
      )

      add(:tenant_id, :string, null: false)
      add(:access_token, :binary, null: false)
      add(:refresh_token, :binary)
      add(:token_type, :string, default: "bearer", null: false)
      add(:expires_at, :utc_datetime)
      add(:granted_scopes, {:array, :string}, default: [])
      add(:raw_payload, :map, default: %{})
      add(:metadata, :map, default: %{})
      add(:status, :string, default: "active", null: false)
      add(:last_used_at, :utc_datetime)
      add(:refresh_attempts, :integer, default: 0, null: false)
      add(:last_refresh_failure, :text)
      add(:next_refresh_at, :utc_datetime)
      add(:refresh_exhausted, :boolean, default: false, null: false)
      add(:auto_refresh_enabled, :boolean, default: true, null: false)
      add(:connection_config, :map, default: %{}, null: false)

      timestamps()
    end

    create(index(:tango_connections, [:tenant_id], prefix: prefix))
    create(index(:tango_connections, [:tenant_id, :provider_id], prefix: prefix))
    create(index(:tango_connections, [:tenant_id, :status], prefix: prefix))
    create(index(:tango_connections, [:tenant_id, :expires_at], prefix: prefix))
    create(index(:tango_connections, [:tenant_id, :last_used_at], prefix: prefix))
    create(index(:tango_connections, [:tenant_id, :status, :expires_at], prefix: prefix))

    create(
      unique_index(:tango_connections, [:provider_id, :tenant_id],
        where: "status = 'active'",
        prefix: prefix
      )
    )

    # Audit logs table
    create table(:tango_audit_logs, primary_key: false, prefix: prefix) do
      add(:id, :uuid, primary_key: true, default: fragment("gen_random_uuid()"))
      add(:provider_id, references(:tango_providers, type: :uuid, on_delete: :delete_all))
      add(:connection_id, references(:tango_connections, type: :uuid, on_delete: :delete_all))
      add(:session_id, :string)
      add(:tenant_id, :string, null: false)
      add(:event_type, :string, null: false)
      add(:success, :boolean, null: false)
      add(:error_code, :string)
      add(:event_data, :jsonb, default: "{}")
      add(:sensitive_data_hash, :string)
      add(:user_agent, :text)
      add(:ip_address, :string)
      add(:occurred_at, :utc_datetime, null: false)

      timestamps(updated_at: false)
    end

    create(index(:tango_audit_logs, [:provider_id], prefix: prefix))
    create(index(:tango_audit_logs, [:connection_id], prefix: prefix))
    create(index(:tango_audit_logs, [:tenant_id], prefix: prefix))
    create(index(:tango_audit_logs, [:event_type], prefix: prefix))
    create(index(:tango_audit_logs, [:occurred_at], prefix: prefix))
    create(index(:tango_audit_logs, [:tenant_id, :event_type, :occurred_at], prefix: prefix))
    create(index(:tango_audit_logs, [:tenant_id, :provider_id, :occurred_at], prefix: prefix))
  end

  def down(opts \\ []) do
    prefix = get_prefix(opts)

    drop(table(:tango_audit_logs, prefix: prefix))
    drop(table(:tango_connections, prefix: prefix))
    drop(table(:tango_oauth_sessions, prefix: prefix))
    drop(table(:tango_providers, prefix: prefix))

    if prefix != "public" do
      execute("DROP SCHEMA IF EXISTS \"#{prefix}\" CASCADE")
    end
  end

  defp get_prefix(opts) do
    opts[:prefix] || Application.get_env(:tango, :schema_prefix, "public")
  end
end

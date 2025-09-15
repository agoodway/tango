defmodule Tango.Migrations.CreateTangoConnections do
  use Ecto.Migration

  def change do
    prefix = Application.get_env(:tango, :schema_prefix, "public")
    create table(:tango_connections, primary_key: false, prefix: prefix) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :provider_id, references(:tango_providers, type: :uuid, on_delete: :delete_all), null: false
      add :tenant_id, :string, null: false
      # Encrypted token storage
      add :access_token, :binary, null: false
      add :refresh_token, :binary
      add :token_type, :string, default: "bearer", null: false
      add :expires_at, :utc_datetime
      add :granted_scopes, {:array, :string}, default: []
      add :raw_payload, :map, default: %{}
      add :metadata, :map, default: %{}

      # Connection status and lifecycle
      add :status, :string, default: "active", null: false
      add :last_used_at, :utc_datetime

      # Token refresh management
      add :refresh_attempts, :integer, default: 0, null: false
      add :last_refresh_failure, :text
      add :next_refresh_at, :utc_datetime
      add :refresh_exhausted, :boolean, default: false, null: false
      add :auto_refresh_enabled, :boolean, default: true, null: false
      add :connection_config, :map, default: %{}, null: false

      timestamps()
    end

    # Tenant-first indexes for multi-tenant security and performance
    create index(:tango_connections, [:tenant_id], prefix: prefix)
    create index(:tango_connections, [:tenant_id, :provider_id], prefix: prefix)
    create index(:tango_connections, [:tenant_id, :status], prefix: prefix)
    create index(:tango_connections, [:tenant_id, :expires_at], prefix: prefix)
    create index(:tango_connections, [:tenant_id, :last_used_at], prefix: prefix)
    create index(:tango_connections, [:tenant_id, :status, :expires_at], prefix: prefix)

    # Unique constraint for active connections (provider_id first for existing constraint)
    create unique_index(:tango_connections, [:provider_id, :tenant_id],
                        where: "status = 'active'", prefix: prefix)
  end
end

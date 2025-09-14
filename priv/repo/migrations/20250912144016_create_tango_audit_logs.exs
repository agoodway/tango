defmodule Tango.Migrations.CreateTangoAuditLogs do
  use Ecto.Migration

  def change do
    prefix = Application.get_env(:tango, :schema_prefix, "public")
    create table(:tango_audit_logs, primary_key: false, prefix: prefix) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :provider_id, references(:tango_providers, type: :uuid, on_delete: :delete_all)
      add :connection_id, references(:tango_connections, type: :uuid, on_delete: :delete_all)
      add :session_id, :string
      add :tenant_id, :string, null: false
      add :event_type, :string, null: false
      add :success, :boolean, null: false
      add :error_code, :string
      add :event_data, :jsonb, default: "{}"
      add :sensitive_data_hash, :string
      add :user_agent, :text
      add :ip_address, :string
      add :occurred_at, :utc_datetime, null: false

      timestamps(updated_at: false)
    end

    create index(:tango_audit_logs, [:provider_id], prefix: prefix)
    create index(:tango_audit_logs, [:connection_id], prefix: prefix)
    create index(:tango_audit_logs, [:tenant_id], prefix: prefix)
    create index(:tango_audit_logs, [:event_type], prefix: prefix)
    create index(:tango_audit_logs, [:occurred_at], prefix: prefix)
  end
end

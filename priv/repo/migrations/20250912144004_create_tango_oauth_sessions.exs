defmodule Tango.Migrations.CreateTangoOAuthSessions do
  use Ecto.Migration

  def change do
    prefix = Application.get_env(:tango, :schema_prefix, "public")
    create table(:tango_oauth_sessions, primary_key: false, prefix: prefix) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :provider_id, references(:tango_providers, type: :uuid, on_delete: :delete_all), null: false
      add :tenant_id, :string, null: false
      add :session_token, :string, null: false
      add :state, :string, null: false
      add :code_verifier, :string
      add :redirect_uri, :text
      add :scopes, {:array, :string}, default: []
      add :metadata, :map, default: %{}
      add :expires_at, :timestamptz, null: false

      timestamps()
    end

    create unique_index(:tango_oauth_sessions, [:session_token], prefix: prefix)
    create unique_index(:tango_oauth_sessions, [:state, :tenant_id], prefix: prefix)
    create index(:tango_oauth_sessions, [:provider_id], prefix: prefix)
    create index(:tango_oauth_sessions, [:tenant_id], prefix: prefix)
        create index(:tango_oauth_sessions, [:tenant_id, :provider_id], prefix: prefix)

    create index(:tango_oauth_sessions, [:expires_at], prefix: prefix)
    create index(:tango_oauth_sessions, [:expires_at, :tenant_id], prefix: prefix)
  end
end

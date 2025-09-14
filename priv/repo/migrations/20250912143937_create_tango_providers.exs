defmodule Tango.Migrations.CreateTangoProviders do
  use Ecto.Migration

  def change do
    prefix = Application.get_env(:tango, :schema_prefix, "public")
    create table(:tango_providers, primary_key: false, prefix: prefix) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :slug, :string, null: false
      add :name, :string, null: false
      add :config, :map, default: %{}
      add :client_secret, :binary
      add :default_scopes, {:array, :string}, default: []
      add :active, :boolean, default: true, null: false
      add :metadata, :map, default: %{}

      timestamps()
    end

    create unique_index(:tango_providers, [:slug], prefix: prefix)
    create index(:tango_providers, [:active], prefix: prefix)
  end
end

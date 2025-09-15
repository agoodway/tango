defmodule Tango.Migrations.CreateTangoSchema do
  use Ecto.Migration

  def change do
    prefix = Application.get_env(:tango, :schema_prefix, "public")

    # Create custom schema if configured and not using default "public"
    if prefix != "public" do
      execute("CREATE SCHEMA IF NOT EXISTS \"#{prefix}\"")
    end
  end
end

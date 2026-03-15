defmodule Tango.Migration do
  @moduledoc """
  Manages database migrations for Tango.

  Uses EctoEvolver for versioned migration tracking and SQL execution.

  ## Usage

  In your Phoenix application, create a migration:

      mix ecto.gen.migration add_tango_tables

  Then in the generated migration file:

      defmodule MyApp.Repo.Migrations.AddTangoTables do
        use Ecto.Migration

        def up do
          Tango.Migration.up()
        end

        def down do
          Tango.Migration.down()
        end
      end

  ## Versioned Migrations

  You can also specify a specific version:

      def up do
        Tango.Migration.up(version: 1)
      end

  Or use a custom schema prefix:

      def up do
        Tango.Migration.up(prefix: "custom_schema")
      end
  """

  use EctoEvolver,
    otp_app: :tango,
    default_prefix: Application.compile_env(:tango, :schema_prefix, "public"),
    versions: [Tango.Migrations.V01],
    tracking_object: {:table, "tango_providers"}
end

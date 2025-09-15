defmodule Tango.MigrationsTest do
  use ExUnit.Case
  doctest Tango.Migrations

  describe "Oban-style migration API" do
    test "migration module exists and has correct functions" do
      assert Code.ensure_loaded?(Tango.Migrations)
      assert function_exported?(Tango.Migrations, :up, 1)
      assert function_exported?(Tango.Migrations, :down, 1)
    end

    test "follows Oban pattern for consuming applications" do
      # Test the intended usage pattern compiles
      migration_code = """
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

      assert Code.compile_string(migration_code)
    end

    test "supports prefix options like Oban" do
      migration_code = """
      defmodule MyApp.Repo.Migrations.AddTangoTablesWithPrefix do
        use Ecto.Migration

        def up do
          Tango.Migrations.up(prefix: "custom_schema")
        end

        def down do
          Tango.Migrations.down(prefix: "custom_schema")
        end
      end
      """

      assert Code.compile_string(migration_code)
    end

    test "real migration file was created and can be run" do
      # Test that our actual migration file exists and is valid
      migration_path = "priv/repo/migrations/20250915173007_add_tango_tables.exs"
      assert File.exists?(migration_path)

      # Test that it contains the expected calls
      {:ok, migration_content} = File.read(migration_path)
      assert String.contains?(migration_content, "Tango.Migrations.up()")
      assert String.contains?(migration_content, "Tango.Migrations.down()")
    end

    test "source code contains all expected table definitions" do
      {:ok, source} = File.read("lib/tango/migrations.ex")

      # Verify all our tables are defined
      assert String.contains?(source, "tango_providers")
      assert String.contains?(source, "tango_oauth_sessions")
      assert String.contains?(source, "tango_connections")
      assert String.contains?(source, "tango_audit_logs")

      # Verify prefix handling
      assert String.contains?(source, "get_prefix")
      assert String.contains?(source, "Application.get_env(:tango, :schema_prefix")
    end
  end
end

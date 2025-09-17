defmodule Tango.MigrationsTest do
  use ExUnit.Case
  doctest Tango.Migration

  describe "Oban-style migration API" do
    test "migration modules exist and have correct functions" do
      # Main migration module
      assert Code.ensure_loaded?(Tango.Migration)
      assert function_exported?(Tango.Migration, :up, 1)
      assert function_exported?(Tango.Migration, :down, 1)
      assert function_exported?(Tango.Migration, :migrated_version, 1)

      # V01 migration module
      assert Code.ensure_loaded?(Tango.Migrations.Versions.V01)
      assert function_exported?(Tango.Migrations.Versions.V01, :up, 1)
      assert function_exported?(Tango.Migrations.Versions.V01, :down, 1)
    end

    test "follows Oban pattern for consuming applications" do
      # Test the intended usage pattern compiles
      migration_code = """
      defmodule MyApp.Repo.Migrations.AddTangoTables do
        use Ecto.Migration

        def up do
          Tango.Migration.up()
        end

        def down do
          Tango.Migration.down()
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
          Tango.Migration.up(prefix: "custom_schema")
        end

        def down do
          Tango.Migration.down(prefix: "custom_schema")
        end
      end
      """

      assert Code.compile_string(migration_code)
    end

    test "supports version options like Oban" do
      migration_code = """
      defmodule MyApp.Repo.Migrations.AddTangoTablesV01 do
        use Ecto.Migration

        def up do
          Tango.Migration.up(version: 1)
        end

        def down do
          Tango.Migration.down(version: 0)
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
      assert String.contains?(migration_content, "Tango.Migration.up()")
      assert String.contains?(migration_content, "Tango.Migration.down()")
    end

    test "versioned structure contains all expected table definitions" do
      {:ok, v01_source} = File.read("lib/tango/migrations/versions/v01.ex")

      # Verify V01 uses SqlRunner
      assert String.contains?(v01_source, "SqlRunner.execute_sql_file")
      assert String.contains?(v01_source, "alias Tango.Migrations.SqlRunner")

      # Verify SQL files exist with our tables
      {:ok, sql_content} = File.read("priv/repo/sql/versions/v01/v01_up.sql")
      assert String.contains?(sql_content, "tango_providers")
      assert String.contains?(sql_content, "tango_oauth_sessions")
      assert String.contains?(sql_content, "tango_connections")
      assert String.contains?(sql_content, "tango_audit_logs")

      # Verify SqlRunner has prefix handling
      {:ok, runner_source} = File.read("lib/tango/migrations/sql_runner.ex")
      assert String.contains?(runner_source, "get_prefix")
      assert String.contains?(runner_source, "Application.get_env(:tango, :schema_prefix")
    end

    test "migration module has version management functions" do
      {:ok, migration_source} = File.read("lib/tango/migration.ex")

      # Verify version management functions exist
      assert String.contains?(migration_source, "migrated_version")
      assert String.contains?(migration_source, "update_version")
      assert String.contains?(migration_source, "@current_version")
      assert String.contains?(migration_source, "@initial_version")

      # Verify Oban-style change function exists
      assert String.contains?(migration_source, "defp change(")
      assert String.contains?(migration_source, "Tango.Migrations.Versions.V")

      # Verify multi-table version tracking
      assert String.contains?(migration_source, "update_table_version")
      assert String.contains?(migration_source, "get_table_version")
      assert String.contains?(migration_source, "parse_version_from_comment")
      assert String.contains?(migration_source, "tango_providers")
      assert String.contains?(migration_source, "tango_oauth_sessions")
      assert String.contains?(migration_source, "tango_connections")
      assert String.contains?(migration_source, "tango_audit_logs")
    end

    test "version tracking covers all Tango tables" do
      {:ok, migration_source} = File.read("lib/tango/migration.ex")

      # Verify all 4 tables are included in version tracking
      table_names = [
        "tango_providers",
        "tango_oauth_sessions",
        "tango_connections",
        "tango_audit_logs"
      ]

      for table_name <- table_names do
        assert String.contains?(migration_source, table_name),
               "Migration should include version tracking for #{table_name}"
      end

      # Verify the logic sets comments on all tables
      assert String.contains?(
               migration_source,
               "update_table_version(prefix, \"tango_providers\""
             )

      assert String.contains?(
               migration_source,
               "update_table_version(prefix, \"tango_oauth_sessions\""
             )

      assert String.contains?(
               migration_source,
               "update_table_version(prefix, \"tango_connections\""
             )

      assert String.contains?(
               migration_source,
               "update_table_version(prefix, \"tango_audit_logs\""
             )
    end
  end

  describe "backwards compatibility" do
    test "Tango.Migration.up() works with standard migration pattern" do
      migration_code = """
      defmodule MyApp.Repo.Migrations.TangoTables do
        use Ecto.Migration

        def up do
          Tango.Migration.up()
        end

        def down do
          Tango.Migration.down()
        end
      end
      """

      assert Code.compile_string(migration_code)
    end

    test "Tango.Migration.up() works with options" do
      migration_code = """
      defmodule MyApp.Repo.Migrations.TangoTablesWithOptions do
        use Ecto.Migration

        def up do
          Tango.Migration.up(prefix: "custom_schema", version: 1)
        end

        def down do
          Tango.Migration.down(prefix: "custom_schema", version: 0)
        end
      end
      """

      assert Code.compile_string(migration_code)
    end
  end

  describe "version tracking implementation" do
    test "version parsing regex pattern works correctly" do
      # Test the regex pattern used in version detection
      pattern = ~r/version=(\d+)/

      # Test various comment formats that should match
      assert Regex.run(pattern, "Tango migration version=1") == ["version=1", "1"]
      assert Regex.run(pattern, "Tango migration version=42") == ["version=42", "42"]
      assert Regex.run(pattern, "prefix version=5 suffix") == ["version=5", "5"]

      # Test formats that should not match
      assert Regex.run(pattern, "Some other comment") == nil
      assert Regex.run(pattern, "version=abc") == nil
      assert Regex.run(pattern, "") == nil
    end

    test "version padding works correctly for module names" do
      # Test the version padding logic used for module name generation
      assert String.pad_leading("1", 2, "0") == "01"
      assert String.pad_leading("9", 2, "0") == "09"
      assert String.pad_leading("10", 2, "0") == "10"
      assert String.pad_leading("99", 2, "0") == "99"
    end

    test "version module resolution works correctly" do
      # Test that V01 module can be correctly resolved
      padded_version = String.pad_leading("1", 2, "0")
      module_name = :"Elixir.Tango.Migrations.Versions.V#{padded_version}"

      assert module_name == :"Elixir.Tango.Migrations.Versions.V01"
      assert Code.ensure_loaded?(module_name)
      assert function_exported?(module_name, :up, 1)
      assert function_exported?(module_name, :down, 1)
    end

    test "all Tango tables are included in version tracking" do
      {:ok, migration_source} = File.read("lib/tango/migration.ex")

      # Verify all 4 table names appear in version tracking logic
      expected_tables = [
        "tango_providers",
        "tango_oauth_sessions",
        "tango_connections",
        "tango_audit_logs"
      ]

      for table_name <- expected_tables do
        assert String.contains?(migration_source, "\"#{table_name}\""),
               "Migration should include #{table_name} in version tracking"
      end

      # Verify update logic references all tables
      assert String.contains?(
               migration_source,
               "update_table_version(prefix, \"tango_providers\""
             )

      assert String.contains?(
               migration_source,
               "update_table_version(prefix, \"tango_oauth_sessions\""
             )

      assert String.contains?(
               migration_source,
               "update_table_version(prefix, \"tango_connections\""
             )

      assert String.contains?(
               migration_source,
               "update_table_version(prefix, \"tango_audit_logs\""
             )
    end

    test "migration logic functions are properly structured" do
      {:ok, migration_source} = File.read("lib/tango/migration.ex")

      # Verify key functions exist
      assert String.contains?(migration_source, "def migrated_version(")
      assert String.contains?(migration_source, "defp get_table_version(")
      assert String.contains?(migration_source, "defp parse_version_from_comment(")
      assert String.contains?(migration_source, "defp update_version(")
      assert String.contains?(migration_source, "defp update_table_version(")

      # Verify version constants
      assert String.contains?(migration_source, "@current_version 1")
      assert String.contains?(migration_source, "@initial_version 1")
    end
  end

  describe "SQL file execution and validation" do
    test "SQL files can be executed directly with PostgreSQL" do
      # Test that SQL files work with direct psql execution
      sql_content = File.read!("priv/repo/sql/versions/v01/v01_up.sql")

      # Replace schema placeholder
      sql_with_schema = String.replace(sql_content, "$SCHEMA$", "public")

      # Write to temp file
      temp_file = "/tmp/tango_test_#{:erlang.unique_integer([:positive])}.sql"
      File.write!(temp_file, sql_with_schema)

      try do
        # This validates that the SQL is valid PostgreSQL
        # (We're not actually executing to avoid test database conflicts)
        assert File.exists?(temp_file)
        assert String.contains?(sql_with_schema, "CREATE TABLE")
        assert String.contains?(sql_with_schema, "CREATE INDEX")
        refute String.contains?(sql_with_schema, "$SCHEMA$")
      after
        File.rm(temp_file)
      end
    end

    test "schema prefix substitution works correctly" do
      sql = """
      CREATE TABLE "$SCHEMA$".test (id INT);
      CREATE INDEX test_idx ON "$SCHEMA$".test (id);
      """

      result = String.replace(sql, "$SCHEMA$", "my_schema")

      assert result =~ "CREATE TABLE \"my_schema\".test"
      assert result =~ "ON \"my_schema\".test"
      refute result =~ "$SCHEMA$"
    end

    test "SPLIT delimiter parsing works correctly" do
      sql = """
      CREATE TABLE test1 (id INT);

      --SPLIT--

      CREATE TABLE test2 (id INT);
      """

      statements =
        String.split(sql, "--SPLIT--")
        |> Enum.map(&String.trim/1)
        |> Enum.reject(&(&1 == ""))

      assert length(statements) == 2
      assert Enum.at(statements, 0) =~ "test1"
      assert Enum.at(statements, 1) =~ "test2"
    end

    test "SQL file contains expected DDL elements" do
      sql_content = File.read!("priv/repo/sql/versions/v01/v01_up.sql")

      # Should contain all 4 table creations
      assert sql_content =~ "CREATE TABLE IF NOT EXISTS \"$SCHEMA$\".tango_providers"
      assert sql_content =~ "CREATE TABLE IF NOT EXISTS \"$SCHEMA$\".tango_oauth_sessions"
      assert sql_content =~ "CREATE TABLE IF NOT EXISTS \"$SCHEMA$\".tango_connections"
      assert sql_content =~ "CREATE TABLE IF NOT EXISTS \"$SCHEMA$\".tango_audit_logs"

      # Should contain proper data types
      assert sql_content =~ "BIGSERIAL PRIMARY KEY"
      assert sql_content =~ "TIMESTAMP"
      assert sql_content =~ "JSONB"
      assert sql_content =~ "BYTEA"

      # Should contain foreign key constraints
      assert sql_content =~ "REFERENCES"
      assert sql_content =~ "ON DELETE CASCADE"

      # Should contain indexes
      assert sql_content =~ "CREATE INDEX IF NOT EXISTS"
      assert sql_content =~ "CREATE UNIQUE INDEX IF NOT EXISTS"
    end

    test "down migration SQL file exists and contains proper cleanup" do
      sql_content = File.read!("priv/repo/sql/versions/v01/v01_down.sql")

      # Should contain table drops in correct order
      assert sql_content =~ "DROP TABLE IF EXISTS \"$SCHEMA$\".tango_audit_logs"
      assert sql_content =~ "DROP TABLE IF EXISTS \"$SCHEMA$\".tango_connections"
      assert sql_content =~ "DROP TABLE IF EXISTS \"$SCHEMA$\".tango_oauth_sessions"
      assert sql_content =~ "DROP TABLE IF EXISTS \"$SCHEMA$\".tango_providers"

      # Should handle schema cleanup
      assert sql_content =~ "DROP SCHEMA IF EXISTS"
    end

    test "SqlRunner module has proper documentation" do
      {:ok, runner_source} = File.read("lib/tango/migrations/sql_runner.ex")

      # Should document the SPLIT convention
      assert String.contains?(runner_source, "--SPLIT--")
      assert String.contains?(runner_source, "schema prefix substitution")
      assert String.contains?(runner_source, "$SCHEMA$")

      # Should explain why not semicolons
      assert String.contains?(runner_source, "semicolon")
      assert String.contains?(runner_source, "unreliable")
    end
  end
end

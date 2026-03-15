defmodule Tango.MigrationsTest do
  use ExUnit.Case

  describe "EctoEvolver-based migration API" do
    test "migration modules exist and have correct functions" do
      assert Code.ensure_loaded?(Tango.Migration)
      assert function_exported?(Tango.Migration, :up, 1)
      assert function_exported?(Tango.Migration, :down, 1)
      assert function_exported?(Tango.Migration, :migrated_version, 1)
      assert function_exported?(Tango.Migration, :current_version, 0)
    end

    test "V01 migration module exists and has correct functions" do
      assert Code.ensure_loaded?(Tango.Migrations.V01)
      assert function_exported?(Tango.Migrations.V01, :up, 1)
      assert function_exported?(Tango.Migrations.V01, :down, 1)
    end

    test "current version is 1" do
      assert Tango.Migration.current_version() == 1
    end

    test "follows Oban pattern for consuming applications" do
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

    test "supports prefix options" do
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

    test "supports version options" do
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

    test "real migration file exists and delegates to Tango.Migration" do
      migration_path = "priv/repo/migrations/20250915173007_add_tango_tables.exs"
      assert File.exists?(migration_path)

      {:ok, migration_content} = File.read(migration_path)
      assert String.contains?(migration_content, "Tango.Migration.up()")
      assert String.contains?(migration_content, "Tango.Migration.down()")
    end

    test "SqlRunner module no longer exists in Tango" do
      refute Code.ensure_loaded?(Tango.Migrations.SqlRunner)
    end
  end

  describe "version tracking" do
    test "version parsing regex pattern works correctly" do
      pattern = ~r/version=(\d+)/

      assert Regex.run(pattern, "Tango migration version=1") == ["version=1", "1"]
      assert Regex.run(pattern, "Tango migration version=42") == ["version=42", "42"]
      assert Regex.run(pattern, "prefix version=5 suffix") == ["version=5", "5"]

      assert Regex.run(pattern, "Some other comment") == nil
      assert Regex.run(pattern, "version=abc") == nil
      assert Regex.run(pattern, "") == nil
    end
  end

  describe "SQL files" do
    test "SQL files can be processed with schema substitution" do
      sql_content = File.read!("priv/repo/sql/versions/v01/v01_up.sql")

      sql_with_schema = String.replace(sql_content, "$SCHEMA$", "public")

      assert String.contains?(sql_with_schema, "CREATE TABLE")
      assert String.contains?(sql_with_schema, "CREATE INDEX")
      refute String.contains?(sql_with_schema, "$SCHEMA$")
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

      assert sql_content =~ "CREATE TABLE IF NOT EXISTS \"$SCHEMA$\".tango_providers"
      assert sql_content =~ "CREATE TABLE IF NOT EXISTS \"$SCHEMA$\".tango_oauth_sessions"
      assert sql_content =~ "CREATE TABLE IF NOT EXISTS \"$SCHEMA$\".tango_connections"
      assert sql_content =~ "CREATE TABLE IF NOT EXISTS \"$SCHEMA$\".tango_audit_logs"

      assert sql_content =~ "BIGSERIAL PRIMARY KEY"
      assert sql_content =~ "TIMESTAMP"
      assert sql_content =~ "JSONB"
      assert sql_content =~ "BYTEA"

      assert sql_content =~ "REFERENCES"
      assert sql_content =~ "ON DELETE CASCADE"

      assert sql_content =~ "CREATE INDEX IF NOT EXISTS"
      assert sql_content =~ "CREATE UNIQUE INDEX IF NOT EXISTS"
    end

    test "down migration SQL file exists and contains proper cleanup" do
      sql_content = File.read!("priv/repo/sql/versions/v01/v01_down.sql")

      assert sql_content =~ "DROP TABLE IF EXISTS \"$SCHEMA$\".tango_audit_logs"
      assert sql_content =~ "DROP TABLE IF EXISTS \"$SCHEMA$\".tango_connections"
      assert sql_content =~ "DROP TABLE IF EXISTS \"$SCHEMA$\".tango_oauth_sessions"
      assert sql_content =~ "DROP TABLE IF EXISTS \"$SCHEMA$\".tango_providers"

      assert sql_content =~ "DROP SCHEMA IF EXISTS"
    end
  end
end

defmodule Tango.Migrations.SqlRunner do
  @moduledoc """
  SQL file execution utilities for Tango migrations.

  Handles loading and executing raw SQL files with schema prefix substitution.
  """

  use Ecto.Migration

  @doc """
  Executes a SQL file with schema prefix substitution.

  ## Parameters
  - `version`: Version number (e.g., "01", "02")
  - `direction`: :up or :down
  - `opts`: Options including :prefix

  ## SQL File Format

  SQL files use two special conventions:

  1. **Schema Prefix**: `$SCHEMA$` placeholder gets replaced with actual schema name
     ```sql
     CREATE TABLE "$SCHEMA$".my_table (id BIGINT);
     -- Becomes: CREATE TABLE "public".my_table (id BIGINT);
     ```

  2. **Statement Splitting**: `--SPLIT--` delimiters separate individual SQL statements
     ```sql
     CREATE TABLE users (id BIGINT);

     --SPLIT--

     CREATE INDEX users_id_idx ON users (id);
     ```

     This is required because:
     - PostgreSQL can execute multiple statements in one file via `psql -f file.sql`
     - Ecto's `execute()` can only handle ONE statement at a time
     - Semicolon splitting is unreliable due to functions, triggers, and string literals
     - `--SPLIT--` provides explicit, safe statement boundaries

  ## Examples

      execute_sql_file("01", :up, prefix: "tenant_schema")
      execute_sql_file("02", :down, [])
  """
  def execute_sql_file(version, direction, opts \\ []) do
    validate_version(version)
    prefix = get_prefix(opts)
    filename = sql_filename(version, direction)

    sql_content = File.read!(sql_file_path(version, filename))
    escaped_prefix = escape_identifier(prefix)
    sql_with_prefix = String.replace(sql_content, "$SCHEMA$", escaped_prefix)

    # For development/testing, you can run this SQL directly in psql:
    # psql -d database_name -f priv/repo/sql/versions/v01/v01_up.sql

    # Split into individual statements for Ecto execution
    # We use --SPLIT-- instead of semicolons because semicolon parsing is unreliable
    # when SQL contains functions, triggers, or string literals with embedded semicolons
    statements =
      sql_with_prefix
      |> String.split("--SPLIT--")
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))
      |> Enum.filter(fn stmt ->
        # Keep statements that contain actual SQL (not just comments)
        String.match?(stmt, ~r/(CREATE|ALTER|DROP|INSERT|UPDATE|DELETE|COMMENT|GRANT|DO)/i)
      end)

    # Execute each statement
    Enum.each(statements, &execute/1)
  end

  defp get_prefix(opts) do
    opts[:prefix] || Application.get_env(:tango, :schema_prefix, "public")
  end

  defp validate_version(version) do
    unless Regex.match?(~r/^\d{1,2}$/, version) do
      raise ArgumentError, "Invalid version format: #{version}. Must be 1-2 digits."
    end
  end

  # Escape PostgreSQL identifiers to prevent SQL injection
  defp escape_identifier(identifier) do
    # Only escape if identifier contains special characters or reserved words
    if String.match?(identifier, ~r/^[a-zA-Z_][a-zA-Z0-9_]*$/) and
         not reserved_word?(identifier) do
      identifier
    else
      escaped = String.replace(identifier, "\"", "\"\"")
      "\"#{escaped}\""
    end
  end

  # PostgreSQL reserved words that need escaping (excluding common schema names)
  defp reserved_word?(word) do
    reserved = ~w(user table index create drop alter select insert update delete)
    String.downcase(word) in reserved
  end

  defp sql_filename(version, :up), do: "v#{version}_up.sql"
  defp sql_filename(version, :down), do: "v#{version}_down.sql"

  defp sql_file_path(version, filename) do
    priv_dir = :code.priv_dir(:tango) || Path.join([File.cwd!(), "priv"])

    Path.join([
      priv_dir,
      "repo",
      "sql",
      "versions",
      "v#{version}",
      filename
    ])
  end
end

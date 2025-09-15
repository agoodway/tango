defmodule Tango.Migration do
  @moduledoc """
  Manages database migrations for Tango.

  Handles version detection, incremental application, and rollback scenarios.
  Follows Oban's migration patterns for consistency and reliability.

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

  use Ecto.Migration

  @current_version 1
  @initial_version 1

  def up(opts \\ []) do
    opts = with_defaults(opts)
    initial = migrated_version(opts)
    target = Keyword.get(opts, :version, @current_version)

    cond do
      initial == 0 ->
        # Fresh installation - apply all migrations up to target
        change(@initial_version..target, :up, opts)

      initial < target ->
        # Incremental upgrade
        change((initial + 1)..target, :up, opts)

      initial == target ->
        :ok

      true ->
        {:error, :cannot_downgrade_with_up}
    end
  end

  def down(opts \\ []) do
    opts = with_defaults(opts)
    initial = migrated_version(opts)
    target = Keyword.get(opts, :version, @initial_version - 1)

    if initial > target do
      range =
        if target < @initial_version, do: @initial_version..initial, else: (target + 1)..initial

      change(range, :down, opts)
    else
      :ok
    end
  end

  def migrated_version(opts \\ []) do
    opts = with_defaults(opts)
    prefix = get_prefix(opts)

    # Check all Tango tables for version, with fallback order
    table_names = [
      "tango_providers",
      "tango_oauth_sessions",
      "tango_connections",
      "tango_audit_logs"
    ]

    Enum.reduce_while(table_names, 0, fn table_name, _acc ->
      version = get_table_version(table_name, prefix)

      if version > 0 do
        {:halt, version}
      else
        {:cont, 0}
      end
    end)
  end

  defp get_table_version(table_name, prefix) do
    query = """
    SELECT obj_description(c.oid)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relname = $1 AND n.nspname = $2
    """

    case get_repo().query(query, [table_name, prefix]) do
      {:ok, %{rows: [[comment]]}} when is_binary(comment) ->
        parse_version_from_comment(comment)

      _ ->
        0
    end
  end

  defp parse_version_from_comment(comment) do
    case Regex.run(~r/version=(\d+)/, comment) do
      [_, version_str] -> String.to_integer(version_str)
      nil -> 0
    end
  end

  defp change(range, direction, opts) do
    for version <- range do
      module = :"Elixir.Tango.Migrations.V#{pad_version(version)}"
      apply(module, direction, [opts])
    end

    # Update version tracking after successful migration
    if direction == :up do
      update_version(Enum.max(range), opts)
    else
      update_version(Enum.min(range) - 1, opts)
    end

    :ok
  end

  defp update_version(version, opts) do
    prefix = get_prefix(opts)
    comment = "Tango migration version=#{version}"

    # Set version comment on all Tango tables for redundancy
    update_table_version(prefix, "tango_providers", comment)
    update_table_version(prefix, "tango_oauth_sessions", comment)
    update_table_version(prefix, "tango_connections", comment)
    update_table_version(prefix, "tango_audit_logs", comment)
  end

  defp update_table_version(prefix, table_name, comment) do
    # Escape identifiers and comment value to prevent SQL injection
    escaped_prefix = escape_identifier(prefix)
    escaped_table = escape_identifier(table_name)
    escaped_comment = escape_comment(comment)
    execute("COMMENT ON TABLE #{escaped_prefix}.#{escaped_table} IS #{escaped_comment}")
  end

  defp escape_identifier(identifier) do
    # PostgreSQL identifier escaping - wrap in double quotes and escape internal quotes
    "\"#{String.replace(identifier, "\"", "\"\"")}\""
  end

  defp escape_comment(comment) do
    # PostgreSQL string literal escaping - wrap in single quotes and escape internal quotes
    "'#{String.replace(comment, "'", "''")}'"
  end

  defp pad_version(version), do: String.pad_leading("#{version}", 2, "0")

  defp with_defaults(opts), do: Keyword.put_new(opts, :version, @current_version)

  defp get_prefix(opts) do
    opts[:prefix] || Application.get_env(:tango, :schema_prefix, "public")
  end

  defp get_repo do
    Application.get_env(:tango, :repo) ||
      raise "Must configure :tango, :repo in your application config"
  end
end

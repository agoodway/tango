defmodule Tango.Migrations.Versions.V01 do
  @moduledoc """
  Tango V01 Migration - Initial schema setup.

  Creates core tables:
  - tango_providers
  - tango_oauth_sessions
  - tango_connections
  - tango_audit_logs
  """

  alias Tango.Migrations.SqlRunner

  def up(opts \\ []) do
    SqlRunner.execute_sql_file("01", :up, opts)
  end

  def down(opts \\ []) do
    SqlRunner.execute_sql_file("01", :down, opts)
  end
end

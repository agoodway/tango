defmodule Tango.Migrations.V01 do
  @moduledoc """
  Tango V01 Migration - Initial schema setup.

  Creates core tables:
  - tango_providers
  - tango_oauth_sessions
  - tango_connections
  - tango_audit_logs
  """

  use EctoEvolver.Version,
    otp_app: :tango,
    version: "01",
    sql_path: "repo/sql/versions"
end

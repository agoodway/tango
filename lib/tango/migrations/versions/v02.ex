defmodule Tango.Migrations.V02 do
  @moduledoc """
  Tango V02 Migration - Provider rejection tracking on connections.

  Adds to tango_connections:
  - auth_failures
  - last_auth_failure
  """

  use EctoEvolver.Version,
    otp_app: :tango,
    version: "02",
    sql_path: "repo/sql/versions"
end

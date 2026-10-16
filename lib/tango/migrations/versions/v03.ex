defmodule Tango.Migrations.V03 do
  @moduledoc """
  Tango V03 Migration - staged authorization candidates and authorization intent.
  """

  use EctoEvolver.Version,
    otp_app: :tango,
    version: "03",
    sql_path: "repo/sql/versions"
end

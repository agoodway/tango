defmodule Tango.Migrations.V04 do
  @moduledoc """
  Tango V04 Migration - retained token response metadata on authorization candidates.
  """

  use EctoEvolver.Version,
    otp_app: :tango,
    version: "04",
    sql_path: "repo/sql/versions"
end

defmodule Tango.Migrations.V04 do
  @moduledoc """
  Tango V04 migration stores token response metadata and authorization completion mode.

  Existing sessions and candidates default to connection completion. Consume mode
  forbids connection bindings. This revision retains schema version 4 under the
  no-external-consumers migration exception. An already-applied V04 requires an
  explicit schema-shape check and targeted reconciliation to retain data, or
  fresh recreation of a disposable developer database. The version marker alone
  is insufficient. This revised down migration queries completion_mode and cannot
  run on the original V04 schema without those columns; do not use the current
  wrapper to roundtrip that schema.

  Rollback takes ACCESS EXCLUSIVE locks on sessions, then authorizations, held
  through migration completion. Before DDL it refuses unexpired consume sessions
  not yet exchanged and unexpired, unconsumed consume candidates. Complete or
  expire pending work and use normal cleanup before retrying. See the setup and
  upgrading guides for deployment and rollback requirements.
  """

  use EctoEvolver.Version,
    otp_app: :tango,
    version: "04",
    sql_path: "repo/sql/versions"
end

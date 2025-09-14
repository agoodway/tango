defmodule Tango.TestRepo do
  @moduledoc """
  Test repository for Tango library testing.

  Uses standard Ecto migrations from priv/repo/migrations.
  """

  use Ecto.Repo,
    otp_app: :tango,
    adapter: Ecto.Adapters.Postgres
end

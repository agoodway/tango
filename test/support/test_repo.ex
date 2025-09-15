defmodule Tango.TestRepo do
  @moduledoc """
  Test repository for Tango library testing.
  """

  use Ecto.Repo,
    otp_app: :tango,
    adapter: Ecto.Adapters.Postgres
end

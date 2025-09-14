defmodule Tango.Repo do
  @moduledoc """
  Ecto repository for Tango OAuth library.

  This repo is configured by the host application and should not be
  started independently in the library supervision tree.
  """

  use Ecto.Repo,
    otp_app: :tango,
    adapter: Ecto.Adapters.Postgres
end

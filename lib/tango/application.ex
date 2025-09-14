defmodule Tango.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      Tango.Vault
    ]

    # Add TestRepo in test environment for library testing
    children =
      if Mix.env() == :test do
        children ++ [Tango.TestRepo]
      else
        children
      end

    opts = [strategy: :one_for_one, name: Tango.Supervisor]
    Supervisor.start_link(children, opts)
  end
end

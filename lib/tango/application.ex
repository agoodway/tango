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
      if Code.ensure_loaded?(Tango.TestRepo) and function_exported?(Tango.TestRepo, :__adapter__, 0) do
        children ++ [Tango.TestRepo]
      else
        children
      end

    opts = [strategy: :one_for_one, name: Tango.Supervisor]
    Supervisor.start_link(children, opts)
  end
end

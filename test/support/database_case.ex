defmodule Tango.DatabaseCase do
  @moduledoc """
  Test case template for database-dependent tests.

  Provides Ecto sandbox setup and common database testing utilities.
  """

  use ExUnit.CaseTemplate

  alias Ecto.Adapters.SQL

  using do
    quote do
      alias Tango.TestRepo, as: Repo
      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import Tango.DatabaseCase
    end
  end

  setup tags do
    :ok = SQL.Sandbox.checkout(Tango.TestRepo)

    unless tags[:async] do
      SQL.Sandbox.mode(Tango.TestRepo, {:shared, self()})
    end

    :ok
  end

  @doc """
  Helper for asserting changeset validity.
  """
  def assert_valid_changeset(changeset) do
    assert changeset.valid?,
           "Expected changeset to be valid, got errors: #{inspect(changeset.errors)}"

    changeset
  end

  @doc """
  Helper for asserting changeset errors.
  """
  def assert_changeset_error(changeset, field, message) do
    refute changeset.valid?
    assert {^message, _} = changeset.errors[field]
    changeset
  end
end

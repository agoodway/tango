defmodule Tango.RefreshFailureRepo do
  @moduledoc false
  # Process-local fault injection around Tango.TestRepo. One of
  # `:transaction`, `:token_write`, `:failure_write`, or `:audit_write`
  # fails the matching operation once, then clears itself.

  import Ecto.Query, only: [from: 2]

  alias Tango.Schemas.{AuditLog, Connection}

  @rollback_marker "rollback-marker"

  @mode_key {__MODULE__, :mode}

  @doc "Arms one failure mode for the next matching repo call."
  def fail_once(mode) when mode in [:transaction, :token_write, :failure_write, :audit_write] do
    Process.put(@mode_key, mode)
    :ok
  end

  @doc "Clears an armed failure mode."
  def clear_mode, do: Process.delete(@mode_key)

  @doc "Value written inside a failing refresh write so a commit can be detected."
  def rollback_marker, do: @rollback_marker

  @doc "Delegates `one/2` to the test repo."
  def one(queryable, opts \\ []), do: Tango.TestRepo.one(queryable, opts)

  @doc "Delegates `all/2` to the test repo."
  def all(queryable, opts \\ []), do: Tango.TestRepo.all(queryable, opts)

  @doc "Delegates `get/3` to the test repo."
  def get(queryable, id, opts \\ []), do: Tango.TestRepo.get(queryable, id, opts)

  @doc "Delegates `get_by/3` to the test repo."
  def get_by(queryable, clauses, opts \\ []), do: Tango.TestRepo.get_by(queryable, clauses, opts)

  @doc "Delegates `query!/3` to the test repo."
  def query!(sql, params \\ [], opts \\ []), do: Tango.TestRepo.query!(sql, params, opts)

  @doc "Delegates `update_all/3` to the test repo."
  def update_all(queryable, updates, opts \\ []),
    do: Tango.TestRepo.update_all(queryable, updates, opts)

  @doc "Delegates `exists?/2` to the test repo."
  def exists?(queryable, opts \\ []), do: Tango.TestRepo.exists?(queryable, opts)

  @doc "Reports whether the test repo has an open transaction."
  def in_transaction?, do: Tango.TestRepo.in_transaction?()

  @doc "Rolls back the test repo transaction."
  def rollback(value), do: Tango.TestRepo.rollback(value)

  @doc "Runs a transaction, or fails once when that mode is armed."
  def transaction(fun, opts \\ [])

  def transaction(fun, opts) when is_function(fun) do
    if consume_mode(:transaction) do
      {:error, :sentinel_transaction_detail}
    else
      Tango.TestRepo.transaction(fun, opts)
    end
  end

  def transaction(%Ecto.Multi{} = multi, opts) do
    if consume_mode(:transaction) do
      {:error, :sentinel_transaction_detail}
    else
      Tango.TestRepo.transaction(multi, opts)
    end
  end

  @doc "Updates a changeset, or fails once for an armed token, failure, or audit write."
  def update(changeset, opts \\ []), do: write(changeset, opts, &Tango.TestRepo.update/2)

  @doc "Inserts a changeset, or fails once for an armed token, failure, or audit write."
  def insert(changeset, opts \\ []), do: write(changeset, opts, &Tango.TestRepo.insert/2)

  @doc "Delegates `insert!/2` to the test repo."
  def insert!(changeset, opts \\ []), do: Tango.TestRepo.insert!(changeset, opts)

  defp write(changeset, opts, writer) do
    cond do
      token_update?(changeset) and consume_mode(:token_write) ->
        mark_uncommitted(changeset)
        {:error, sentinel_changeset(changeset)}

      failure_update?(changeset) and consume_mode(:failure_write) ->
        mark_uncommitted(changeset)
        {:error, sentinel_changeset(changeset)}

      audit_insert?(changeset) and consume_mode(:audit_write) ->
        {:error, sentinel_changeset(changeset)}

      true ->
        writer.(changeset, opts)
    end
  end

  defp consume_mode(expected) do
    if Process.get(@mode_key) == expected do
      clear_mode()
      true
    else
      false
    end
  end

  defp token_update?(%Ecto.Changeset{changes: changes}) do
    Map.has_key?(changes, :access_token) or Map.has_key?(changes, :refresh_token)
  end

  defp failure_update?(%Ecto.Changeset{data: %Connection{}, changes: changes} = changeset) do
    not token_update?(changeset) and
      (Map.has_key?(changes, :last_refresh_failure) or Map.has_key?(changes, :refresh_attempts) or
         Map.has_key?(changes, :next_refresh_at) or Map.has_key?(changes, :refresh_exhausted))
  end

  defp failure_update?(_changeset), do: false

  defp audit_insert?(%Ecto.Changeset{data: %AuditLog{}}), do: true
  defp audit_insert?(_changeset), do: false

  defp sentinel_changeset(changeset) do
    Ecto.Changeset.add_error(changeset, :base, "sentinel_persistence_detail")
  end

  # A commit of the refresh transaction would keep this write. Rollback removes it.
  defp mark_uncommitted(%Ecto.Changeset{data: %Connection{id: id}}) when is_integer(id) do
    Tango.TestRepo.update_all(from(c in Connection, where: c.id == ^id),
      set: [last_auth_failure: @rollback_marker]
    )
  end

  defp mark_uncommitted(_changeset), do: :ok
end

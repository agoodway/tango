defmodule Tango.ConnectionLock do
  @moduledoc false

  import Ecto.Query, only: [from: 2, where: 3]

  alias Tango.Schemas.Connection

  @doc """
  Serializes active-generation changes for one provider and tenant.

  The schema prefix is part of the namespace so independent Tango installations
  sharing a PostgreSQL database do not contend with each other.
  """
  def lock(repo, provider_id, tenant_id)
      when is_integer(provider_id) and is_binary(tenant_id) do
    prefix = Application.get_env(:tango, :schema_prefix) || "public"
    namespace = ["tango", prefix, Integer.to_string(provider_id), tenant_id]
    <<key::signed-64, _rest::binary>> = :crypto.hash(:sha256, Enum.join(namespace, <<0>>))
    %{rows: [[_void]]} = repo.query!("SELECT pg_advisory_xact_lock($1::bigint)", [key])
    :ok
  end

  @doc """
  Locks each provider and tenant pair in provider-id order, then tenant binary order.

  Duplicate pairs are locked once. The caller must already be inside `repo`'s
  transaction. A repeated call for a held pair does not block, and the locks
  last until the outer transaction commits or rolls back.
  """
  def lock_ordered(repo, keys) when is_list(keys) do
    keys
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.each(fn {provider_id, tenant_id} ->
      :ok = lock(repo, provider_id, tenant_id)
    end)

    :ok
  end

  @doc """
  Returns whether an active generation other than `excluded_id` exists for one
  provider and tenant. Pass `nil` to check for any active generation.
  """
  def other_active_generation?(repo, provider_id, tenant_id, excluded_id) do
    query =
      from(connection in Connection,
        where: connection.provider_id == ^provider_id,
        where: connection.tenant_id == ^tenant_id,
        where: connection.status == :active
      )

    query =
      if excluded_id,
        do: where(query, [connection], connection.id != ^excluded_id),
        else: query

    repo.exists?(query)
  end
end

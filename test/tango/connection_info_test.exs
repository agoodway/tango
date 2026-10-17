defmodule Tango.ConnectionInfoTest do
  use Tango.DatabaseCase, async: false

  alias Tango.Factory
  alias Tango.Schemas.Connection, as: ConnectionSchema

  @info_fields [
    :account_subject,
    :expires_at,
    :granted_scopes,
    :id,
    :provider_slug,
    :status,
    :tenant_id
  ]

  test "info has exactly seven credential-free fields" do
    bypass = Bypass.open()
    {:ok, requests} = Agent.start_link(fn -> 0 end)

    Bypass.stub(bypass, "POST", "/oauth2/token", fn conn ->
      Agent.update(requests, &(&1 + 1))
      Plug.Conn.resp(conn, 500, "")
    end)

    provider =
      Factory.create_google_provider("_info_fields",
        urls: Tango.OAuthMockServer.google_urls(bypass)
      )

    tenant_id = Factory.tenant_id("info_fields")

    connection =
      provider
      |> Factory.create_connection(tenant_id)
      |> ConnectionSchema.changeset(%{
        account_subject: nil,
        granted_scopes: nil,
        expires_at: nil
      })
      |> Repo.update!()

    assert {:ok, info} = Tango.get_connection_info(connection.id, tenant_id)
    assert info |> Map.from_struct() |> Map.keys() |> Enum.sort() == @info_fields
    assert info.id == connection.id
    assert info.tenant_id == tenant_id
    assert info.provider_slug == provider.slug
    assert info.status == :active
    assert info.account_subject == nil
    assert info.granted_scopes == nil
    assert info.expires_at == nil
    refute Map.has_key?(Map.from_struct(info), :access_token)

    near =
      provider
      |> Factory.create_connection(Factory.tenant_id("info_near"))
      |> ConnectionSchema.changeset(%{expires_at: DateTime.add(DateTime.utc_now(), 60, :second)})
      |> Repo.update!()

    assert {:ok, %{id: id}} = Tango.get_connection_info(near.id, near.tenant_id)
    assert id == near.id
    assert Agent.get(requests, & &1) == 0
  end

  test "info is tenant scoped for every status" do
    provider =
      Factory.create_provider(%{slug: "records_status_#{System.unique_integer([:positive])}"})

    owner = Factory.tenant_id("info_owner")
    other = Factory.tenant_id("info_other")

    rows =
      for status <- [:expired, :revoked, :active] do
        connection = Factory.create_connection(provider, owner)

        case status do
          :active ->
            connection

          status ->
            connection
            |> ConnectionSchema.changeset(%{status: status})
            |> Repo.update!()
        end
      end

    foreign = Factory.create_connection(provider, other)

    for connection <- rows do
      assert {:ok, info} = Tango.get_connection_info(connection.id, owner)
      assert info.status == connection.status
      assert info.tenant_id == owner
      assert {:error, :not_found} = Tango.get_connection_info(connection.id, other)
    end

    assert {:error, :not_found} = Tango.get_connection_info(foreign.id, owner)
    assert {:error, :not_found} = Tango.get_connection_info(-1, owner)
  end

  test "listing filters slug independently of provider name" do
    suffix = System.unique_integer([:positive])
    slug = "records_slug_#{suffix}"

    named =
      Factory.create_provider(%{
        name: "records_name_#{suffix}",
        slug: slug,
        active: false
      })

    decoy =
      Factory.create_provider(%{
        name: slug,
        slug: "records_decoy_#{suffix}"
      })

    tenant_id = Factory.tenant_id("info_list")

    expired =
      named
      |> Factory.create_connection(tenant_id)
      |> ConnectionSchema.changeset(%{status: :expired})
      |> Repo.update!()

    revoked =
      named
      |> Factory.create_connection(tenant_id)
      |> ConnectionSchema.changeset(%{status: :revoked})
      |> Repo.update!()

    active = Factory.create_connection(named, tenant_id)

    assert [%{id: active_id}] = Tango.list_connection_infos(tenant_id)
    assert active_id == active.id

    decoy_connection = Factory.create_connection(decoy, tenant_id)

    listed = Tango.list_connection_infos(tenant_id, status: :any, provider_slug: slug)
    assert Enum.map(listed, & &1.id) == Enum.sort([active.id, expired.id, revoked.id])
    assert Enum.all?(listed, &(&1.provider_slug == slug))

    assert Tango.list_connection_infos(tenant_id, status: []) == []

    assert Tango.list_connection_infos(tenant_id, status: [:revoked]) |> Enum.map(& &1.id) == [
             revoked.id
           ]

    assert Tango.list_connection_infos(tenant_id, provider_slug: named.name) == []
    assert Tango.list_connection_infos(tenant_id, provider_slug: "missing_records") == []

    assert [%{id: decoy_id}] =
             Tango.list_connection_infos(tenant_id, provider_slug: decoy.slug)

    assert decoy_id == decoy_connection.id

    assert_raise ArgumentError, fn ->
      Tango.list_connection_infos(tenant_id, status: :paused)
    end

    assert_raise ArgumentError, fn ->
      Tango.list_connection_infos(tenant_id, unknown: true)
    end
  end

  test "info selects no encrypted columns" do
    provider = Factory.create_provider()
    tenant_id = Factory.tenant_id("info_sql")
    connection = Factory.create_connection(provider, tenant_id)

    queries =
      capture_connection_queries(fn ->
        assert {:ok, _info} = Tango.get_connection_info(connection.id, tenant_id)
        assert [%{id: id}] = Tango.list_connection_infos(tenant_id)
        assert id == connection.id
      end)

    assert queries != []

    for query <- queries do
      assert query =~ "tango_connections"
      refute query =~ "access_token"
      refute query =~ "refresh_token"
      refute query =~ "raw_payload"
      refute query =~ "config"
      refute query =~ "metadata"
    end
  end

  test "invalid filters raise before querying" do
    tenant_id = Factory.tenant_id("info_invalid")

    queries =
      capture_connection_queries(fn ->
        assert_raise ArgumentError, fn ->
          Tango.list_connection_infos(tenant_id, status: :paused)
        end

        assert_raise ArgumentError, fn ->
          Tango.list_connection_infos(tenant_id, mystery: true)
        end
      end)

    assert queries == []
  end

  defp capture_connection_queries(fun) do
    test_pid = self()
    handler = "connection-info-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler,
      [:tango, :test_repo, :query],
      fn _event, _measurements, %{query: query}, _config ->
        if String.contains?(query, "tango_connections"),
          do: send(test_pid, {:connection_query, query})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler) end)
    fun.()
    receive_queries([])
  end

  defp receive_queries(acc) do
    receive do
      {:connection_query, query} -> receive_queries([query | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end

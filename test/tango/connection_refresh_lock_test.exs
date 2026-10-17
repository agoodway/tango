defmodule Tango.ConnectionRefreshLockTest do
  use ExUnit.Case, async: false

  import Ecto.Query

  alias Ecto.Adapters.SQL.Sandbox
  alias Tango.{Factory, OAuthMockServer}
  alias Tango.Schemas.{AuditLog, Provider}
  alias Tango.Schemas.Connection, as: ConnectionSchema
  alias Tango.TestRepo, as: Repo

  setup tags do
    if tags[:sweep_policy] do
      :ok
    else
      refresh_lock_fixture()
    end
  end

  defp refresh_lock_fixture do
    bypass = Bypass.open()
    test_pid = self()
    {:ok, requests} = Agent.start_link(fn -> 0 end)

    Bypass.expect(bypass, "POST", "/oauth2/token", fn conn ->
      Agent.update(requests, &(&1 + 1))
      send(test_pid, {:token_request, self()})

      receive do
        :release -> :ok
      after
        5_000 -> :ok
      end

      body =
        URI.encode_query(%{
          "access_token" => "fresh_access_token",
          "expires_in" => "3600",
          "token_type" => "Bearer"
        })

      conn
      |> Plug.Conn.put_resp_header("content-type", "application/x-www-form-urlencoded")
      |> Plug.Conn.resp(200, body)
    end)

    {provider, conn} =
      Sandbox.unboxed_run(Repo, fn ->
        provider =
          Factory.create_google_provider("_lock_#{System.unique_integer([:positive])}",
            urls: OAuthMockServer.google_urls(bypass)
          )

        {:ok, conn} =
          provider
          |> Factory.create_connection(Factory.tenant_id("lock"))
          |> ConnectionSchema.changeset(%{
            expires_at: DateTime.add(DateTime.utc_now(), 60, :second)
          })
          |> Repo.update()

        {provider, conn}
      end)

    on_exit(fn ->
      Sandbox.unboxed_run(Repo, fn ->
        Repo.delete_all(from(l in AuditLog, where: l.connection_id == ^conn.id))
        Repo.delete_all(from(c in ConnectionSchema, where: c.provider_id == ^provider.id))
        Repo.delete_all(from(p in Provider, where: p.id == ^provider.id))
      end)
    end)

    {:ok, conn: conn, requests: requests}
  end

  test "concurrent callers spend the refresh token once", %{conn: conn, requests: requests} do
    {first, first_pid} = start_caller(fn -> Tango.Connection.refresh_if_needed(conn) end)
    assert_receive {:token_request, handler}, 5_000

    {second, second_pid} = start_caller(fn -> Tango.Connection.refresh_if_needed(conn) end)
    await_blocked(second_pid, first_pid)
    send(handler, :release)

    assert {:ok, %{access_token: "fresh_access_token"}} = Task.await(first)
    assert {:ok, %{access_token: "fresh_access_token"}} = Task.await(second)
    assert Agent.get(requests, & &1) == 1
  end

  test "the expiring-connection sweep waits for a request-time refresh",
       %{conn: conn, requests: requests} do
    assert [conn.id] == Sandbox.unboxed_run(Repo, fn -> expiring_connection_ids() end),
           "committed expiring connections from an aborted run remain; delete them first"

    {first, first_pid} = start_caller(fn -> Tango.Connection.refresh_if_needed(conn) end)
    assert_receive {:token_request, handler}, 5_000

    {sweep, sweep_pid} = start_caller(fn -> Tango.Connection.refresh_expiring_connections() end)
    await_blocked(sweep_pid, first_pid)
    send(handler, :release)

    assert {:ok, %{access_token: "fresh_access_token"}} = Task.await(first)
    assert {:ok, 0} = Task.await(sweep)
    assert Agent.get(requests, & &1) == 1
  end

  test "public refresh waits for and reuses an expiring-connection sweep refresh",
       %{conn: conn, requests: requests} do
    assert [conn.id] == Sandbox.unboxed_run(Repo, fn -> expiring_connection_ids() end),
           "committed expiring connections from an aborted run remain; delete them first"

    {sweep, sweep_pid} = start_caller(fn -> Tango.Connection.refresh_expiring_connections() end)
    assert_receive {:token_request, handler}, 5_000

    {refresh, refresh_pid} =
      start_caller(fn -> Tango.Connection.refresh_connection(conn) end)

    await_blocked(refresh_pid, sweep_pid)
    send(handler, :release)

    assert {:ok, 1} = Task.await(sweep)
    assert {:ok, %{access_token: "fresh_access_token"} = refreshed} = Task.await(refresh)

    persisted =
      Sandbox.unboxed_run(Repo, fn -> Repo.get!(ConnectionSchema, conn.id) end)

    assert refreshed.access_token == persisted.access_token
    assert Agent.get(requests, & &1) == 1
  end

  test "reading the current connection does not wait behind an in-flight refresh",
       %{conn: conn, requests: requests} do
    {refresh, _refresh_pid} = start_caller(fn -> Tango.Connection.refresh_if_needed(conn) end)
    assert_receive {:token_request, handler}, 5_000

    {read, _read_pid} =
      start_caller(fn -> Tango.get_active_connection(conn.id, conn.tenant_id) end)

    assert {:ok, current} = Task.await(read, 1_000)
    assert current.id == conn.id
    assert current.access_token == conn.access_token

    send(handler, :release)
    assert {:ok, %{access_token: "fresh_access_token"}} = Task.await(refresh)
    assert Agent.get(requests, & &1) == 1
  end

  @tag :sweep_policy
  test "sweep rechecks due time after acquiring locks" do
    bypass = Bypass.open()
    test_pid = self()
    {:ok, requests} = Agent.start_link(fn -> 0 end)
    {:ok, hold} = Agent.start_link(fn -> false end)

    Bypass.stub(bypass, "POST", "/oauth/token", fn conn ->
      Agent.update(requests, &(&1 + 1))

      if Agent.get(hold, & &1) do
        send(test_pid, {:sweep_token_request, self()})

        receive do
          :release_503 ->
            json_response(conn, 503, %{"error" => "server_error"})

          :release_200 ->
            json_response(conn, 200, %{
              "access_token" => "fresh_access_token",
              "expires_in" => 3600,
              "token_type" => "Bearer"
            })
        after
          5_000 ->
            json_response(conn, 500, %{"error" => "timeout"})
        end
      else
        json_response(conn, 500, %{"error" => "immediate"})
      end
    end)

    provider = unboxed(fn -> refresh_provider(bypass, "due") end)

    on_exit(fn ->
      unboxed(fn ->
        Repo.delete_all(from(l in AuditLog, where: l.provider_id == ^provider.id))
        Repo.delete_all(from(c in ConnectionSchema, where: c.provider_id == ^provider.id))
        Repo.delete(provider)
      end)
    end)

    future =
      unboxed(fn ->
        due_connection(provider, "future", %{
          next_refresh_at: DateTime.add(DateTime.utc_now(), 600, :second)
        })
      end)

    assert unboxed(fn -> Tango.Connection.refresh_expiring_connections() end) == {:ok, 0}
    assert Agent.get(requests, & &1) == 0
    assert unboxed(fn -> Repo.get!(ConnectionSchema, future.id).refresh_attempts end) == 0

    Agent.update(hold, fn _held -> true end)

    overdue =
      unboxed(fn ->
        Repo.delete(future)

        due_connection(provider, "overdue", %{
          next_refresh_at: DateTime.add(DateTime.utc_now(), -30, :second)
        })
      end)

    assert_only_expiring([overdue.id])
    {sweep, _pid} = start_caller(fn -> Tango.Connection.refresh_expiring_connections() end)
    assert_receive {:sweep_token_request, handler}, 5_000
    send(handler, :release_200)
    assert {:ok, 1} = Task.await(sweep)
    assert Agent.get(requests, & &1) == 1

    equal =
      unboxed(fn ->
        Repo.delete(overdue)

        due_connection(provider, "equal", %{
          next_refresh_at: DateTime.utc_now() |> DateTime.truncate(:second)
        })
      end)

    assert_only_expiring([equal.id])
    {sweep, _pid} = start_caller(fn -> Tango.Connection.refresh_expiring_connections() end)
    assert_receive {:sweep_token_request, handler}, 5_000
    send(handler, :release_200)
    assert {:ok, 1} = Task.await(sweep)
    assert Agent.get(requests, & &1) == 2

    raced =
      unboxed(fn ->
        Repo.delete(equal)
        due_connection(provider, "raced", %{})
      end)

    assert_only_expiring([raced.id])
    {first, first_pid} = start_caller(fn -> Tango.Connection.refresh_expiring_connections() end)
    assert_receive {:sweep_token_request, handler}, 5_000
    {second, second_pid} = start_caller(fn -> Tango.Connection.refresh_expiring_connections() end)
    await_blocked(second_pid, first_pid)
    send(handler, :release_503)
    assert {:ok, 0} = Task.await(first)
    assert {:ok, 0} = Task.await(second)
    assert Agent.get(requests, & &1) == 3

    stored = unboxed(fn -> Repo.get!(ConnectionSchema, raced.id) end)
    assert stored.refresh_attempts == 0
    assert stored.status == :active
    assert DateTime.compare(stored.next_refresh_at, DateTime.utc_now()) == :gt

    Enum.reduce(
      [
        {"disabled", %{auto_refresh_enabled: false}},
        {"revoked", %{status: :revoked}},
        {"refreshed", %{expires_at: DateTime.add(DateTime.utc_now(), 7200, :second)}}
      ],
      raced,
      fn {suffix, mutate}, previous ->
        waiting =
          unboxed(fn ->
            Repo.delete!(previous)
            due_connection(provider, suffix, %{})
          end)

        requests_before = Agent.get(requests, & &1)
        holder = hold_connection(waiting, mutate)
        assert_only_expiring([waiting.id])

        {sweep, sweep_pid} =
          start_caller(fn -> Tango.Connection.refresh_expiring_connections() end)

        await_blocked(sweep_pid, holder)
        send(holder_task(holder), :release)
        assert {:ok, 0} = Task.await(sweep)
        assert Agent.get(requests, & &1) == requests_before
        waiting
      end
    )
  end

  @tag :sweep_policy
  test "sweep counts only completed token saves" do
    bypass = Bypass.open()
    {:ok, requests} = Agent.start_link(fn -> 0 end)
    success_token = "refresh-success-token"
    failure_token = "refresh-failure-token"

    Bypass.stub(bypass, "POST", "/oauth/token", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      Agent.update(requests, &(&1 + 1))

      cond do
        String.contains?(body, success_token) ->
          json_response(conn, 200, %{
            "access_token" => "saved_access_token",
            "refresh_token" => "saved_refresh_token",
            "expires_in" => 3600,
            "token_type" => "Bearer"
          })

        String.contains?(body, failure_token) ->
          json_response(conn, 503, %{"error" => "server_error"})

        true ->
          Plug.Conn.resp(conn, 500, "unexpected refresh")
      end
    end)

    {provider, success, failure, skipped} =
      unboxed(fn ->
        provider = refresh_provider(bypass, "counts")

        success =
          due_connection(provider, "success", %{"refresh_token" => success_token})

        failure =
          due_connection(provider, "failure", %{"refresh_token" => failure_token})

        skipped = due_connection(provider, "skipped", %{})
        {provider, success, failure, skipped}
      end)

    on_exit(fn ->
      unboxed(fn ->
        ids = [success.id, failure.id, skipped.id]
        Repo.delete_all(from(l in AuditLog, where: l.connection_id in ^ids))
        Repo.delete_all(from(l in AuditLog, where: l.provider_id == ^provider.id))
        Repo.delete_all(from(c in ConnectionSchema, where: c.provider_id == ^provider.id))
        Repo.delete(provider)
      end)
    end)

    assert_only_expiring([success.id, failure.id, skipped.id])

    holder =
      hold_connection(skipped, %{next_refresh_at: DateTime.add(DateTime.utc_now(), 600, :second)})

    audits_before =
      unboxed(fn ->
        Repo.aggregate(from(l in AuditLog, where: l.event_type == :batch_token_refresh), :count)
      end)

    {sweep, sweep_pid} = start_caller(fn -> Tango.Connection.refresh_expiring_connections() end)
    await_blocked(sweep_pid, holder)
    send(holder_task(holder), :release)
    assert {:ok, 1} = Task.await(sweep)
    assert Agent.get(requests, & &1) == 2

    unboxed(fn ->
      assert Repo.aggregate(
               from(l in AuditLog, where: l.event_type == :batch_token_refresh),
               :count
             ) ==
               audits_before + 1

      audit =
        Repo.one!(
          from(l in AuditLog,
            where: l.event_type == :batch_token_refresh,
            order_by: [desc: l.id],
            limit: 1
          )
        )

      assert audit.event_data["success_count"] == 1
      assert audit.event_data["failure_count"] == 1
      assert audit.event_data["total_selected"] == 3
      assert audit.event_data["total_processed"] == 2
      assert Jason.encode!(audit.event_data)
    end)
  end

  defp json_response(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_header("content-type", "application/json")
    |> Plug.Conn.resp(status, Jason.encode!(body))
  end

  defp unboxed(fun), do: Sandbox.unboxed_run(Repo, fun)

  defp refresh_provider(bypass, suffix) do
    Factory.create_provider(%{
      name: "records_#{suffix}_#{System.unique_integer([:positive])}",
      slug: "records_#{suffix}_#{System.unique_integer([:positive])}",
      auth_mode: "oauth2",
      client_secret: "records_secret",
      config: %{
        "display_name" => "Records",
        "client_id" => "records_client",
        "auth_url" => "https://example.test/oauth/authorize",
        "token_url" => "http://localhost:#{bypass.port}/oauth/token"
      }
    })
  end

  defp due_connection(provider, suffix, attrs) do
    token_attrs =
      attrs
      |> Map.take([:refresh_token, "refresh_token"])
      |> Map.new(fn
        {:refresh_token, value} -> {"refresh_token", value}
        pair -> pair
      end)

    field_attrs = Map.drop(attrs, [:refresh_token, "refresh_token"])

    provider
    |> Factory.create_connection(Factory.tenant_id(suffix), token_attrs)
    |> ConnectionSchema.changeset(
      Map.merge(
        %{expires_at: DateTime.add(DateTime.utc_now(), 60, :second)},
        field_attrs
      )
    )
    |> Repo.update!()
  end

  defp assert_only_expiring(ids) do
    assert Enum.sort(unboxed(fn -> expiring_connection_ids() end)) == Enum.sort(ids),
           "committed expiring connections from an aborted run remain; delete them first"
  end

  defp hold_connection(connection, changes) do
    parent = self()

    task =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn -> hold_locked(parent, connection, changes) end)
      end)

    task_pid = task.pid
    assert_receive {:holder_pid, ^task_pid, backend_pid}, 5_000
    assert_receive {:holder_locked, ^task_pid}, 5_000
    Process.put({:holder_task, backend_pid}, task)
    backend_pid
  end

  defp hold_locked(parent, connection, changes) do
    Repo.transaction(fn ->
      %{rows: [[pid]]} = Repo.query!("SELECT pg_backend_pid()")
      send(parent, {:holder_pid, self(), pid})

      Repo.one!(from(c in ConnectionSchema, where: c.id == ^connection.id, lock: "FOR UPDATE"))

      send(parent, {:holder_locked, self()})

      receive do
        :release -> :ok
      after
        5_000 -> raise "holder was not released"
      end

      Repo.update!(
        ConnectionSchema.changeset(Repo.get!(ConnectionSchema, connection.id), changes)
      )
    end)
  end

  defp holder_task(backend_pid) do
    Process.get({:holder_task, backend_pid}).pid
  end

  defp expiring_connection_ids do
    Repo.all(
      from(c in ConnectionSchema,
        where: c.status == :active and not is_nil(c.refresh_token) and not is_nil(c.expires_at),
        where: c.expires_at <= ^DateTime.add(DateTime.utc_now(), 300, :second),
        select: c.id
      )
    )
  end

  defp start_caller(fun) do
    parent = self()

    task =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          %{rows: [[pid]]} = Repo.query!("SELECT pg_backend_pid()")
          send(parent, {:backend_pid, self(), pid})
          fun.()
        end)
      end)

    task_pid = task.pid
    assert_receive {:backend_pid, ^task_pid, backend_pid}, 5_000
    {task, backend_pid}
  end

  defp await_blocked(waiter_pid, holder_pid, attempts \\ 100)

  defp await_blocked(_waiter_pid, _holder_pid, 0),
    do: flunk("the second caller never waited on the first caller's row lock")

  defp await_blocked(waiter_pid, holder_pid, attempts) do
    %{rows: [[blocked?]]} =
      Sandbox.unboxed_run(Repo, fn ->
        Repo.query!("SELECT $1::int = ANY(pg_blocking_pids($2::int))", [holder_pid, waiter_pid])
      end)

    if blocked? do
      :ok
    else
      Process.sleep(20)
      await_blocked(waiter_pid, holder_pid, attempts - 1)
    end
  end
end

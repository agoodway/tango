defmodule Tango.ConnectionRefreshLockTest do
  use ExUnit.Case, async: false

  import Ecto.Query

  alias Ecto.Adapters.SQL.Sandbox
  alias Tango.{Factory, OAuthMockServer}
  alias Tango.Schemas.{AuditLog, Provider}
  alias Tango.Schemas.Connection, as: ConnectionSchema
  alias Tango.TestRepo, as: Repo

  setup do
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

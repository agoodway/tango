defmodule Tango.AuthorizationLockTest do
  use ExUnit.Case, async: false

  import Ecto.Query

  alias Ecto.Adapters.SQL.Sandbox
  alias Tango.{ConnectionLock, Factory}
  alias Tango.Schemas.{AuditLog, Authorization, Connection, OAuthSession, Provider}
  alias Tango.TestRepo, as: Repo

  setup do
    previous_origins = Application.get_env(:tango, :allowed_completion_origins)
    Application.put_env(:tango, :allowed_completion_origins, ["https://app.example.test"])

    on_exit(fn ->
      if previous_origins,
        do: Application.put_env(:tango, :allowed_completion_origins, previous_origins),
        else: Application.delete_env(:tango, :allowed_completion_origins)
    end)
  end

  test "provider and tenant lock serializes transactions" do
    provider_id = System.unique_integer([:positive])
    tenant_id = "lock-#{System.unique_integer([:positive])}"
    parent = self()

    holder =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          Repo.transaction(fn ->
            :ok = ConnectionLock.lock(Repo, provider_id, tenant_id)
            %{rows: [[pid]]} = Repo.query!("SELECT pg_backend_pid()")
            send(parent, {:holder_locked, self(), pid})

            receive do
              :release -> :ok
            end
          end)
        end)
      end)

    holder_task_pid = holder.pid
    assert_receive {:holder_locked, ^holder_task_pid, holder_backend_pid}, 5_000

    waiter =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          Repo.transaction(fn ->
            %{rows: [[pid]]} = Repo.query!("SELECT pg_backend_pid()")
            send(parent, {:waiter_backend, self(), pid})
            :ok = ConnectionLock.lock(Repo, provider_id, tenant_id)
          end)
        end)
      end)

    waiter_task_pid = waiter.pid
    assert_receive {:waiter_backend, ^waiter_task_pid, waiter_backend_pid}, 5_000
    await_blocked(waiter_backend_pid, holder_backend_pid)
    send(holder.pid, :release)
    assert {:ok, :ok} = Task.await(holder)
    assert {:ok, :ok} = Task.await(waiter)
  end

  test "concurrent initial finalizations produce exactly one active generation" do
    parent = self()

    {provider, tenant_id, candidates} =
      Sandbox.unboxed_run(Repo, fn ->
        provider = Factory.create_provider()
        tenant_id = Factory.tenant_id("initial-finalize-race")

        candidates =
          for suffix <- ["first", "second"] do
            initial_candidate(provider, tenant_id, suffix)
          end

        {provider, tenant_id, candidates}
      end)

    on_exit(fn -> cleanup_provider(provider.id) end)

    tasks =
      for {handle, candidate} <- candidates do
        Task.async(fn ->
          Sandbox.unboxed_run(Repo, fn ->
            multi =
              Ecto.Multi.new()
              |> Ecto.Multi.run(:ready, fn _repo, _changes ->
                send(parent, {:finalizer_ready, self()})

                receive do
                  :go -> {:ok, :ready}
                end
              end)
              |> Tango.multi_finalize_authorization(
                :grant,
                handle,
                tenant_id,
                finalize_opts(provider, candidate)
              )

            Repo.transaction(multi)
          end)
        end)
      end

    on_exit(fn ->
      Enum.each(tasks, &send(&1.pid, :go))
      Enum.each(tasks, &Process.exit(&1.pid, :kill))
    end)

    ready_pids =
      for _ <- tasks do
        assert_receive {:finalizer_ready, pid}, 5_000
        pid
      end

    Enum.each(ready_pids, &send(&1, :go))
    results = Task.await_many(tasks, 5_000)

    assert Enum.count(results, &match?({:ok, %{grant: _}}, &1)) == 1
    assert Enum.count(results, &match?({:error, :grant, :stale_connection, _}, &1)) == 1

    assert 1 ==
             Sandbox.unboxed_run(Repo, fn ->
               Repo.aggregate(
                 from(c in Connection,
                   where: c.provider_id == ^provider.id,
                   where: c.tenant_id == ^tenant_id,
                   where: c.status == :active
                 ),
                 :count
               )
             end)
  end

  test "bulk revocation mutates only provider and tenant keys locked by its transaction" do
    parent = self()

    {provider, first} =
      Sandbox.unboxed_run(Repo, fn ->
        provider = Factory.create_provider()
        first = Factory.create_connection(provider, Factory.tenant_id("bulk-first"))
        {provider, first}
      end)

    on_exit(fn -> cleanup_provider(provider.id) end)

    holder =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          Repo.transaction(fn ->
            :ok = ConnectionLock.lock(Repo, provider.id, first.tenant_id)
            %{rows: [[backend_pid]]} = Repo.query!("SELECT pg_backend_pid()")
            send(parent, {:bulk_holder, self(), backend_pid})

            receive do
              :release -> :ok
            end
          end)
        end)
      end)

    holder_pid = holder.pid
    assert_receive {:bulk_holder, ^holder_pid, holder_backend_pid}, 5_000

    bulk =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          %{rows: [[backend_pid]]} = Repo.query!("SELECT pg_backend_pid()")
          send(parent, {:bulk_waiter, self(), backend_pid})
          Tango.Connection.revoke_provider_connections(provider.name)
        end)
      end)

    bulk_pid = bulk.pid

    on_exit(fn ->
      send(holder.pid, :release)
      Process.exit(holder.pid, :kill)
      Process.exit(bulk.pid, :kill)
    end)

    assert_receive {:bulk_waiter, ^bulk_pid, bulk_backend_pid}, 5_000
    await_blocked(bulk_backend_pid, holder_backend_pid)

    second =
      Sandbox.unboxed_run(Repo, fn ->
        Factory.create_connection(provider, Factory.tenant_id("bulk-second"))
      end)

    send(holder.pid, :release)
    assert {:ok, :ok} = Task.await(holder)
    assert {:ok, 1} = Task.await(bulk)

    assert :active ==
             Sandbox.unboxed_run(Repo, fn -> Repo.get!(Connection, second.id).status end)
  end

  defp initial_candidate(provider, tenant_id, suffix) do
    intent = "intent-#{suffix}-#{System.unique_integer([:positive])}"

    {:ok, session} =
      Tango.create_authorization_session(provider.slug, tenant_id,
        scopes: ["records.read"],
        redirect_uri: "https://api.example.test/callback",
        completion_origin: "https://app.example.test",
        intent_reference: intent
      )

    handle = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

    attrs = %{
      provider_id: provider.id,
      oauth_session_id: session.id,
      tenant_id: tenant_id,
      handle_hash: :crypto.hash(:sha256, handle),
      access_token: "access-#{suffix}",
      refresh_token: "refresh-#{suffix}",
      token_type: "Bearer",
      token_expires_at: DateTime.add(DateTime.utc_now(), 3600, :second),
      granted_scopes: ["records.read"],
      oauth_client_id: session.oauth_client_id,
      intent_reference: intent,
      completion_origin: session.completion_origin,
      account_subject: "subject-1",
      identity_claims: %{},
      verified_at: DateTime.utc_now(),
      expires_at: DateTime.add(DateTime.utc_now(), 600, :second)
    }

    candidate = %Authorization{} |> Authorization.changeset(attrs) |> Repo.insert!()
    {handle, candidate}
  end

  defp finalize_opts(provider, candidate) do
    [
      required_scopes: ["records.read"],
      require_refresh_token: true,
      intent_reference: candidate.intent_reference,
      provider: provider.slug,
      expected_connection_id: nil
    ]
  end

  defp cleanup_provider(provider_id) do
    Sandbox.unboxed_run(Repo, fn ->
      Repo.delete_all(from(a in AuditLog, where: a.provider_id == ^provider_id))
      Repo.delete_all(from(a in Authorization, where: a.provider_id == ^provider_id))
      Repo.delete_all(from(s in OAuthSession, where: s.provider_id == ^provider_id))
      Repo.delete_all(from(c in Connection, where: c.provider_id == ^provider_id))
      Repo.delete_all(from(p in Provider, where: p.id == ^provider_id))
    end)
  end

  defp await_blocked(waiter_pid, holder_pid, attempts \\ 100)

  defp await_blocked(_waiter_pid, _holder_pid, 0),
    do: flunk("provider/tenant advisory lock did not serialize callers")

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

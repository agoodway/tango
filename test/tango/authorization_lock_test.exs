defmodule Tango.AuthorizationLockTest do
  use ExUnit.Case, async: false

  import Ecto.Query

  alias Ecto.Adapters.SQL.Sandbox
  alias Tango.{ConnectionLock, Factory}
  alias Tango.Schemas.{AuditLog, Authorization, Connection, OAuthSession, Provider}
  alias Tango.TestRepo, as: Repo

  defmodule PausedVerifier do
    @behaviour Tango.AuthorizationVerifier

    @impl true
    def verify(_provider, _credential, opts) do
      send(opts[:parent], {:verifier_ready, self()})

      receive do
        :release ->
          {:ok, %{subject: "subject-1", claims: %{}, continuity: :initial}}
      end
    end
  end

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

  test "public generation prelock and plain finalizer serialize the same handle" do
    parent = self()

    {provider, tenant, handle, candidate} =
      Sandbox.unboxed_run(Repo, fn ->
        provider = Factory.create_provider()
        tenant = Factory.tenant_id("prelocked-finalize")
        {handle, candidate} = initial_candidate(provider, tenant, "prelocked")
        {provider, tenant, handle, candidate}
      end)

    on_exit(fn -> cleanup_provider(provider.id) end)

    multi =
      Tango.multi_finalize_authorization(
        Ecto.Multi.new(),
        :grant,
        handle,
        tenant,
        finalize_opts(provider, candidate)
      )

    holder =
      database_task(fn ->
        Repo.transaction(fn ->
          assert :ok = Tango.lock_connection_generations(tenant, [provider.slug])
          send(parent, {:generation_prelocked, self()})

          receive do
            :finalize -> Repo.transaction(multi)
          end
        end)
      end)

    {holder_backend, holder_pid} = start_database_task(holder)
    assert_receive {:generation_prelocked, ^holder_pid}, 5_000
    waiter = database_task(fn -> Repo.transaction(multi) end)
    {waiter_backend, _} = start_database_task(waiter)
    assert waiter_backend != holder_backend
    await_blocked(waiter_backend, holder_backend)
    send(holder_pid, :finalize)

    assert {:ok, {:ok, %{grant: _}}} = Task.await(holder, 5_000)
    assert {:error, :grant, :completion_consumed, _} = Task.await(waiter, 5_000)
    assert_consumed(candidate)

    assert 1 ==
             Sandbox.unboxed_run(Repo, fn ->
               Repo.aggregate(
                 from(c in Connection,
                   where: c.provider_id == ^provider.id,
                   where: c.tenant_id == ^tenant,
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

  test "two consumers serialize one proof and one replay failure" do
    {provider, tenant, handle, candidate} = consume_fixture()
    parent = self()

    winner =
      database_task(fn -> held_consumption(provider, tenant, handle, candidate, parent) end)

    {winner_backend, _} = start_database_task(winner)
    assert_receive {:consumed_pending, winner_pid}, 5_000

    loser =
      database_task(fn ->
        Repo.transaction(consume_multi(provider, tenant, handle, candidate))
      end)

    {loser_backend, _} = start_database_task(loser)
    assert loser_backend != winner_backend
    await_blocked(loser_backend, winner_backend)
    send(winner_pid, :commit)
    results = Task.await_many([winner, loser], 5_000)

    assert Enum.count(results, &match?({:ok, %{proof: _}}, &1)) == 1
    assert Enum.count(results, &match?({:error, :proof, :completion_consumed, _}, &1)) == 1
    assert_consumed(candidate)
    assert_no_connections(provider)
  end

  test "host rollback releases a waiting consumer with credentials intact" do
    {provider, tenant, handle, candidate} = consume_fixture()
    parent = self()

    holder =
      database_task(fn -> held_consumption(provider, tenant, handle, candidate, parent) end)

    {holder_backend, _} = start_database_task(holder)
    assert_receive {:consumed_pending, holder_pid}, 5_000

    waiter =
      database_task(fn ->
        Repo.transaction(consume_multi(provider, tenant, handle, candidate))
      end)

    {waiter_backend, _} = start_database_task(waiter)
    await_blocked(waiter_backend, holder_backend)

    Sandbox.unboxed_run(Repo, fn ->
      stored = Repo.get!(Authorization, candidate.id)
      refute stored.consumed_at
      assert stored.access_token == candidate.access_token
      assert stored.refresh_token == candidate.refresh_token
      assert stored.provider_data == candidate.provider_data
    end)

    send(holder_pid, :rollback)
    assert {:error, :host_write, :host_rejected, %{proof: _}} = Task.await(holder)
    assert {:ok, %{proof: %{subject: "subject-1"}}} = Task.await(waiter)
    assert_consumed(candidate)
    assert_no_connections(provider)
  end

  test "a verifier returning after committed consumption cannot resurrect credentials" do
    {provider, tenant, handle, candidate} = consume_fixture()
    parent = self()

    verifier =
      database_task(fn ->
        Tango.verify_authorization(handle, tenant, {PausedVerifier, parent: parent},
          provider: provider.slug,
          intent_reference: candidate.intent_reference
        )
      end)

    start_database_task(verifier)
    assert_receive {:verifier_ready, verifier_pid}, 5_000

    assert {:ok, %{proof: _}} =
             Sandbox.unboxed_run(Repo, fn ->
               Repo.transaction(consume_multi(provider, tenant, handle, candidate))
             end)

    send(verifier_pid, :release)
    assert {:error, :completion_consumed} = Task.await(verifier)
    assert_consumed(candidate)
    assert_no_connections(provider)
  end

  test "provider mutations block consumers and invalidate a verifier's stale result" do
    for {change, reason} <- [
          {%{active: false}, :invalid_completion},
          {%{config: %{"client_id" => "rotated-client"}}, :client_changed}
        ] do
      {provider, tenant, handle, candidate} = consume_fixture()
      parent = self()
      change = Map.update(change, :config, provider.config, &Map.merge(provider.config, &1))

      verifier =
        database_task(fn ->
          Tango.verify_authorization(handle, tenant, {PausedVerifier, parent: parent},
            provider: provider.slug,
            intent_reference: candidate.intent_reference
          )
        end)

      start_database_task(verifier)
      assert_receive {:verifier_ready, verifier_pid}, 5_000

      mutation =
        database_task(fn ->
          Repo.transaction(fn ->
            {:ok, _} = Tango.update_provider(provider, change)
            send(parent, {:provider_mutated, self()})

            receive do
              :commit -> :ok
            end
          end)
        end)

      {mutation_backend, _} = start_database_task(mutation)
      assert_receive {:provider_mutated, mutation_pid}, 5_000

      consumer =
        database_task(fn ->
          Repo.transaction(consume_multi(provider, tenant, handle, candidate))
        end)

      {consumer_backend, _} = start_database_task(consumer)
      await_blocked(consumer_backend, mutation_backend)
      send(mutation_pid, :commit)
      assert {:ok, :ok} = Task.await(mutation)
      assert {:error, :proof, ^reason, _} = Task.await(consumer)
      send(verifier_pid, :release)
      assert {:error, ^reason} = Task.await(verifier)
      assert_no_connections(provider)
    end
  end

  test "expired candidate cleanup serializes with consumption and leaves no proof" do
    {provider, tenant, handle, candidate} = consume_fixture()
    parent = self()

    Sandbox.unboxed_run(Repo, fn ->
      candidate
      |> Ecto.Changeset.change(
        expires_at: DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)
      )
      |> Repo.update!()
    end)

    cleanup =
      database_task(fn ->
        held_cleanup(&Tango.cleanup_expired_authorizations/0, parent)
      end)

    {cleanup_backend, _} = start_database_task(cleanup)
    assert_receive {:cleanup_pending, cleanup_pid, audit_ids}, 5_000
    cleanup_audits_on_exit(audit_ids)

    consumer =
      database_task(fn ->
        Repo.transaction(consume_multi(provider, tenant, handle, candidate))
      end)

    {consumer_backend, _} = start_database_task(consumer)
    await_blocked(consumer_backend, cleanup_backend)
    send(cleanup_pid, :commit)
    assert {:ok, {:ok, 1}} = Task.await(cleanup)
    assert {:error, :proof, :invalid_completion, _} = Task.await(consumer)
    Sandbox.unboxed_run(Repo, fn -> refute Repo.get(Authorization, candidate.id) end)
    assert_no_connections(provider)
  end

  test "session cleanup waits for consumption before cascading candidate deletion" do
    {provider, tenant, handle, candidate} = consume_fixture()
    parent = self()

    Sandbox.unboxed_run(Repo, fn ->
      Repo.get!(OAuthSession, candidate.oauth_session_id)
      |> Ecto.Changeset.change(
        expires_at:
          DateTime.utc_now() |> DateTime.add(-25 * 3600, :second) |> DateTime.truncate(:second)
      )
      |> Repo.update!()
    end)

    consumer =
      database_task(fn -> held_consumption(provider, tenant, handle, candidate, parent) end)

    {consumer_backend, _} = start_database_task(consumer)
    assert_receive {:consumed_pending, consumer_pid}, 5_000
    cleanup = database_task(fn -> held_cleanup(&Tango.cleanup_expired_sessions/0, parent) end)
    {cleanup_backend, _} = start_database_task(cleanup)
    await_blocked(cleanup_backend, consumer_backend)
    send(consumer_pid, :commit)
    assert {:ok, %{proof: _}} = Task.await(consumer)
    assert_receive {:cleanup_pending, cleanup_pid, audit_ids}, 5_000
    cleanup_audits_on_exit(audit_ids)
    send(cleanup_pid, :commit)
    assert {:ok, {:ok, 1}} = Task.await(cleanup)

    Sandbox.unboxed_run(Repo, fn ->
      refute Repo.get(OAuthSession, candidate.oauth_session_id)
      refute Repo.get(Authorization, candidate.id)
    end)

    assert_no_connections(provider)
  end

  defp held_cleanup(operation, parent) do
    Repo.transaction(fn ->
      before_ids = Repo.all(from(log in AuditLog, select: log.id))
      result = operation.()
      audit_ids = Repo.all(from(log in AuditLog, select: log.id)) -- before_ids
      send(parent, {:cleanup_pending, self(), audit_ids})

      receive do
        :commit -> result
      end
    end)
  end

  defp cleanup_audits_on_exit(audit_ids) do
    on_exit(fn ->
      Sandbox.unboxed_run(Repo, fn ->
        Repo.delete_all(from(log in AuditLog, where: log.id in ^audit_ids))
      end)
    end)
  end

  defp consume_fixture do
    fixture =
      Sandbox.unboxed_run(Repo, fn ->
        provider = Factory.create_provider()
        tenant = Factory.tenant_id("consume-race")
        {handle, candidate} = initial_candidate(provider, tenant, "consume", :consume)
        {provider, tenant, handle, candidate}
      end)

    {provider, _, _, _} = fixture
    on_exit(fn -> cleanup_provider(provider.id) end)
    fixture
  end

  defp database_task(operation) do
    parent = self()

    task =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          %{rows: [[backend]]} = Repo.query!("SELECT pg_backend_pid()")
          send(parent, {:database_ready, self(), backend})

          receive do
            :go -> operation.()
          end
        end)
      end)

    on_exit(fn -> Process.exit(task.pid, :kill) end)
    task
  end

  defp start_database_task(task) do
    pid = task.pid
    assert_receive {:database_ready, ^pid, backend}, 5_000
    send(pid, :go)
    {backend, pid}
  end

  defp held_consumption(provider, tenant, handle, candidate, parent) do
    consume_multi(provider, tenant, handle, candidate)
    |> Ecto.Multi.run(:host_write, fn repo, _changes ->
      stored = repo.get!(Authorization, candidate.id)
      assert stored.consumed_at
      assert stored.access_token == nil
      assert stored.refresh_token == nil
      assert stored.provider_data == %{}
      send(parent, {:consumed_pending, self()})

      receive do
        :commit -> {:ok, :committed}
        :rollback -> {:error, :host_rejected}
      end
    end)
    |> Repo.transaction()
  end

  defp consume_multi(provider, tenant, handle, candidate) do
    Tango.Authorization.multi_consume_authorization(Ecto.Multi.new(), :proof, handle, tenant,
      provider: provider.slug,
      intent_reference: candidate.intent_reference,
      required_scopes: ["records.read"]
    )
  end

  defp assert_consumed(candidate) do
    Sandbox.unboxed_run(Repo, fn ->
      stored = Repo.get!(Authorization, candidate.id)
      assert stored.consumed_at
      assert stored.access_token == nil
      assert stored.refresh_token == nil
      assert stored.provider_data == %{}
    end)
  end

  defp assert_no_connections(provider) do
    Sandbox.unboxed_run(Repo, fn ->
      refute Repo.exists?(from(c in Connection, where: c.provider_id == ^provider.id))
    end)
  end

  defp initial_candidate(provider, tenant_id, suffix, mode \\ :connection) do
    intent = "intent-#{suffix}-#{System.unique_integer([:positive])}"

    {:ok, session} =
      Tango.create_authorization_session(provider.slug, tenant_id,
        scopes: ["records.read"],
        redirect_uri: "https://api.example.test/callback",
        completion_origin: "https://app.example.test",
        intent_reference: intent,
        completion_mode: mode
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
      completion_mode: mode,
      provider_data: %{"workspace_id" => "synthetic-workspace"},
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

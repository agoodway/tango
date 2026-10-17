defmodule Tango.ConnectionLockTest do
  use ExUnit.Case, async: false

  import Ecto.Query

  alias Ecto.Adapters.SQL.Sandbox
  alias Tango.ConnectionLock
  alias Tango.Factory
  alias Tango.Schemas.{AuditLog, Authorization, Connection, OAuthSession, Provider}
  alias Tango.TestRepo, as: Repo

  defmodule OtherRepo do
    use Ecto.Repo,
      otp_app: :tango,
      adapter: Ecto.Adapters.Postgres
  end

  setup do
    previous_origins = Application.get_env(:tango, :allowed_completion_origins)
    original_repo = Application.get_env(:tango, :repo)
    Application.put_env(:tango, :allowed_completion_origins, ["https://app.example.test"])

    on_exit(fn ->
      if previous_origins,
        do: Application.put_env(:tango, :allowed_completion_origins, previous_origins),
        else: Application.delete_env(:tango, :allowed_completion_origins)

      Application.put_env(:tango, :repo, original_repo)
    end)

    :ok
  end

  test "requires configured-repo transaction in current process" do
    tenant_id = Factory.tenant_id("lock_guard")

    assert {:error, :not_in_transaction} = Tango.lock_connection_generations(tenant_id, [])

    assert {:error, :not_in_transaction} =
             unboxed(fn ->
               Tango.lock_connection_generations(tenant_id, [])
             end)

    :ok = Sandbox.checkout(Repo)

    on_exit(fn -> Sandbox.checkin(Repo) end)

    assert {:error, :not_in_transaction} = Tango.lock_connection_generations(tenant_id, [])

    other = start_other_repo()
    :ok = Sandbox.checkout(other)

    assert {:ok, {:error, :not_in_transaction}} =
             other.transaction(fn ->
               Tango.lock_connection_generations(tenant_id, [])
             end)
  end

  test "resolves all slugs including inactive providers before locking" do
    suffix = System.unique_integer([:positive])
    tenant_id = Factory.tenant_id("lock_resolve")
    missing = "records_missing_#{suffix}"

    active =
      insert_provider!(%{slug: "records_active_#{suffix}", name: "records_active_#{suffix}"})

    inactive =
      insert_provider!(%{
        slug: "records_inactive_#{suffix}",
        name: "records_inactive_#{suffix}",
        active: false
      })

    parent = self()

    holder =
      hold_resolution(tenant_id, [active.slug, missing, "records_later_#{suffix}"], parent)

    holder_pid = holder.pid

    assert_receive {:resolved, ^holder_pid, {:error, {:provider_not_found, ^missing}}}, 5_000
    assert_acquires_immediately(active.id, tenant_id)
    send(holder.pid, :release)
    assert {:ok, {:error, {:provider_not_found, ^missing}}} = Task.await(holder)

    skipped =
      hold_batch(tenant_id, [missing, inactive.slug], [missing: :skip], parent)

    skipped_pid = skipped.pid
    assert_receive {:batch, ^skipped_pid, skipped_backend, :ok}, 5_000

    {waiter, waiter_backend} = start_waiter(fn -> lock_pair(inactive.id, tenant_id) end)
    await_blocked(waiter_backend, skipped_backend)
    send(skipped.pid, :release)
    assert {:ok, :ok} = Task.await(skipped)
    assert {:ok, :ok} = Task.await(waiter)

    assert {:ok, :ok} = unboxed(fn -> empty_lock(tenant_id) end)

    assert_raise ArgumentError, fn ->
      Tango.lock_connection_generations(tenant_id, [], missing: :bogus)
    end

    assert_raise ArgumentError, fn ->
      Tango.lock_connection_generations(tenant_id, [active.slug], unknown: true)
    end
  end

  test "duplicate and nested acquisition holds until outer completion" do
    suffix = System.unique_integer([:positive])

    provider =
      insert_provider!(%{slug: "records_nested_#{suffix}", name: "records_nested_#{suffix}"})

    tenant_id = Factory.tenant_id("lock_nested")
    parent = self()

    holder =
      track(
        Task.async(fn -> unboxed(fn -> nested_hold(tenant_id, provider.slug, parent) end) end)
      )

    holder_pid = holder.pid
    assert_receive {:outer, ^holder_pid, holder_backend}, 5_000

    {waiter, waiter_backend} = start_waiter(fn -> lock_pair(provider.id, tenant_id) end)
    await_blocked(waiter_backend, holder_backend)
    assert_receive {:nested, {:ok, :ok}}, 5_000
    await_blocked(waiter_backend, holder_backend)

    send(holder.pid, :release)
    assert {:ok, :ok} = Task.await(holder)
    assert {:ok, :ok} = Task.await(waiter)

    rolled =
      track(
        Task.async(fn -> unboxed(fn -> rollback_hold(tenant_id, provider.slug, parent) end) end)
      )

    rolled_pid = rolled.pid
    assert_receive {:rollback_ready, ^rolled_pid, rolled_backend}, 5_000

    {contender, contender_backend} = start_waiter(fn -> lock_pair(provider.id, tenant_id) end)
    await_blocked(contender_backend, rolled_backend)
    send(rolled.pid, :rollback)
    assert {:error, :released} = Task.await(rolled)
    assert {:ok, :ok} = Task.await(contender)
  end

  test "public batch and tenant revoke use provider id order" do
    suffix = System.unique_integer([:positive])
    tenant_id = Factory.tenant_id("lock_id_order")
    low = insert_provider!(%{slug: "z_records_#{suffix}", name: "z_records_#{suffix}"})
    high = insert_provider!(%{slug: "a_records_#{suffix}", name: "a_records_#{suffix}"})
    assert low.id < high.id
    assert high.slug < low.slug

    unboxed(fn ->
      Factory.create_connection(low, tenant_id)
      Factory.create_connection(high, tenant_id)
    end)

    parent = self()
    holder = hold_key(low.id, tenant_id, parent)
    holder_pid = holder.pid
    assert_receive {:held, ^holder_pid, holder_backend}, 5_000

    {batch, batch_backend} =
      start_waiter(fn -> batch_transaction(tenant_id, [high.slug, low.slug]) end)

    {revoke, revoke_backend} =
      start_waiter(fn -> Tango.Connection.revoke_tenant_connections(tenant_id) end)

    await_blocked(batch_backend, holder_backend)
    await_blocked(revoke_backend, holder_backend)
    assert_acquires_immediately(high.id, tenant_id)

    send(holder.pid, :release)
    assert {:ok, :ok} = Task.await(holder)
    assert {:ok, :ok} = Task.await(batch)
    assert {:ok, 2} = Task.await(revoke)
  end

  test "provider revoke and key helper use binary tenant order" do
    suffix = System.unique_integer([:positive])

    provider =
      insert_provider!(%{slug: "records_tenants_#{suffix}", name: "records_tenants_#{suffix}"})

    unboxed(fn ->
      Factory.create_connection(provider, "a")
      Factory.create_connection(provider, "Z")
    end)

    assert Enum.sort(["a", "Z"]) == ["Z", "a"]

    parent = self()
    keys = [{provider.id, "a"}, {provider.id, "Z"}]
    holder = hold_key(provider.id, "a", parent)
    holder_pid = holder.pid
    assert_receive {:held, ^holder_pid, holder_backend}, 5_000

    {ordered, ordered_backend} = start_waiter(fn -> ordered_transaction(keys) end)
    await_blocked(ordered_backend, holder_backend)

    {probe, probe_backend} = start_waiter(fn -> lock_pair(provider.id, "Z") end)
    await_blocked(probe_backend, ordered_backend)

    send(holder.pid, :release)
    assert {:ok, :ok} = Task.await(holder)
    assert {:ok, :ok} = Task.await(ordered)
    assert {:ok, :ok} = Task.await(probe)

    revoke_holder = hold_key(provider.id, "a", parent)
    revoke_holder_pid = revoke_holder.pid
    assert_receive {:held, ^revoke_holder_pid, revoke_holder_backend}, 5_000

    {revoke, revoke_backend} =
      start_waiter(fn -> Tango.Connection.revoke_provider_connections(provider.slug) end)

    await_blocked(revoke_backend, revoke_holder_backend)

    {revoke_probe, revoke_probe_backend} = start_waiter(fn -> lock_pair(provider.id, "Z") end)
    await_blocked(revoke_probe_backend, revoke_backend)

    send(revoke_holder.pid, :release)
    assert {:ok, :ok} = Task.await(revoke_holder)
    assert {:ok, 2} = Task.await(revoke)
    assert {:ok, :ok} = Task.await(revoke_probe)
  end

  test "generation lock blocks refresh finalize and revoke" do
    suffix = System.unique_integer([:positive])

    {provider, tenant_id, handle, candidate} =
      unboxed(fn ->
        provider =
          Factory.create_provider(%{
            slug: "records_finalize_#{suffix}",
            name: "records_finalize_#{suffix}"
          })

        tenant_id = Factory.tenant_id("lock_finalize")
        {handle, candidate} = initial_candidate(provider, tenant_id, "generation")
        {provider, tenant_id, handle, candidate}
      end)

    on_exit(fn -> cleanup_providers([provider.id]) end)

    parent = self()
    holder = hold_key(provider.id, tenant_id, parent)
    holder_pid = holder.pid
    assert_receive {:held, ^holder_pid, holder_backend}, 5_000

    {finalize, finalize_backend} =
      start_waiter(fn -> finalize_candidate(provider, tenant_id, handle, candidate) end)

    await_blocked(finalize_backend, holder_backend)
    assert Task.yield(finalize, 100) == nil
    send(holder.pid, :release)
    assert {:ok, :ok} = Task.await(holder)

    assert {:ok, %{grant: %{connection: connection}}} = Task.await(finalize)

    refresh_holder = hold_key(provider.id, tenant_id, parent)
    refresh_holder_pid = refresh_holder.pid
    assert_receive {:held, ^refresh_holder_pid, refresh_backend}, 5_000

    {refresh, refresh_waiter} =
      start_waiter(fn -> Tango.Connection.refresh_if_needed(connection) end)

    await_blocked(refresh_waiter, refresh_backend)
    assert Task.yield(refresh, 100) == nil
    send(refresh_holder.pid, :release)
    assert {:ok, :ok} = Task.await(refresh_holder)
    assert {:ok, %{id: connection_id}} = Task.await(refresh)
    assert connection_id == connection.id

    revoke_holder = hold_key(provider.id, tenant_id, parent)
    revoke_holder_pid = revoke_holder.pid
    assert_receive {:held, ^revoke_holder_pid, revoke_backend}, 5_000

    {revoke, revoke_waiter} =
      start_waiter(fn -> Tango.revoke_connection(connection, tenant_id) end)

    await_blocked(revoke_waiter, revoke_backend)
    assert Task.yield(revoke, 100) == nil
    send(revoke_holder.pid, :release)
    assert {:ok, :ok} = Task.await(revoke_holder)
    assert {:ok, %{status: :revoked}} = Task.await(revoke)
  end

  defp start_other_repo do
    config = Keyword.delete(Tango.TestRepo.config(), :name)
    {:ok, pid} = OtherRepo.start_link(config)
    Process.unlink(pid)
    Sandbox.mode(OtherRepo, :manual)

    on_exit(fn -> stop_other_repo(pid) end)

    OtherRepo
  end

  defp stop_other_repo(pid) do
    if Process.alive?(pid), do: Process.exit(pid, :kill)
    :ok
  end

  defp insert_provider!(attrs) do
    provider = unboxed(fn -> Factory.create_provider(attrs) end)
    on_exit(fn -> cleanup_providers([provider.id]) end)
    provider
  end

  defp unboxed(fun), do: Sandbox.unboxed_run(Repo, fun)

  defp hold_resolution(tenant_id, slugs, parent) do
    track(
      Task.async(fn -> unboxed(fn -> resolution_transaction(tenant_id, slugs, parent) end) end)
    )
  end

  defp resolution_transaction(tenant_id, slugs, parent) do
    Repo.transaction(fn ->
      result = Tango.lock_connection_generations(tenant_id, slugs)
      send(parent, {:resolved, self(), result})

      receive do
        :release -> result
      end
    end)
  end

  defp hold_batch(tenant_id, slugs, opts, parent) do
    track(Task.async(fn -> unboxed(fn -> batch_hold(tenant_id, slugs, opts, parent) end) end))
  end

  defp batch_hold(tenant_id, slugs, opts, parent) do
    Repo.transaction(fn ->
      result = Tango.lock_connection_generations(tenant_id, slugs, opts)
      send(parent, {:batch, self(), backend_pid(), result})

      receive do
        :release -> result
      end
    end)
  end

  defp hold_key(provider_id, tenant_id, parent) do
    track(
      Task.async(fn ->
        unboxed(fn -> hold_key_transaction(provider_id, tenant_id, parent) end)
      end)
    )
  end

  defp hold_key_transaction(provider_id, tenant_id, parent) do
    Repo.transaction(fn ->
      :ok = ConnectionLock.lock(Repo, provider_id, tenant_id)
      send(parent, {:held, self(), backend_pid()})

      receive do
        :release -> :ok
      end
    end)
  end

  defp nested_hold(tenant_id, slug, parent) do
    Repo.transaction(fn ->
      :ok = Tango.lock_connection_generations(tenant_id, [slug])
      :ok = Tango.lock_connection_generations(tenant_id, [slug])
      send(parent, {:outer, self(), backend_pid()})
      nested = nested_lock(tenant_id, slug)
      send(parent, {:nested, nested})

      receive do
        :release -> :ok
      end
    end)
  end

  defp nested_lock(tenant_id, slug) do
    Repo.transaction(fn ->
      Tango.lock_connection_generations(tenant_id, [slug])
    end)
  end

  defp rollback_hold(tenant_id, slug, parent) do
    Repo.transaction(fn ->
      :ok = Tango.lock_connection_generations(tenant_id, [slug])
      send(parent, {:rollback_ready, self(), backend_pid()})

      receive do
        :rollback -> Repo.rollback(:released)
      end
    end)
  end

  defp empty_lock(tenant_id) do
    Repo.transaction(fn ->
      Tango.lock_connection_generations(tenant_id, [])
    end)
  end

  defp batch_transaction(tenant_id, slugs) do
    Repo.transaction(fn ->
      Tango.lock_connection_generations(tenant_id, slugs)
    end)
  end

  defp ordered_transaction(keys) do
    Repo.transaction(fn ->
      ConnectionLock.lock_ordered(Repo, keys)
    end)
  end

  defp lock_pair(provider_id, tenant_id) do
    Repo.transaction(fn ->
      ConnectionLock.lock(Repo, provider_id, tenant_id)
    end)
  end

  defp start_waiter(fun) do
    parent = self()

    task =
      track(Task.async(fn -> unboxed(fn -> announce_and_run(parent, fun) end) end))

    task_pid = task.pid
    assert_receive {:waiter, ^task_pid, backend}, 5_000
    {task, backend}
  end

  defp announce_and_run(parent, fun) do
    send(parent, {:waiter, self(), backend_pid()})
    fun.()
  end

  defp assert_acquires_immediately(provider_id, tenant_id) do
    task = track(Task.async(fn -> unboxed(fn -> lock_pair(provider_id, tenant_id) end) end))

    case Task.yield(task, 1_000) do
      {:ok, {:ok, :ok}} -> :ok
      other -> flunk("expected the generation key to be free, got #{inspect(other)}")
    end
  end

  defp track(%Task{} = task) do
    on_exit(fn ->
      if Process.alive?(task.pid) do
        send(task.pid, :release)
        Process.exit(task.pid, :kill)
      end
    end)

    task
  end

  defp backend_pid do
    %{rows: [[pid]]} = Repo.query!("SELECT pg_backend_pid()")
    pid
  end

  defp await_blocked(waiter_pid, holder_pid, attempts \\ 100)

  defp await_blocked(_waiter_pid, _holder_pid, 0),
    do: flunk("provider/tenant advisory lock did not serialize callers")

  defp await_blocked(waiter_pid, holder_pid, attempts) do
    %{rows: [[blocked?]]} =
      unboxed(fn ->
        Repo.query!("SELECT $1::int = ANY(pg_blocking_pids($2::int))", [holder_pid, waiter_pid])
      end)

    if blocked? do
      :ok
    else
      Process.sleep(20)
      await_blocked(waiter_pid, holder_pid, attempts - 1)
    end
  end

  defp finalize_candidate(provider, tenant_id, handle, candidate) do
    Ecto.Multi.new()
    |> Tango.multi_finalize_authorization(
      :grant,
      handle,
      tenant_id,
      finalize_opts(provider, candidate)
    )
    |> Repo.transaction()
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

  defp cleanup_providers(provider_ids) do
    unboxed(fn ->
      Repo.delete_all(from(a in AuditLog, where: a.provider_id in ^provider_ids))
      Repo.delete_all(from(a in Authorization, where: a.provider_id in ^provider_ids))
      Repo.delete_all(from(s in OAuthSession, where: s.provider_id in ^provider_ids))
      Repo.delete_all(from(c in Connection, where: c.provider_id in ^provider_ids))
      Repo.delete_all(from(p in Provider, where: p.id in ^provider_ids))
    end)
  end
end

defmodule Tango.TokenResponseMetadataMigrationTest do
  use Tango.DatabaseCase, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias Ecto.Migrator
  alias Tango.Schemas.{Authorization, OAuthSession}
  alias Tango.Types.EncryptedBinary

  @prefix "tango_v04_roundtrip"
  @bootstrap_version 20_991_026_120_000
  @upgrade_version 20_991_026_120_001
  @race_prefix "tango_v04_rollback_race"
  @race_bootstrap_version 20_991_026_120_010
  @race_upgrade_version 20_991_026_120_011

  defmodule Bootstrap do
    use Ecto.Migration
    def up, do: Tango.Migration.up(version: 3, prefix: "tango_v04_roundtrip")
    def down, do: Tango.Migration.down(version: 0, prefix: "tango_v04_roundtrip")
  end

  defmodule Upgrade do
    use Ecto.Migration
    def up, do: Tango.Migration.up(version: 4, prefix: "tango_v04_roundtrip")
    def down, do: Tango.Migration.down(version: 3, prefix: "tango_v04_roundtrip")
  end

  defmodule RaceBootstrap do
    use Ecto.Migration
    def up, do: Tango.Migration.up(version: 3, prefix: "tango_v04_rollback_race")
  end

  defmodule RaceUpgrade do
    use Ecto.Migration
    def up, do: Tango.Migration.up(version: 4, prefix: "tango_v04_rollback_race")

    def down do
      %{rows: [[backend_pid]]} = Tango.TestRepo.query!("SELECT pg_backend_pid()")
      send(:tango_v04_rollback_race_parent, {:rollback_backend, backend_pid})
      Tango.Migration.down(version: 3, prefix: "tango_v04_rollback_race")
    end
  end

  test "V03 -> V04 -> V03 -> V04 roundtrip preserves rows and adds only V04 objects" do
    migrate(:up, @bootstrap_version, Bootstrap)
    assert migrated_version() == 3
    refute provider_data_column?()
    refute column?("tango_oauth_sessions", "completion_mode")
    refute column?("tango_authorizations", "completion_mode")

    candidate_id = insert_candidate(insert_provider())

    migrate(:up, @upgrade_version, Upgrade)
    assert migrated_version() == 4
    assert provider_data_column?()
    assert provider_data_check?()
    assert provider_data(candidate_id) == %{}
    assert_completion_mode_defaults(candidate_id)
    assert_completion_mode_checks()

    migrate(:down, @upgrade_version, Upgrade)
    assert migrated_version() == 3
    refute provider_data_column?()
    refute provider_data_check?()
    refute column?("tango_oauth_sessions", "completion_mode")
    refute column?("tango_authorizations", "completion_mode")
    assert column?("tango_oauth_sessions", "expected_connection_id")
    assert column?("tango_connections", "account_subject")
    assert candidate_id == candidate_value(candidate_id, "id")

    migrate(:up, @upgrade_version, Upgrade)
    assert migrated_version() == 4
    assert provider_data(candidate_id) == %{}
    assert_completion_mode_defaults(candidate_id)
    assert_completion_mode_checks()
  end

  test "V04 stores object provider_data and its check rejects other JSON values" do
    migrate(:up, @bootstrap_version, Bootstrap)
    migrate(:up, @upgrade_version, Upgrade)
    candidate_id = insert_candidate(insert_provider())

    Repo.query!(
      ~s(UPDATE "#{@prefix}".tango_authorizations SET provider_data = $2 WHERE id = $1),
      [candidate_id, %{"instance_url" => "https://instance.example.test"}]
    )

    assert provider_data(candidate_id) == %{"instance_url" => "https://instance.example.test"}

    for value <- ["[]", ~s("text"), "1", "null"] do
      assert {:error,
              %Postgrex.Error{
                postgres: %{
                  code: :check_violation,
                  constraint: "tango_authorizations_provider_data_check"
                }
              }} =
               Repo.transaction(fn ->
                 case Repo.query(
                        """
                        UPDATE "#{@prefix}".tango_authorizations
                        SET provider_data = $2::text::jsonb WHERE id = $1
                        """,
                        [candidate_id, value]
                      ) do
                   {:ok, result} -> result
                   {:error, error} -> Repo.rollback(error)
                 end
               end)
    end
  end

  test "V04 rejects unknown and null modes and connection bindings for consume rows" do
    migrate(:up, @bootstrap_version, Bootstrap)
    migrate(:up, @upgrade_version, Upgrade)
    candidate_id = insert_candidate(insert_provider())
    session_id = candidate_value(candidate_id, "oauth_session_id")

    for {table, id} <- [
          {"tango_oauth_sessions", session_id},
          {"tango_authorizations", candidate_id}
        ] do
      assert_update_error(
        table,
        id,
        "completion_mode = 'unknown'",
        :check_violation,
        "#{table}_completion_mode_check"
      )

      assert_update_error(table, id, "completion_mode = NULL", :not_null_violation, nil)

      assert_update_error(
        table,
        id,
        "completion_mode = 'consume', expected_connection_id = -1",
        :check_violation,
        "#{table}_consume_connection_check"
      )
    end

    assert_update_error(
      "tango_authorizations",
      candidate_id,
      "completion_mode = 'consume', verified_connection_id = -1",
      :check_violation,
      "tango_authorizations_consume_connection_check"
    )
  end

  for pending <- [:session, :candidate] do
    test "V04 rollback refuses a pending consume #{pending} before removing any V04 objects" do
      migrate(:up, @bootstrap_version, Bootstrap)
      migrate(:up, @upgrade_version, Upgrade)
      candidate_id = insert_candidate(insert_provider())
      session_id = candidate_value(candidate_id, "oauth_session_id")
      now = database_now()

      case unquote(pending) do
        :session ->
          set_session(session_id, "completion_mode = 'consume', expires_at = $2", [
            DateTime.add(now, 60)
          ])

        :candidate ->
          set_session(session_id, "completion_mode = 'consume', exchanged_at = $2", [now])

          set_candidate(candidate_id, "completion_mode = 'consume', expires_at = $2", [
            DateTime.add(now, 60)
          ])
      end

      assert_raise Postgrex.Error, ~r/Pending consume authorizations prevent V04 rollback/, fn ->
        Migrator.down(Repo, @upgrade_version, Upgrade, log: false, migration_lock: false)
      end

      assert migrated_version() == 4
      assert provider_data_column?()
      assert provider_data_check?()
      assert_completion_mode_checks()
      assert column?("tango_oauth_sessions", "completion_mode")
      assert column?("tango_authorizations", "completion_mode")
    end
  end

  test "V04 rollback waits for an in-flight consume writer and refuses after its commit" do
    assert Process.register(self(), :tango_v04_rollback_race_parent)

    Sandbox.unboxed_run(Repo, fn -> refute schema_exists?(@race_prefix) end)
    on_exit(fn -> cleanup_race_prefix() end)

    Sandbox.unboxed_run(Repo, fn ->
      migrate(:up, @race_bootstrap_version, RaceBootstrap)
      migrate(:up, @race_upgrade_version, RaceUpgrade)
    end)

    candidate_id =
      Sandbox.unboxed_run(Repo, fn ->
        insert_candidate(insert_provider(@race_prefix), @race_prefix)
      end)

    parent = self()

    writer =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          Repo.transaction(fn ->
            %{rows: [[backend_pid]]} = Repo.query!("SELECT pg_backend_pid()")

            Repo.query!(
              """
              UPDATE "#{@race_prefix}".tango_authorizations
              SET completion_mode = 'consume', expires_at = now() + interval '1 hour'
              WHERE id = $1
              """,
              [candidate_id]
            )

            send(parent, {:writer_pending, backend_pid})

            receive do
              :commit -> :ok
            after
              10_000 -> flunk("writer commit barrier was not released")
            end
          end)
        end)
      end)

    assert_receive {:writer_pending, writer_backend}, 5_000

    rollback =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          try do
            Migrator.down(Repo, @race_upgrade_version, RaceUpgrade,
              log: false,
              migration_lock: false
            )
          rescue
            error in Postgrex.Error -> {:error, error}
          end
        end)
      end)

    assert_receive {:rollback_backend, rollback_backend}, 5_000
    await_blocked(rollback_backend, writer_backend)
    send(writer.pid, :commit)
    assert {:ok, :ok} = Task.await(writer)

    assert {:error, %Postgrex.Error{} = error} = Task.await(rollback)
    assert Exception.message(error) =~ "Pending consume authorizations prevent V04 rollback"

    Sandbox.unboxed_run(Repo, fn ->
      assert migrated_version(@race_prefix) == 4
      assert column?("tango_oauth_sessions", "completion_mode", @race_prefix)
      assert column?("tango_authorizations", "completion_mode", @race_prefix)
      assert column?("tango_authorizations", "provider_data", @race_prefix)
      assert constraint?("tango_authorizations_completion_mode_check", @race_prefix)
      assert constraint?("tango_authorizations_provider_data_check", @race_prefix)
    end)
  end

  for terminal <- [:exchanged_session, :expired_session, :consumed_candidate, :expired_candidate] do
    test "V04 rollback permits a consume #{terminal}" do
      migrate(:up, @bootstrap_version, Bootstrap)
      migrate(:up, @upgrade_version, Upgrade)
      candidate_id = insert_candidate(insert_provider())
      session_id = candidate_value(candidate_id, "oauth_session_id")
      now = database_now()
      set_session(session_id, "completion_mode = 'consume', exchanged_at = $2", [now])

      case unquote(terminal) do
        :exchanged_session ->
          :ok

        :expired_session ->
          set_session(session_id, "exchanged_at = NULL, expires_at = $2", [now])

        :consumed_candidate ->
          set_candidate(candidate_id, "completion_mode = 'consume', consumed_at = $2", [now])

        :expired_candidate ->
          set_candidate(candidate_id, "completion_mode = 'consume', expires_at = $2", [now])
      end

      migrate(:down, @upgrade_version, Upgrade)
      assert migrated_version() == 3
      refute provider_data_column?()
      refute column?("tango_oauth_sessions", "completion_mode")
      refute column?("tango_authorizations", "completion_mode")
      assert candidate_id == candidate_value(candidate_id, "id")
    end
  end

  defp assert_completion_mode_defaults(candidate_id) do
    session_id = candidate_value(candidate_id, "oauth_session_id")
    assert Repo.get!(Authorization, candidate_id, prefix: @prefix).completion_mode == :connection
    assert Repo.get!(OAuthSession, session_id, prefix: @prefix).completion_mode == :connection
    assert candidate_value(candidate_id, "completion_mode") == "connection"

    for table <- ["tango_oauth_sessions", "tango_authorizations"] do
      %{rows: [["NO", default]]} =
        Repo.query!(
          """
          SELECT is_nullable, column_default FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = $2 AND column_name = 'completion_mode'
          """,
          [@prefix, table]
        )

      assert default == "'connection'::text"
    end
  end

  defp assert_completion_mode_checks do
    for table <- ["tango_oauth_sessions", "tango_authorizations"],
        suffix <- ["completion_mode_check", "consume_connection_check"] do
      assert constraint?("#{table}_#{suffix}")
    end
  end

  defp assert_update_error(table, id, assignments, code, constraint) do
    assert {:error, %Postgrex.Error{postgres: postgres}} =
             Repo.transaction(fn ->
               case Repo.query(
                      ~s(UPDATE "#{@prefix}".#{table} SET #{assignments} WHERE id = $1),
                      [id]
                    ) do
                 {:ok, result} -> result
                 {:error, error} -> Repo.rollback(error)
               end
             end)

    assert postgres.code == code
    if constraint, do: assert(postgres.constraint == constraint)
  end

  defp database_now do
    %{rows: [[now]]} = Repo.query!("SELECT now()")
    now
  end

  defp set_session(id, assignments, params),
    do:
      Repo.query!(~s(UPDATE "#{@prefix}".tango_oauth_sessions SET #{assignments} WHERE id = $1), [
        id | params
      ])

  defp set_candidate(id, assignments, params),
    do:
      Repo.query!(~s(UPDATE "#{@prefix}".tango_authorizations SET #{assignments} WHERE id = $1), [
        id | params
      ])

  defp candidate_value(id, column) do
    %{rows: [[value]]} =
      Repo.query!(~s(SELECT #{column} FROM "#{@prefix}".tango_authorizations WHERE id = $1), [id])

    value
  end

  defp migrate(direction, version, module),
    do:
      assert(
        :ok =
          apply(Migrator, direction, [Repo, version, module, [log: false, migration_lock: false]])
      )

  defp migrated_version(prefix \\ @prefix) do
    %{rows: [[comment]]} =
      Repo.query!("SELECT obj_description(($1 || '.tango_providers')::regclass, 'pg_class')", [
        prefix
      ])

    [_, version] = Regex.run(~r/version=(\d+)/, comment)
    String.to_integer(version)
  end

  defp provider_data_column?, do: column?("tango_authorizations", "provider_data")
  defp provider_data_check?, do: constraint?("tango_authorizations_provider_data_check")

  defp column?(table, column, prefix \\ @prefix) do
    %{num_rows: rows} =
      Repo.query!(
        """
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2 AND column_name = $3
        """,
        [prefix, table, column]
      )

    rows == 1
  end

  defp constraint?(name, prefix \\ @prefix) do
    %{num_rows: rows} =
      Repo.query!(
        """
        SELECT 1 FROM pg_constraint c
        JOIN pg_namespace n ON n.oid = c.connamespace
        WHERE n.nspname = $1 AND c.conname = $2
        """,
        [prefix, name]
      )

    rows == 1
  end

  defp provider_data(candidate_id) do
    %{rows: [[data]]} =
      Repo.query!(
        ~s(SELECT provider_data FROM "#{@prefix}".tango_authorizations WHERE id = $1),
        [candidate_id]
      )

    data
  end

  defp insert_provider(prefix \\ @prefix) do
    %{rows: [[id]]} =
      Repo.query!(
        """
        INSERT INTO "#{prefix}".tango_providers
          (slug, name, client_secret, inserted_at, updated_at)
        VALUES ('metadata-migration', 'Metadata migration', $1, now(), now()) RETURNING id
        """,
        [<<1, 2, 3>>]
      )

    id
  end

  defp insert_candidate(provider_id, prefix \\ @prefix) do
    {:ok, encrypted_token} = EncryptedBinary.dump("synthetic-access-token")

    %{rows: [[session_id]]} =
      Repo.query!(
        """
        INSERT INTO "#{prefix}".tango_oauth_sessions
          (provider_id, tenant_id, session_token, state, expires_at, inserted_at, updated_at)
        VALUES ($1, 'metadata-tenant', 'synthetic-session', 'synthetic-state',
          now() + interval '1 hour', now(), now())
        RETURNING id
        """,
        [provider_id]
      )

    %{rows: [[candidate_id]]} =
      Repo.query!(
        """
        INSERT INTO "#{prefix}".tango_authorizations
          (provider_id, oauth_session_id, tenant_id, handle_hash, oauth_client_id, intent_reference,
           completion_origin, access_token, expires_at, inserted_at, updated_at)
        VALUES ($1, $2, 'metadata-tenant', $3, 'client-synthetic', 'intent',
           'https://metadata.example.test', $4, now() + interval '10 minutes', now(), now())
        RETURNING id
        """,
        [provider_id, session_id, :crypto.hash(:sha256, "synthetic-handle"), encrypted_token]
      )

    candidate_id
  end

  defp schema_exists?(prefix) do
    %{num_rows: rows} = Repo.query!("SELECT 1 FROM pg_namespace WHERE nspname = $1", [prefix])
    rows == 1
  end

  defp cleanup_race_prefix do
    Sandbox.unboxed_run(Repo, fn ->
      Repo.query!(~s(DROP SCHEMA IF EXISTS "#{@race_prefix}" CASCADE))

      Repo.query!(
        "DELETE FROM schema_migrations WHERE version IN ($1, $2)",
        [@race_bootstrap_version, @race_upgrade_version]
      )
    end)
  end

  defp await_blocked(waiter_backend, holder_backend, attempts \\ 100)

  defp await_blocked(_waiter_backend, _holder_backend, 0),
    do: flunk("rollback never waited for the in-flight consume writer")

  defp await_blocked(waiter_backend, holder_backend, attempts) do
    %{rows: [[blocked?]]} =
      Sandbox.unboxed_run(Repo, fn ->
        Repo.query!("SELECT $1::int = ANY(pg_blocking_pids($2::int))", [
          holder_backend,
          waiter_backend
        ])
      end)

    if blocked? do
      :ok
    else
      Process.sleep(20)
      await_blocked(waiter_backend, holder_backend, attempts - 1)
    end
  end
end

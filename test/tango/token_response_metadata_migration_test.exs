defmodule Tango.TokenResponseMetadataMigrationTest do
  use Tango.DatabaseCase, async: false

  alias Ecto.Migrator

  @prefix "tango_v04_roundtrip"
  @bootstrap_version 20_991_026_120_000
  @upgrade_version 20_991_026_120_001

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

  test "V03 -> V04 -> V03 -> V04 roundtrip adds and drops provider_data and its check" do
    migrate(:up, @bootstrap_version, Bootstrap)
    assert migrated_version() == 3
    refute provider_data_column?()

    candidate_id = insert_candidate(insert_provider())

    migrate(:up, @upgrade_version, Upgrade)
    assert migrated_version() == 4
    assert provider_data_column?()
    assert provider_data_check?()
    assert provider_data(candidate_id) == %{}

    migrate(:down, @upgrade_version, Upgrade)
    assert migrated_version() == 3
    refute provider_data_column?()
    refute provider_data_check?()

    migrate(:up, @upgrade_version, Upgrade)
    assert migrated_version() == 4
    assert provider_data(candidate_id) == %{}
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

  defp migrate(direction, version, module),
    do:
      assert(
        :ok =
          apply(Migrator, direction, [Repo, version, module, [log: false, migration_lock: false]])
      )

  defp migrated_version do
    %{rows: [[comment]]} =
      Repo.query!("SELECT obj_description(($1 || '.tango_providers')::regclass, 'pg_class')", [
        @prefix
      ])

    [_, version] = Regex.run(~r/version=(\d+)/, comment)
    String.to_integer(version)
  end

  defp provider_data_column? do
    %{num_rows: rows} =
      Repo.query!(
        """
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = 'tango_authorizations' AND column_name = 'provider_data'
        """,
        [@prefix]
      )

    rows == 1
  end

  defp provider_data_check? do
    %{num_rows: rows} =
      Repo.query!(
        """
        SELECT 1 FROM pg_constraint c
        JOIN pg_namespace n ON n.oid = c.connamespace
        WHERE n.nspname = $1 AND c.conname = 'tango_authorizations_provider_data_check'
        """,
        [@prefix]
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

  defp insert_provider do
    %{rows: [[id]]} =
      Repo.query!(
        """
        INSERT INTO "#{@prefix}".tango_providers
          (slug, name, client_secret, inserted_at, updated_at)
        VALUES ('metadata-migration', 'Metadata migration', $1, now(), now()) RETURNING id
        """,
        [<<1, 2, 3>>]
      )

    id
  end

  defp insert_candidate(provider_id) do
    %{rows: [[session_id]]} =
      Repo.query!(
        """
        INSERT INTO "#{@prefix}".tango_oauth_sessions
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
        INSERT INTO "#{@prefix}".tango_authorizations
          (provider_id, oauth_session_id, tenant_id, handle_hash, oauth_client_id, intent_reference,
           completion_origin, access_token, expires_at, inserted_at, updated_at)
        VALUES ($1, $2, 'metadata-tenant', $3, 'client-synthetic', 'intent',
           'https://metadata.example.test', $4, now() + interval '10 minutes', now(), now())
        RETURNING id
        """,
        [provider_id, session_id, :crypto.hash(:sha256, "synthetic-handle"), <<4, 5, 6>>]
      )

    candidate_id
  end
end

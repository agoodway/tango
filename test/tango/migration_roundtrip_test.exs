defmodule Tango.MigrationRoundtripTest do
  @moduledoc """
  Executes the V01 ↔ V02 schema migration in both directions in a dedicated
  test prefix, with a connection row in place.

  Runs through `Ecto.Migrator` because `Tango.Migration.up/down` execute inside
  an Ecto migration runner — the same way a consuming application calls them.
  The wrapper modules below mirror the pinned-range upgrade migration the
  README prescribes, so this also proves that snippet rolls back to V01 rather
  than to zero. The main test schema is never changed.
  """

  use Tango.DatabaseCase, async: false

  alias Ecto.Migrator

  @prefix "tango_v02_roundtrip_test"

  defmodule BootstrapTangoV2 do
    use Ecto.Migration

    def up, do: Tango.Migration.up(version: 2, prefix: "tango_v02_roundtrip_test")
    def down, do: Tango.Migration.down(version: 0, prefix: "tango_v02_roundtrip_test")
  end

  defmodule UpgradeTangoV2 do
    use Ecto.Migration

    def up, do: Tango.Migration.up(version: 2, prefix: "tango_v02_roundtrip_test")
    def down, do: Tango.Migration.down(version: 1, prefix: "tango_v02_roundtrip_test")
  end

  @bootstrap_version 20_990_101_119_999
  @upgrade_version 20_990_101_120_000

  test "V02 rolls back to V01 and reapplies with an existing connection row intact" do
    assert :ok =
             Migrator.up(Repo, @bootstrap_version, BootstrapTangoV2,
               log: false,
               migration_lock: false
             )

    tenant_id = "migration_roundtrip_#{System.unique_integer([:positive])}"
    connection_id = insert_connection(tenant_id)

    assert migrated_version_comment() == "Tango version=2"

    # Register the wrapper migration as applied: the schema already sits at
    # V02, so this runs no DDL, but Migrator.down only rolls back a migration
    # it has recorded.
    assert :ok =
             Migrator.up(Repo, @upgrade_version, UpgradeTangoV2,
               log: false,
               migration_lock: false
             )

    # V02 -> V01: the rejection-counter columns go away, nothing else does.
    assert :ok =
             Migrator.down(Repo, @upgrade_version, UpgradeTangoV2,
               log: false,
               migration_lock: false
             )

    assert migrated_version_comment() == "Tango version=1"
    refute column_exists?("auth_failures")
    refute column_exists?("last_auth_failure")

    # Raw SQL: the V02 schema struct would SELECT the dropped columns.
    %{rows: [[fetched_tenant]]} =
      Repo.query!(
        ~s[SELECT tenant_id FROM "#{@prefix}".tango_connections WHERE id = $1],
        [connection_id]
      )

    assert fetched_tenant == tenant_id

    # V01 -> V02: columns return with their defaults on the existing row.
    assert :ok =
             Migrator.up(Repo, @upgrade_version, UpgradeTangoV2,
               log: false,
               migration_lock: false
             )

    assert migrated_version_comment() == "Tango version=2"
    assert column_exists?("auth_failures")
    assert column_exists?("last_auth_failure")

    %{rows: [[auth_failures, last_auth_failure]]} =
      Repo.query!(
        """
        SELECT auth_failures, last_auth_failure
        FROM "#{@prefix}".tango_connections
        WHERE id = $1
        """,
        [connection_id]
      )

    assert auth_failures == 0
    assert last_auth_failure == nil
  end

  defp insert_connection(tenant_id) do
    now = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)

    %{rows: [[provider_id]]} =
      Repo.query!(
        """
        INSERT INTO "#{@prefix}".tango_providers
          (slug, name, inserted_at, updated_at)
        VALUES ($1, $2, $3, $3)
        RETURNING id
        """,
        ["roundtrip-provider", "Roundtrip Provider", now]
      )

    %{rows: [[connection_id]]} =
      Repo.query!(
        """
        INSERT INTO "#{@prefix}".tango_connections
          (provider_id, tenant_id, access_token, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $4)
        RETURNING id
        """,
        [provider_id, tenant_id, <<1>>, now]
      )

    connection_id
  end

  defp migrated_version_comment do
    %{rows: [[comment]]} =
      Repo.query!("SELECT obj_description('#{@prefix}.tango_providers'::regclass, 'pg_class')")

    comment
  end

  defp column_exists?(column) do
    %{rows: [[count]]} =
      Repo.query!(
        """
        SELECT count(*) FROM information_schema.columns
        WHERE table_schema = $1
          AND table_name = 'tango_connections'
          AND column_name = $2
        """,
        [@prefix, column]
      )

    count == 1
  end
end

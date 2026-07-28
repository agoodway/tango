defmodule Tango.MigrationRoundtripTest do
  @moduledoc """
  Executes the V01 ↔ V02 schema migration in both directions against the test
  database, with a connection row in place.

  Runs through `Ecto.Migrator` because `Tango.Migration.up/down` execute inside
  an Ecto migration runner — the same way a consuming application calls them.
  The wrapper modules below mirror the pinned-range upgrade migration the
  README prescribes, so this also proves that snippet rolls back to V01 rather
  than to zero. All DDL happens inside the SQL sandbox and rolls back with the
  test.
  """

  use Tango.DatabaseCase, async: false

  alias Ecto.Migrator
  alias Tango.Factory
  alias Tango.Schemas.Connection

  defmodule UpgradeTangoV2 do
    use Ecto.Migration

    def up, do: Tango.Migration.up(version: 2)
    def down, do: Tango.Migration.down(version: 1)
  end

  @migration_version 20_990_101_120_000

  test "V02 rolls back to V01 and reapplies with an existing connection row intact" do
    provider = Factory.create_github_provider("_roundtrip")
    tenant_id = Factory.tenant_id("migration_roundtrip")
    conn = Factory.create_github_connection(provider, tenant_id, "_roundtrip")

    assert migrated_version_comment() == "Tango version=2"

    # Register the wrapper migration as applied: the schema already sits at
    # V02, so this runs no DDL, but Migrator.down only rolls back a migration
    # it has recorded.
    assert :ok =
             Migrator.up(Repo, @migration_version, UpgradeTangoV2,
               log: false,
               migration_lock: false
             )

    # V02 -> V01: the rejection-counter columns go away, nothing else does.
    assert :ok =
             Migrator.down(Repo, @migration_version, UpgradeTangoV2,
               log: false,
               migration_lock: false
             )

    assert migrated_version_comment() == "Tango version=1"
    refute column_exists?("auth_failures")
    refute column_exists?("last_auth_failure")

    # Raw SQL: the V02 schema struct would SELECT the dropped columns.
    %{rows: [[fetched_tenant]]} =
      Repo.query!("SELECT tenant_id FROM tango_connections WHERE id = $1", [conn.id])

    assert fetched_tenant == tenant_id

    # V01 -> V02: columns return with their defaults on the existing row.
    assert :ok =
             Migrator.up(Repo, @migration_version, UpgradeTangoV2,
               log: false,
               migration_lock: false
             )

    assert migrated_version_comment() == "Tango version=2"
    assert column_exists?("auth_failures")
    assert column_exists?("last_auth_failure")

    reloaded = Repo.get(Connection, conn.id)
    assert reloaded.auth_failures == 0
    assert reloaded.last_auth_failure == nil
  end

  # `Tango.Migration.migrated_version/0` reads through the migration runner's
  # `repo/0`, which is nil in a test process, so the EctoEvolver tracking
  # marker — the comment on tango_providers — is read directly.
  defp migrated_version_comment do
    %{rows: [[comment]]} =
      Repo.query!("SELECT obj_description('public.tango_providers'::regclass, 'pg_class')")

    comment
  end

  defp column_exists?(column) do
    %{rows: [[count]]} =
      Repo.query!(
        """
        SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'tango_connections'
          AND column_name = $1
        """,
        [column]
      )

    count == 1
  end
end

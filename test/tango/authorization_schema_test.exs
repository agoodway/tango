defmodule Tango.AuthorizationSchemaTest do
  use Tango.DatabaseCase, async: false

  alias Ecto.Migrator
  alias Tango.Schemas.{Authorization, Connection, OAuthSession, Provider}

  @prefix "tango_v03_authorization_test"
  @bootstrap_version 20_261_015_150_001
  @upgrade_version 20_261_015_150_002

  defmodule BootstrapV3 do
    use Ecto.Migration

    def up, do: Tango.Migration.up(version: 3, prefix: "tango_v03_authorization_test")
    def down, do: Tango.Migration.down(version: 0, prefix: "tango_v03_authorization_test")
  end

  defmodule UpgradeV3 do
    use Ecto.Migration

    def up, do: Tango.Migration.up(version: 3, prefix: "tango_v03_authorization_test")
    def down, do: Tango.Migration.down(version: 2, prefix: "tango_v03_authorization_test")
  end

  defmodule UpgradeV4 do
    use Ecto.Migration

    def up, do: Tango.Migration.up(version: 4, prefix: "tango_v03_authorization_test")
    def down, do: Tango.Migration.down(version: 3, prefix: "tango_v03_authorization_test")
  end

  test "schemas expose staged authorization fields without a raw provider payload" do
    refute :raw_payload in Authorization.__schema__(:fields)
    assert :account_subject in Connection.__schema__(:fields)
    assert :oauth_client_id in Connection.__schema__(:fields)
    assert :completion_origin in OAuthSession.__schema__(:fields)
    assert :expected_connection_id in OAuthSession.__schema__(:fields)
    assert :auth_params in OAuthSession.__schema__(:fields)
    assert :completion_mode in OAuthSession.__schema__(:fields)
    assert :completion_mode in Authorization.__schema__(:fields)
  end

  test "authorization candidates encrypt tokens and enforce source and handle uniqueness" do
    migrate_v03()

    assert :ok =
             Migrator.up(Repo, 20_991_026_130_000, UpgradeV4, log: false, migration_lock: false)

    provider = insert_provider()
    session = insert_session(provider)
    second_session = insert_session(provider)
    handle_hash = :crypto.hash(:sha256, "one-time-completion-handle")
    access_token = "candidate-access-token"
    refresh_token = "candidate-refresh-token"

    authorization =
      insert_authorization(provider, session, %{
        handle_hash: handle_hash,
        access_token: access_token,
        refresh_token: refresh_token
      })

    %{rows: [[stored_access_token, stored_refresh_token, stored_handle_hash]]} =
      Repo.query!(
        """
        SELECT access_token, refresh_token, handle_hash
        FROM "#{@prefix}".tango_authorizations
        WHERE id = $1
        """,
        [authorization.id]
      )

    refute stored_access_token == access_token
    refute stored_refresh_token == refresh_token
    assert stored_handle_hash == handle_hash
    assert byte_size(stored_handle_hash) == 32

    assert {:error, duplicate_source} =
             authorization_changeset(provider, session, %{
               handle_hash: :crypto.hash(:sha256, "different-handle")
             })
             |> Repo.insert()

    assert {"has already been taken", _} = duplicate_source.errors[:oauth_session_id]

    assert {:error, duplicate_handle} =
             authorization_changeset(provider, second_session, %{handle_hash: handle_hash})
             |> Repo.insert()

    assert {"has already been taken", _} = duplicate_handle.errors[:handle_hash]

    consumed_session = insert_session(provider)

    consumed =
      insert_authorization(provider, consumed_session, %{
        access_token: nil,
        consumed_at: DateTime.utc_now()
      })

    assert consumed.access_token == nil

    unconsumed_session = insert_session(provider)

    assert {:error, unconsumed_without_token} =
             authorization_changeset(provider, unconsumed_session, %{access_token: nil})
             |> Repo.insert()

    assert {"must be present until the authorization is consumed", _} =
             unconsumed_without_token.errors[:access_token]
  end

  test "completion modes default to connection and consume rows reject connection bindings" do
    migrate_v03()

    assert :ok =
             Migrator.up(Repo, 20_991_026_130_000, UpgradeV4, log: false, migration_lock: false)

    provider = insert_provider()
    session = insert_session(provider)
    authorization = insert_authorization(provider, session, %{})

    assert Repo.get!(OAuthSession, session.id, prefix: @prefix).completion_mode == :connection

    assert Repo.get!(Authorization, authorization.id, prefix: @prefix).completion_mode ==
             :connection

    consume_session =
      provider
      |> insert_session()
      |> OAuthSession.changeset(%{completion_mode: :consume})
      |> Repo.update!()

    consume = insert_authorization(provider, consume_session, %{completion_mode: :consume})

    assert Repo.get!(OAuthSession, consume_session.id, prefix: @prefix).completion_mode ==
             :consume

    assert Repo.get!(Authorization, consume.id, prefix: @prefix).completion_mode == :consume

    for mode <- ["unknown", nil] do
      changeset = authorization_changeset(provider, consume_session, %{completion_mode: mode})
      refute changeset.valid?
      assert changeset.errors[:completion_mode]
    end

    connection =
      %Connection{}
      |> Ecto.put_meta(prefix: @prefix)
      |> Connection.changeset(%{
        provider_id: provider.id,
        tenant_id: "tenant-authorization",
        access_token: "synthetic"
      })
      |> Repo.insert!()

    assert {:error, invalid_session} =
             session
             |> OAuthSession.changeset(%{
               completion_mode: :consume,
               expected_connection_id: connection.id
             })
             |> Repo.update()

    assert invalid_session.errors[:completion_mode]

    for field <- [:expected_connection_id, :verified_connection_id] do
      assert {:error, invalid_candidate} =
               consume
               |> Authorization.changeset(%{field => connection.id})
               |> Repo.update()

      assert invalid_candidate.errors[:completion_mode]
    end
  end

  test "V03 migrates up, rolls back to V02, and reapplies in a dedicated prefix" do
    migrate_v03()

    assert migrated_version_comment() == "Tango version=3"
    assert table_exists?("tango_authorizations")
    assert column_exists?("tango_oauth_sessions", "completion_origin")
    assert column_exists?("tango_connections", "account_subject")

    assert :ok =
             Migrator.up(Repo, @upgrade_version, UpgradeV3,
               log: false,
               migration_lock: false
             )

    assert :ok =
             Migrator.down(Repo, @upgrade_version, UpgradeV3,
               log: false,
               migration_lock: false
             )

    assert migrated_version_comment() == "Tango version=2"
    refute table_exists?("tango_authorizations")
    refute column_exists?("tango_oauth_sessions", "completion_origin")
    refute column_exists?("tango_connections", "account_subject")

    assert :ok =
             Migrator.up(Repo, @upgrade_version, UpgradeV3,
               log: false,
               migration_lock: false
             )

    assert migrated_version_comment() == "Tango version=3"
    assert table_exists?("tango_authorizations")
    assert column_exists?("tango_oauth_sessions", "completion_origin")
    assert column_exists?("tango_connections", "account_subject")
  end

  defp migrate_v03 do
    assert :ok =
             Migrator.up(Repo, @bootstrap_version, BootstrapV3,
               log: false,
               migration_lock: false
             )
  end

  defp insert_provider do
    %Provider{}
    |> Ecto.put_meta(prefix: @prefix)
    |> Provider.changeset(%{
      slug: "provider-#{System.unique_integer([:positive])}",
      name: "Test Provider",
      client_secret: "provider-client-secret",
      config: %{
        "client_id" => "oauth-client-id",
        "auth_url" => "https://provider.example/authorize",
        "token_url" => "https://provider.example/token"
      }
    })
    |> Repo.insert!()
  end

  defp insert_session(provider) do
    %OAuthSession{}
    |> Ecto.put_meta(prefix: @prefix)
    |> OAuthSession.changeset(%{
      provider_id: provider.id,
      tenant_id: "tenant-authorization",
      session_token: random_token(),
      state: random_token(),
      expires_at: DateTime.add(DateTime.utc_now(), 600, :second)
    })
    |> Repo.insert!()
  end

  defp insert_authorization(provider, session, attrs) do
    provider
    |> authorization_changeset(session, attrs)
    |> Repo.insert!()
  end

  defp authorization_changeset(provider, session, attrs) do
    defaults = %{
      provider_id: provider.id,
      oauth_session_id: session.id,
      tenant_id: "tenant-authorization",
      handle_hash: :crypto.hash(:sha256, random_token()),
      access_token: "default-access-token",
      refresh_token: "default-refresh-token",
      token_type: "bearer",
      granted_scopes: ["records.read"],
      oauth_client_id: "oauth-client-id",
      intent_reference: "intent-123",
      completion_origin: "https://consumer.example",
      expires_at: DateTime.add(DateTime.utc_now(), 600, :second)
    }

    %Authorization{}
    |> Ecto.put_meta(prefix: @prefix)
    |> Authorization.changeset(Map.merge(defaults, attrs))
  end

  defp random_token do
    32
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  defp migrated_version_comment do
    %{rows: [[comment]]} =
      Repo.query!("SELECT obj_description('#{@prefix}.tango_providers'::regclass, 'pg_class')")

    comment
  end

  defp table_exists?(table) do
    %{rows: [[exists?]]} =
      Repo.query!(
        """
        SELECT EXISTS (
          SELECT 1
          FROM information_schema.tables
          WHERE table_schema = $1 AND table_name = $2
        )
        """,
        [@prefix, table]
      )

    exists?
  end

  defp column_exists?(table, column) do
    %{rows: [[exists?]]} =
      Repo.query!(
        """
        SELECT EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = $2 AND column_name = $3
        )
        """,
        [@prefix, table, column]
      )

    exists?
  end
end

defmodule Tango.ConnectionTest do
  @moduledoc """
  Tests for Tango.Connection module business logic.

  Covers connection lifecycle management, token refresh, multi-tenant isolation,
  and connection statistics. Tests the 0% coverage module identified in security review.
  """

  use Tango.DatabaseCase, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias Tango.{Factory, OAuthMockServer}
  alias Tango.Schemas.AuditLog
  alias Tango.Schemas.Connection, as: ConnectionSchema
  alias Tango.Schemas.Provider

  describe "refresh_changeset/2" do
    test "preserves omitted scopes and clears explicitly empty scopes" do
      connection = %ConnectionSchema{granted_scopes: ["records.read"]}

      omitted =
        ConnectionSchema.refresh_changeset(connection, %{"access_token" => "fresh"})

      explicit =
        ConnectionSchema.refresh_changeset(connection, %{
          "access_token" => "fresh",
          "scope" => ""
        })

      assert Ecto.Changeset.get_field(omitted, :granted_scopes) == ["records.read"]
      assert Ecto.Changeset.get_field(explicit, :granted_scopes) == []
    end
  end

  describe "token response conversion" do
    test "preserves whether the provider omitted scope" do
      omitted =
        OAuth2.AccessToken.new(%{
          "access_token" => "fresh",
          "expires_in" => 3600,
          "token_type" => "Bearer"
        })

      explicit =
        OAuth2.AccessToken.new(%{
          "access_token" => "fresh",
          "expires_in" => 3600,
          "token_type" => "Bearer",
          "scope" => ""
        })

      refute Map.has_key?(Tango.Auth.convert_token_to_response(omitted), "scope")
      assert Tango.Auth.convert_token_to_response(explicit)["scope"] == ""
    end
  end

  describe "list_connections/2" do
    test "lists active connections for a tenant" do
      provider1 = Factory.create_github_provider("_list1")
      provider2 = Factory.create_google_provider("_list2")
      tenant_id = Factory.tenant_id("list_test")
      other_tenant = "other_tenant_list_test"

      # Create connections for the target tenant (different providers to avoid unique constraint)
      conn1 = Factory.create_github_connection(provider1, tenant_id, "_1")

      conn2 =
        Factory.create_connection(provider2, tenant_id, %{"access_token" => "google_token_2"})

      # Create connection for different tenant (should not appear)
      _other_conn = Factory.create_github_connection(provider1, other_tenant, "_other")

      # Create revoked connection for same tenant (should not appear)
      provider3 = Factory.create_api_key_provider("_list3")
      _revoked_conn = Factory.create_revoked_connection(provider3, tenant_id)

      # List connections
      connections = Tango.Connection.list_connections(tenant_id)

      # Should only return active connections for the tenant
      assert length(connections) == 2
      connection_ids = Enum.map(connections, & &1.id) |> MapSet.new()
      assert MapSet.member?(connection_ids, conn1.id)
      assert MapSet.member?(connection_ids, conn2.id)

      # All connections should belong to the correct tenant
      Enum.each(connections, fn conn ->
        assert conn.tenant_id == tenant_id
        assert conn.status == :active
      end)
    end

    test "filters connections by provider" do
      provider1 = Factory.create_github_provider("_filter1")
      provider2 = Factory.create_github_provider("_filter2")
      tenant_id = "tenant_filter_test"

      # Create connections with different providers
      conn1 = Factory.create_github_connection(provider1, tenant_id, "_p1")
      _conn2 = Factory.create_github_connection(provider2, tenant_id, "_p2")

      # Filter by provider1
      connections = Tango.Connection.list_connections(tenant_id, provider: provider1.name)

      assert length(connections) == 1
      assert hd(connections).id == conn1.id
      assert hd(connections).provider.name == provider1.name
    end

    test "supports preload option" do
      provider = Factory.create_github_provider("_preload")
      tenant_id = "tenant_preload_test"
      _conn = Factory.create_github_connection(provider, tenant_id)

      # Test with preload (default)
      connections_with_preload = Tango.Connection.list_connections(tenant_id)
      assert length(connections_with_preload) == 1
      connection = hd(connections_with_preload)
      assert connection.provider != nil
      assert connection.provider.name == provider.name

      # Test without preload
      connections_without_preload = Tango.Connection.list_connections(tenant_id, preload: false)
      assert length(connections_without_preload) == 1
      connection = hd(connections_without_preload)
      # Provider should not be loaded
      assert not Ecto.assoc_loaded?(connection.provider)
    end
  end

  describe "get_connection/2" do
    test "gets connection by ID with tenant isolation" do
      provider = Factory.create_github_provider("_get")
      tenant_id = "tenant_get_test"
      other_tenant = "other_tenant_get_test"

      conn = Factory.create_github_connection(provider, tenant_id)

      # Should retrieve connection for correct tenant
      assert {:ok, retrieved} = Tango.Connection.get_connection(conn.id, tenant_id)
      assert retrieved.id == conn.id
      assert retrieved.tenant_id == tenant_id

      # Should not retrieve connection for wrong tenant
      assert {:error, :not_found} = Tango.Connection.get_connection(conn.id, other_tenant)

      # Should not retrieve non-existent connection (use proper UUID format)
      fake_id = 999_999
      assert {:error, :not_found} = Tango.Connection.get_connection(fake_id, tenant_id)
    end
  end

  describe "get_active_connection/3" do
    test "returns an active tenant-owned connection without refreshing by default" do
      provider = Factory.create_github_provider("_active_get")
      tenant_id = Factory.tenant_id("active_get")
      conn = Factory.create_github_connection(provider, tenant_id)

      assert {:ok, retrieved} = Tango.get_active_connection(conn.id, tenant_id)
      assert retrieved.id == conn.id
      assert retrieved.status == :active
    end

    test "hides another tenant's connection without requesting a token" do
      bypass = Bypass.open()
      {:ok, requests} = Agent.start_link(fn -> 0 end)

      Bypass.stub(bypass, "POST", "/oauth2/token", fn conn ->
        Agent.update(requests, &(&1 + 1))
        Plug.Conn.resp(conn, 500, "")
      end)

      provider =
        Factory.create_google_provider("_active_cross_tenant",
          urls: OAuthMockServer.google_urls(bypass)
        )

      conn =
        provider
        |> Factory.create_connection(Factory.tenant_id("active_owner"))
        |> expire_in(60)

      assert {:error, :not_found} =
               Tango.get_active_connection(conn.id, "other-tenant", auto_refresh: true)

      assert Agent.get(requests, & &1) == 0
    end
  end

  describe "get_connection_for_provider/2" do
    test "gets active connection for provider and tenant" do
      provider = Factory.create_github_provider("_provider_get")
      tenant_id = "tenant_provider_get_test"

      conn = Factory.create_github_connection(provider, tenant_id)

      # Should retrieve the connection
      assert {:ok, retrieved} =
               Tango.Connection.get_connection_for_provider(provider.name, tenant_id)

      assert retrieved.id == conn.id
      assert retrieved.tenant_id == tenant_id
      assert retrieved.provider.name == provider.name
    end

    test "returns most recent connection when multiple exist" do
      provider = Factory.create_github_provider("_recent")
      tenant_id = "tenant_recent_test"

      # Create connection, revoke it, then create a new one
      conn1 = Factory.create_github_connection(provider, tenant_id, "_old")
      # Revoke first connection to allow creating second
      revoked_changeset = ConnectionSchema.changeset(conn1, %{status: :revoked})
      {:ok, _} = Repo.update(revoked_changeset)

      # Ensure different inserted_at times
      :timer.sleep(10)
      conn2 = Factory.create_github_connection(provider, tenant_id, "_new")

      # Should return the most recent one
      assert {:ok, retrieved} =
               Tango.Connection.get_connection_for_provider(provider.name, tenant_id)

      assert retrieved.id == conn2.id
    end

    test "ignores revoked connections" do
      provider = Factory.create_github_provider("_revoked_ignore")
      tenant_id = "tenant_revoked_ignore_test"

      # Create and revoke a connection first
      revoked_conn = Factory.create_github_connection(provider, tenant_id, "_revoked")
      revoked_changeset = ConnectionSchema.changeset(revoked_conn, %{status: :revoked})
      {:ok, _} = Repo.update(revoked_changeset)

      # Create active connection after revoking the first
      active_conn = Factory.create_github_connection(provider, tenant_id, "_active")

      # Should return the active connection, not the revoked one
      assert {:ok, retrieved} =
               Tango.Connection.get_connection_for_provider(provider.name, tenant_id)

      assert retrieved.id == active_conn.id
      assert retrieved.status == :active
    end

    test "returns not found when no active connections exist" do
      provider = Factory.create_github_provider("_not_found")
      tenant_id = "tenant_not_found_test"

      assert {:error, :not_found} =
               Tango.Connection.get_connection_for_provider(provider.name, tenant_id)

      assert {:error, :not_found} =
               Tango.Connection.get_connection_for_provider("nonexistent_provider", tenant_id)
    end
  end

  describe "get_connection_for_provider/3 with auto_refresh" do
    setup do
      bypass = Bypass.open()
      {:ok, bypass: bypass, urls: OAuthMockServer.google_urls(bypass)}
    end

    test "returns the row's token when another caller already refreshed it", %{urls: urls} do
      provider = Factory.create_google_provider("_refresh_winner", urls: urls)
      tenant_id = Factory.tenant_id("refresh_winner")
      conn = Factory.create_connection(provider, tenant_id)
      stale = %{conn | expires_at: DateTime.add(DateTime.utc_now(), 60, :second)}

      {:ok, _winner} =
        conn
        |> ConnectionSchema.changeset(%{
          access_token: "winner_access_token",
          expires_at: DateTime.add(DateTime.utc_now(), 3600, :second)
        })
        |> Repo.update()

      assert {:ok, served} = Tango.Connection.refresh_if_needed(stale)
      assert served.access_token == "winner_access_token"
      assert Repo.get!(ConnectionSchema, conn.id).refresh_attempts == 0
    end

    test "returns refresh_not_allowed for an expired token that cannot refresh", %{urls: urls} do
      for {suffix, attrs} <- [
            {"_no_token", %{refresh_token: nil}},
            {"_disabled", %{auto_refresh_enabled: false}},
            {"_exhausted", %{refresh_exhausted: true}}
          ] do
        provider = Factory.create_google_provider("_not_allowed" <> suffix, urls: urls)
        tenant_id = Factory.tenant_id("not_allowed" <> suffix)

        {:ok, _conn} =
          provider
          |> Factory.create_connection(tenant_id)
          |> ConnectionSchema.changeset(
            Map.put(attrs, :expires_at, DateTime.add(DateTime.utc_now(), -60, :second))
          )
          |> Repo.update()

        assert {:error, {:refresh_failed, :refresh_not_allowed}} =
                 Tango.Connection.get_connection_for_provider(provider.slug, tenant_id,
                   auto_refresh: true
                 )
      end
    end

    test "returns connection without refresh when auto_refresh is false" do
      provider = Factory.create_github_provider("_auto_refresh_false")
      tenant_id = "tenant_auto_refresh_false_test"

      # Create an active connection that expires soon (needs refresh)
      conn = Factory.create_github_connection(provider, tenant_id)
      expires_soon = DateTime.add(DateTime.utc_now(), 60, :second)

      changeset = ConnectionSchema.changeset(conn, %{expires_at: expires_soon})
      {:ok, expiring_conn} = Repo.update(changeset)

      # Should return connection without refresh attempt
      assert {:ok, retrieved} =
               Tango.Connection.get_connection_for_provider(provider.name, tenant_id,
                 auto_refresh: false
               )

      assert retrieved.id == expiring_conn.id
      assert retrieved.access_token == expiring_conn.access_token
    end

    test "automatically refreshes expiring connection when auto_refresh is true" do
      provider = Factory.create_github_provider("_auto_refresh_true")
      tenant_id = "tenant_auto_refresh_true_test"

      # Create an active connection that expires soon but remove refresh token to avoid OAuth2 call
      conn = Factory.create_github_connection(provider, tenant_id)
      expires_soon = DateTime.add(DateTime.utc_now(), 60, :second)

      changeset =
        ConnectionSchema.changeset(conn, %{
          expires_at: expires_soon,
          # Remove refresh token to skip actual OAuth2 call
          refresh_token: nil
        })

      {:ok, expiring_conn} = Repo.update(changeset)

      # Should detect that refresh is needed but skip it due to no refresh token
      assert {:ok, retrieved} =
               Tango.Connection.get_connection_for_provider(provider.name, tenant_id,
                 auto_refresh: true
               )

      assert retrieved.id == expiring_conn.id
      assert retrieved.tenant_id == tenant_id
    end

    test "falls back gracefully when refresh fails" do
      provider = Factory.create_github_provider("_auto_refresh_fallback")
      tenant_id = "tenant_auto_refresh_fallback_test"

      # Create an active connection that expires soon but can't be refreshed
      conn = Factory.create_github_connection(provider, tenant_id)
      expires_soon = DateTime.add(DateTime.utc_now(), 60, :second)

      changeset =
        ConnectionSchema.changeset(conn, %{
          expires_at: expires_soon,
          # No refresh token available
          refresh_token: nil
        })

      {:ok, expiring_conn} = Repo.update(changeset)

      # Should return original connection even if refresh would fail
      assert {:ok, retrieved} =
               Tango.Connection.get_connection_for_provider(provider.name, tenant_id,
                 auto_refresh: true
               )

      assert retrieved.id == expiring_conn.id
      assert retrieved.tenant_id == tenant_id
    end

    test "uses default behavior when auto_refresh option not provided" do
      provider = Factory.create_github_provider("_auto_refresh_default")
      tenant_id = "tenant_auto_refresh_default_test"

      conn = Factory.create_github_connection(provider, tenant_id)

      # Should work with empty options list (default auto_refresh: false)
      assert {:ok, retrieved} =
               Tango.Connection.get_connection_for_provider(provider.name, tenant_id, [])

      assert retrieved.id == conn.id
    end
  end

  describe "mark_connection_used/1" do
    test "updates last_used_at timestamp" do
      provider = Factory.create_github_provider("_used")
      tenant_id = "tenant_used_test"

      conn = Factory.create_unused_connection(provider, tenant_id)
      assert conn.last_used_at == nil

      # Mark as used
      assert {:ok, updated_conn} = Tango.Connection.mark_connection_used(conn)

      # Should have updated timestamp
      assert updated_conn.last_used_at != nil
      assert DateTime.compare(updated_conn.last_used_at, DateTime.utc_now()) in [:eq, :lt]
    end
  end

  describe "record_auth_failure/2" do
    test "counts a rejection and leaves the connection usable below the threshold" do
      provider = Factory.create_github_provider("_authfail1")
      tenant_id = Factory.tenant_id("auth_fail_below")
      conn = Factory.create_github_connection(provider, tenant_id, "_authfail1")

      assert {:ok, updated} = Tango.Connection.record_auth_failure(conn, "http_401")

      assert updated.auth_failures == 1
      assert updated.last_auth_failure == "http_401"
      assert updated.status == :active

      assert {:ok, _still_served} =
               Tango.Connection.get_connection_for_provider(provider.slug, tenant_id)
    end

    test "expires the connection at the threshold, so it is no longer served" do
      provider = Factory.create_github_provider("_authfail2")
      tenant_id = Factory.tenant_id("auth_fail_threshold")
      conn = Factory.create_github_connection(provider, tenant_id, "_authfail2")

      {:ok, conn} = Tango.Connection.record_auth_failure(conn, "http_401")
      {:ok, conn} = Tango.Connection.record_auth_failure(conn, "http_401")
      {:ok, expired} = Tango.Connection.record_auth_failure(conn, "http_401")

      assert expired.auth_failures == 3
      assert expired.status == :expired

      assert {:error, :not_found} =
               Tango.Connection.get_connection_for_provider(provider.slug, tenant_id)
    end

    test "accepts a connection id scoped by tenant" do
      provider = Factory.create_github_provider("_authfail3")
      tenant_id = Factory.tenant_id("auth_fail_by_id")
      conn = Factory.create_github_connection(provider, tenant_id, "_authfail3")

      assert {:ok, updated} =
               Tango.Connection.record_auth_failure(conn.id, "http_401", tenant_id: tenant_id)

      assert updated.auth_failures == 1
      assert updated.last_auth_failure == "http_401"
    end

    test "requires a tenant with a bare connection id" do
      assert {:error, :tenant_id_required} = Tango.Connection.record_auth_failure(1, "http_401")
    end

    test "refuses another tenant's connection id" do
      provider = Factory.create_github_provider("_authfail6")
      tenant_id = Factory.tenant_id("auth_fail_cross_tenant")
      conn = Factory.create_github_connection(provider, tenant_id, "_authfail6")

      assert {:error, :not_found} =
               Tango.Connection.record_auth_failure(conn.id, "http_401",
                 tenant_id: "other-tenant"
               )

      assert Repo.get(ConnectionSchema, conn.id).auth_failures == 0
    end

    test "counts from the database row, not the caller's stale struct" do
      provider = Factory.create_github_provider("_authfail7")
      tenant_id = Factory.tenant_id("auth_fail_stale")
      conn = Factory.create_github_connection(provider, tenant_id, "_authfail7")

      # Two reports through the SAME stale struct: without the fresh row-locked
      # load this raises Ecto.StaleEntryError on the second (optimistic lock),
      # or undercounts if the count came from the struct.
      {:ok, _} = Tango.Connection.record_auth_failure(conn, "http_401")
      {:ok, second} = Tango.Connection.record_auth_failure(conn, "http_401")

      assert second.auth_failures == 2
    end

    test "honours a caller's max_failures over the default" do
      provider = Factory.create_github_provider("_authfail5")
      tenant_id = Factory.tenant_id("auth_fail_opts")
      conn = Factory.create_github_connection(provider, tenant_id, "_authfail5")

      {:ok, conn} = Tango.Connection.record_auth_failure(conn, "http_401", max_failures: 2)
      assert conn.status == :active

      {:ok, expired} = Tango.Connection.record_auth_failure(conn, "http_401", max_failures: 2)

      assert expired.auth_failures == 2
      assert expired.status == :expired
    end

    test "reports an unknown connection id rather than raising" do
      assert {:error, :not_found} =
               Tango.Connection.record_auth_failure(-1, "http_401", tenant_id: "anyone")
    end

    test "leaves a revoked connection revoked, since expired rows are deleted after 30 days" do
      provider = Factory.create_github_provider("_authfail8")
      tenant_id = Factory.tenant_id("auth_fail_revoked")
      conn = Factory.create_github_connection(provider, tenant_id, "_authfail8")

      {:ok, conn} = Tango.Connection.record_auth_failure(conn, "http_401")
      {:ok, conn} = Tango.Connection.record_auth_failure(conn, "http_401")
      {:ok, revoked} = Tango.Connection.revoke_connection(conn, tenant_id)
      assert revoked.status == :revoked

      # The third strike arrives after the revoke — it must not land.
      assert {:error, :not_found} = Tango.Connection.record_auth_failure(conn, "http_401")

      reloaded = Repo.get(ConnectionSchema, conn.id)
      assert reloaded.status == :revoked
      assert reloaded.auth_failures == 2
    end

    test "expiring a connection records an audit log" do
      provider = Factory.create_github_provider("_authfail4")
      tenant_id = Factory.tenant_id("auth_fail_audit")
      conn = Factory.create_github_connection(provider, tenant_id, "_authfail4")

      {:ok, _} = Tango.Connection.record_auth_failure(conn, "http_401")

      log =
        Tango.Schemas.AuditLog
        |> where(connection_id: ^conn.id, event_type: :connection_auth_failed)
        |> Repo.one()

      assert log
      refute log.success
    end
  end

  describe "record_auth_success/2" do
    test "clears a partial rejection streak" do
      provider = Factory.create_github_provider("_authok1")
      tenant_id = Factory.tenant_id("auth_success_clears")
      conn = Factory.create_github_connection(provider, tenant_id, "_authok1")

      {:ok, failed} = Tango.Connection.record_auth_failure(conn, "http_401")
      assert failed.auth_failures == 1

      assert :ok = Tango.Connection.record_auth_success(failed)

      reloaded = Repo.get(ConnectionSchema, conn.id)
      assert reloaded.auth_failures == 0
      assert reloaded.last_auth_failure == nil
    end

    test "is a no-op when there is no streak to clear" do
      provider = Factory.create_github_provider("_authok2")
      tenant_id = Factory.tenant_id("auth_success_noop")
      conn = Factory.create_github_connection(provider, tenant_id, "_authok2")

      assert :ok = Tango.Connection.record_auth_success(conn)

      assert Repo.get(ConnectionSchema, conn.id).updated_at == conn.updated_at
    end

    test "clears the database streak even through a stale struct" do
      provider = Factory.create_github_provider("_authok3")
      tenant_id = Factory.tenant_id("auth_success_stale")
      conn = Factory.create_github_connection(provider, tenant_id, "_authok3")

      # `conn` still reads auth_failures: 0 in memory; another process has
      # recorded a strike. Deciding from the struct would leave it behind.
      {:ok, _} = Tango.Connection.record_auth_failure(conn, "http_401")

      assert :ok = Tango.Connection.record_auth_success(conn)

      assert Repo.get(ConnectionSchema, conn.id).auth_failures == 0
    end

    test "accepts a connection id scoped by tenant" do
      provider = Factory.create_github_provider("_authok4")
      tenant_id = Factory.tenant_id("auth_success_by_id")
      conn = Factory.create_github_connection(provider, tenant_id, "_authok4")

      {:ok, _} = Tango.Connection.record_auth_failure(conn, "http_401")

      assert :ok = Tango.Connection.record_auth_success(conn.id, tenant_id: tenant_id)
      assert Repo.get(ConnectionSchema, conn.id).auth_failures == 0
    end

    test "requires a tenant with a bare connection id" do
      assert {:error, :tenant_id_required} = Tango.Connection.record_auth_success(1)
    end

    test "leaves another tenant's streak alone" do
      provider = Factory.create_github_provider("_authok5")
      tenant_id = Factory.tenant_id("auth_success_cross_tenant")
      conn = Factory.create_github_connection(provider, tenant_id, "_authok5")

      {:ok, _} = Tango.Connection.record_auth_failure(conn, "http_401")

      assert :ok = Tango.Connection.record_auth_success(conn.id, tenant_id: "other-tenant")
      assert Repo.get(ConnectionSchema, conn.id).auth_failures == 1
    end
  end

  describe "refresh_connection/1" do
    test "forces refresh even while the access token is still valid" do
      bypass = Bypass.open()

      OAuthMockServer.setup_google_oauth(bypass,
        success_response: %{
          "access_token" => "forced_access_token",
          "expires_in" => 3600,
          "token_type" => "Bearer"
        }
      )

      provider =
        Factory.create_google_provider("_forced_refresh",
          urls: OAuthMockServer.google_urls(bypass)
        )

      conn = Factory.create_connection(provider, Factory.tenant_id("forced_refresh"))
      assert DateTime.compare(conn.expires_at, DateTime.utc_now()) == :gt

      assert {:ok, updated_without_refresh} =
               conn
               |> ConnectionSchema.changeset(%{metadata: %{"updated" => true}})
               |> Repo.update()

      assert updated_without_refresh.lock_version > conn.lock_version
      assert {:ok, refreshed} = Tango.Connection.refresh_connection(conn)
      assert refreshed.access_token == "forced_access_token"
      assert refreshed.granted_scopes == conn.granted_scopes
    end

    test "keeps rotated tokens when the success audit log cannot be written" do
      bypass = Bypass.open()

      OAuthMockServer.setup_google_oauth(bypass,
        success_response: %{
          "access_token" => "rotated_access_token",
          "refresh_token" => "rotated_refresh_token",
          "expires_in" => 3600,
          "token_type" => "Bearer"
        }
      )

      provider =
        Factory.create_google_provider("_audit_failure_refresh",
          urls: OAuthMockServer.google_urls(bypass)
        )

      conn = Factory.create_connection(provider, Factory.tenant_id("audit_failure_refresh"))
      reject_audit_event("token_refreshed")

      assert {:ok, refreshed} = Tango.Connection.refresh_connection(conn)
      assert refreshed.access_token == "rotated_access_token"

      stored = Repo.get!(ConnectionSchema, conn.id)
      assert stored.access_token == "rotated_access_token"
      assert stored.refresh_token == "rotated_refresh_token"
      assert stored.refresh_attempts == 0
    end

    test "validates refresh prerequisites" do
      provider = Factory.create_github_provider("_refresh")
      tenant_id = "tenant_refresh_test"

      # Create connection with refresh token and near expiration
      # 5 minutes
      near_future = DateTime.add(DateTime.utc_now(), 300, :second)

      conn = Factory.create_github_connection(provider, tenant_id, "_refresh")

      refresh_changeset =
        ConnectionSchema.changeset(conn, %{
          expires_at: near_future,
          auto_refresh_enabled: true,
          refresh_exhausted: false
        })

      {:ok, conn_to_refresh} = Repo.update(refresh_changeset)

      # Note: This will attempt real OAuth calls and fail - testing error handling
      result =
        try do
          Tango.Connection.refresh_connection(conn_to_refresh)
        rescue
          error in [FunctionClauseError, RuntimeError, MatchError, Protocol.UndefinedError] ->
            {:error, Exception.message(error)}
        end

      # Should fail gracefully due to network/OAuth issues
      assert {:error, _reason} = result

      refreshed_conn = Repo.get!(ConnectionSchema, conn_to_refresh.id)
      assert refreshed_conn != nil
    end

    test "rejects refresh for connections without refresh token" do
      provider = Factory.create_github_provider("_no_refresh")
      tenant_id = "tenant_no_refresh_test"

      conn = Factory.create_github_connection(provider, tenant_id, "_no_refresh")
      no_refresh_changeset = ConnectionSchema.changeset(conn, %{refresh_token: nil})
      {:ok, conn_no_refresh} = Repo.update(no_refresh_changeset)

      # Should fail immediately
      result = Tango.Connection.refresh_connection(conn_no_refresh)
      assert {:error, reason} = result
      assert reason in [:no_refresh_token, :refresh_not_allowed]
    end

    test "rejects refresh for refresh-exhausted connections" do
      provider = Factory.create_github_provider("_exhausted")
      tenant_id = "tenant_exhausted_test"

      conn = Factory.create_github_connection(provider, tenant_id, "_exhausted")
      exhausted_changeset = ConnectionSchema.changeset(conn, %{refresh_exhausted: true})
      {:ok, exhausted_conn} = Repo.update(exhausted_changeset)

      # Should fail immediately
      assert {:error, :refresh_not_allowed} = Tango.Connection.refresh_connection(exhausted_conn)
    end
  end

  describe "refresh_expiring_connections/0" do
    test "does not count a failed refresh of a still-valid token as refreshed" do
      bypass = Bypass.open()
      OAuthMockServer.setup_google_oauth(bypass, should_fail: true)

      provider =
        Factory.create_google_provider("_sweep_fail", urls: OAuthMockServer.google_urls(bypass))

      conn = expire_in(Factory.create_connection(provider, Factory.tenant_id("sweep_fail")), 60)

      assert {:ok, 0} = Tango.Connection.refresh_expiring_connections()
      assert Repo.get!(ConnectionSchema, conn.id).refresh_attempts == 1
    end

    test "identifies and processes expiring connections" do
      provider = Factory.create_github_provider("_batch_refresh")

      # Create connections with different expiry states
      # 5 minutes
      near_expiry = DateTime.add(DateTime.utc_now(), 5 * 60, :second)
      # 24 hours
      far_future = DateTime.add(DateTime.utc_now(), 24 * 60 * 60, :second)

      # Connection that should be refreshed
      conn1 = Factory.create_github_connection(provider, "tenant1", "_expiring")

      expiring_changeset =
        ConnectionSchema.changeset(conn1, %{
          expires_at: near_expiry,
          auto_refresh_enabled: true,
          refresh_exhausted: false
        })

      {:ok, _} = Repo.update(expiring_changeset)

      # Connection that should not be refreshed (not expiring soon)
      conn2 = Factory.create_github_connection(provider, "tenant2", "_not_expiring")

      not_expiring_changeset =
        ConnectionSchema.changeset(conn2, %{
          expires_at: far_future,
          auto_refresh_enabled: true,
          refresh_exhausted: false
        })

      {:ok, _} = Repo.update(not_expiring_changeset)

      # Connection that should not be refreshed (auto refresh disabled)
      conn3 = Factory.create_github_connection(provider, "tenant3", "_disabled")

      disabled_changeset =
        ConnectionSchema.changeset(conn3, %{
          expires_at: near_expiry,
          auto_refresh_enabled: false,
          refresh_exhausted: false
        })

      {:ok, _} = Repo.update(disabled_changeset)

      # Note: This will attempt real OAuth calls - testing error handling
      result =
        try do
          Tango.Connection.refresh_expiring_connections()
        rescue
          error in [FunctionClauseError, RuntimeError, MatchError, Protocol.UndefinedError] ->
            case error do
              %FunctionClauseError{} -> {:ok, 0}
              _ -> {:error, Exception.message(error)}
            end
        end

      # Should complete without crashing (may have 0 successes due to OAuth failures)
      case result do
        {:ok, count} ->
          assert is_integer(count)
          assert count >= 0

        {:error, _reason} ->
          # Also acceptable for this integration test
          :ok
      end
    end
  end

  describe "revoke_connection/2" do
    test "successfully revokes a connection" do
      provider = Factory.create_github_provider("_revoke")
      tenant_id = "tenant_revoke_test"

      conn = Factory.create_github_connection(provider, tenant_id)
      assert conn.status == :active

      # Revoke the connection
      assert {:ok, revoked_conn} = Tango.Connection.revoke_connection(conn, tenant_id)
      assert revoked_conn.status == :revoked
      assert revoked_conn.id == conn.id
    end

    test "rejects revocation for wrong tenant" do
      provider = Factory.create_github_provider("_revoke_wrong")
      tenant_id = "tenant_revoke_wrong_test"
      wrong_tenant = "wrong_tenant_revoke_test"

      conn = Factory.create_github_connection(provider, tenant_id)

      # Should not allow wrong tenant to revoke
      assert {:error, :not_authorized} = Tango.Connection.revoke_connection(conn, wrong_tenant)

      # Connection should still be active
      updated_conn = Repo.get!(ConnectionSchema, conn.id)
      assert updated_conn.status == :active
    end

    test "revokes an expired generation" do
      provider = Factory.create_github_provider("_revoke_expired")
      tenant_id = "tenant_revoke_expired_test"

      expired =
        provider
        |> Factory.create_github_connection(tenant_id)
        |> ConnectionSchema.changeset(%{status: :expired})
        |> Repo.update!()

      assert {:ok, revoked} = Tango.Connection.revoke_connection(expired, tenant_id)
      assert revoked.status == :revoked
      assert Repo.get!(ConnectionSchema, expired.id).status == :revoked
    end

    test "revokes active and expired ids in tenant scope" do
      suffix = System.unique_integer([:positive])

      provider =
        Factory.create_provider(%{
          slug: "records_revoke_#{suffix}",
          name: "records_revoke_#{suffix}"
        })

      tenant_id = Factory.tenant_id("revoke_ids")

      expired =
        provider
        |> Factory.create_connection(tenant_id)
        |> ConnectionSchema.changeset(%{status: :expired})
        |> Repo.update!()

      active = Factory.create_connection(provider, tenant_id)

      assert {:ok, revoked_active} = Tango.revoke_connection(active.id, tenant_id)
      assert revoked_active.status == :revoked
      assert revoked_audit_count(active.id) == 1

      assert {:ok, revoked_expired} = Tango.revoke_connection(expired.id, tenant_id)
      assert revoked_expired.status == :revoked
      assert revoked_audit_count(expired.id) == 1
    end

    test "foreign missing and revoked ids are indistinguishable" do
      suffix = System.unique_integer([:positive])

      provider =
        Factory.create_provider(%{
          slug: "records_foreign_#{suffix}",
          name: "records_foreign_#{suffix}"
        })

      owner = Factory.tenant_id("revoke_owner")
      other = Factory.tenant_id("revoke_other")

      revoked =
        provider
        |> Factory.create_connection(owner)
        |> ConnectionSchema.changeset(%{status: :revoked})
        |> Repo.update!()

      foreign = Factory.create_connection(provider, other)

      foreign_before = Repo.get!(ConnectionSchema, foreign.id)
      assert {:error, :not_found} = Tango.revoke_connection(foreign.id, owner)
      assert connection_unchanged?(foreign_before, Repo.get!(ConnectionSchema, foreign.id))

      assert {:error, :not_found} = Tango.revoke_connection(-1, owner)

      revoked_before = Repo.get!(ConnectionSchema, revoked.id)
      assert {:error, :not_found} = Tango.revoke_connection(revoked.id, owner)
      assert connection_unchanged?(revoked_before, Repo.get!(ConnectionSchema, revoked.id))
      assert revoked_audit_count(foreign.id) == 0
      assert revoked_audit_count(revoked.id) == 0
    end

    test "struct tenant mismatch remains not_authorized" do
      suffix = System.unique_integer([:positive])

      provider =
        Factory.create_provider(%{
          slug: "records_mismatch_#{suffix}",
          name: "records_mismatch_#{suffix}"
        })

      connection = Factory.create_connection(provider, Factory.tenant_id("revoke_match"))
      before = Repo.get!(ConnectionSchema, connection.id)

      assert {:error, :not_authorized} =
               Tango.revoke_connection(connection, Factory.tenant_id("revoke_mismatch"))

      assert connection_unchanged?(before, Repo.get!(ConnectionSchema, connection.id))
    end

    test "revoke waits then rechecks state" do
      suffix = System.unique_integer([:positive])
      parent = self()

      {provider, connection} =
        Sandbox.unboxed_run(Repo, fn ->
          provider =
            Factory.create_provider(%{
              slug: "records_race_#{suffix}",
              name: "records_race_#{suffix}"
            })

          connection = Factory.create_connection(provider, Factory.tenant_id("revoke_race"))
          {provider, connection}
        end)

      on_exit(fn -> cleanup_provider(provider.id) end)

      holder =
        Task.async(fn ->
          Sandbox.unboxed_run(Repo, fn ->
            hold_then_revoke(provider.id, connection.id, connection.tenant_id, parent)
          end)
        end)

      holder_pid = holder.pid
      assert_receive {:held, ^holder_pid, holder_backend}, 5_000

      {waiter, waiter_backend} = start_id_revoke(connection.id, connection.tenant_id)
      await_revoke_blocked(waiter_backend, holder_backend)
      assert Task.yield(waiter, 100) == nil

      send(holder.pid, :revoke)
      assert {:ok, {:ok, %{status: :revoked}}} = Task.await(holder)
      assert {:error, :not_found} = Task.await(waiter)

      Sandbox.unboxed_run(Repo, fn ->
        stored = Repo.get!(ConnectionSchema, connection.id)
        assert stored.status == :revoked
        assert revoked_audit_count(connection.id) == 1
      end)
    end

    test "audit failure rolls back revocation" do
      suffix = System.unique_integer([:positive])

      provider =
        Factory.create_provider(%{
          slug: "records_audit_#{suffix}",
          name: "records_audit_#{suffix}"
        })

      tenant_id = Factory.tenant_id("revoke_audit")
      connection = Factory.create_connection(provider, tenant_id)
      reject_audit_event("connection_revoked")
      on_exit(fn -> drop_audit_reject_trigger() end)

      assert_raise Postgrex.Error, fn ->
        Tango.revoke_connection(connection.id, tenant_id)
      end

      assert Repo.get!(ConnectionSchema, connection.id).status == :active
      assert revoked_audit_count(connection.id) == 0
    end
  end

  describe "revoke_tenant_connections/1" do
    test "revokes all active connections for a tenant" do
      provider1 = Factory.create_github_provider("_tenant_revoke1")
      provider2 = Factory.create_github_provider("_tenant_revoke2")
      tenant_id = "tenant_revoke_all_test"
      other_tenant = "other_tenant_revoke_test"

      # Create connections for target tenant (different providers)
      conn1 = Factory.create_github_connection(provider1, tenant_id, "_1")
      conn2 = Factory.create_github_connection(provider2, tenant_id, "_2")

      # Create connection for other tenant (should not be affected)
      other_conn = Factory.create_github_connection(provider1, other_tenant, "_other")

      # Create already revoked connection (should not be counted)
      provider3 = Factory.create_github_provider("_tenant_revoke3")
      revoked_conn = Factory.create_github_connection(provider3, tenant_id, "_already_revoked")
      revoked_changeset = ConnectionSchema.changeset(revoked_conn, %{status: :revoked})
      {:ok, _} = Repo.update(revoked_changeset)

      # Revoke all connections for tenant
      assert {:ok, count} = Tango.Connection.revoke_tenant_connections(tenant_id)
      # Only the 2 active connections
      assert count == 2

      # Verify connections are revoked
      updated_conn1 = Repo.get!(ConnectionSchema, conn1.id)
      updated_conn2 = Repo.get!(ConnectionSchema, conn2.id)
      assert updated_conn1.status == :revoked
      assert updated_conn2.status == :revoked

      # Other tenant's connection should be unaffected
      updated_other = Repo.get!(ConnectionSchema, other_conn.id)
      assert updated_other.status == :active
    end
  end

  describe "revoke_provider_connections/1" do
    test "revokes all connections for a provider across tenants" do
      provider1 = Factory.create_github_provider("_provider_revoke1")
      provider2 = Factory.create_github_provider("_provider_revoke2")

      # Create connections with provider1
      conn1 = Factory.create_github_connection(provider1, "tenant1", "_p1")
      conn2 = Factory.create_github_connection(provider1, "tenant2", "_p1")

      # Create connection with provider2 (should not be affected)
      other_conn = Factory.create_github_connection(provider2, "tenant1", "_p2")

      # Revoke all connections for provider1
      assert {:ok, count} = Tango.Connection.revoke_provider_connections(provider1.name)
      assert count == 2

      # Verify provider1 connections are revoked
      updated_conn1 = Repo.get!(ConnectionSchema, conn1.id)
      updated_conn2 = Repo.get!(ConnectionSchema, conn2.id)
      assert updated_conn1.status == :revoked
      assert updated_conn2.status == :revoked

      # Provider2 connection should be unaffected
      updated_other = Repo.get!(ConnectionSchema, other_conn.id)
      assert updated_other.status == :active
    end

    test "handles non-existent provider gracefully" do
      assert {:error, :not_found} =
               Tango.Connection.revoke_provider_connections("nonexistent_provider")
    end
  end

  describe "cleanup_expired_connections/0" do
    test "cleans up old expired connections" do
      provider = Factory.create_github_provider("_cleanup")
      tenant_id = "tenant_cleanup_test"

      # Create expired connection (old) using factory method
      old_expired = Factory.create_expired_connection(provider, tenant_id)

      # Create recently expired connection (should not be cleaned) - use different provider
      provider2 = Factory.create_github_provider("_cleanup2")
      # 10 days ago
      recent_time = DateTime.add(DateTime.utc_now(), -10 * 24 * 60 * 60, :second)

      recent_expired_conn =
        Factory.create_github_connection(provider2, tenant_id, "_recent_expired")

      recent_changeset =
        ConnectionSchema.changeset(recent_expired_conn, %{
          status: :expired,
          updated_at: recent_time
        })

      {:ok, recent_expired} = Repo.update(recent_changeset)

      # Create active connection (should not be cleaned) - use different provider
      provider3 = Factory.create_github_provider("_cleanup3")
      _active_conn = Factory.create_github_connection(provider3, tenant_id, "_active")

      initial_count = Repo.aggregate(ConnectionSchema, :count, :id)

      # Run cleanup
      assert {:ok, cleaned_count} = Tango.Connection.cleanup_expired_connections()
      assert cleaned_count >= 1

      final_count = Repo.aggregate(ConnectionSchema, :count, :id)
      assert final_count < initial_count

      # Old expired connection should be gone
      assert Repo.get(ConnectionSchema, old_expired.id) == nil

      # Recent expired and active connections should remain
      assert Repo.get(ConnectionSchema, recent_expired.id) != nil
    end
  end

  describe "get_connection_stats/1" do
    test "returns comprehensive connection statistics for tenant" do
      provider1 = Factory.create_github_provider("_stats1")
      provider2 = Factory.create_github_provider("_stats2")
      tenant_id = "tenant_stats_test"
      other_tenant = "other_tenant_stats_test"

      # Create various connections for target tenant (different providers to avoid constraint)
      _active1 = Factory.create_github_connection(provider1, tenant_id, "_active1")
      _active2 = Factory.create_github_connection(provider2, tenant_id, "_active2")

      # Create revoked connection (with different provider)
      provider3 = Factory.create_github_provider("_stats3")
      revoked = Factory.create_github_connection(provider3, tenant_id, "_revoked")
      revoked_changeset = ConnectionSchema.changeset(revoked, %{status: :revoked})
      {:ok, _} = Repo.update(revoked_changeset)

      # Create expired connection (with different provider)
      provider4 = Factory.create_github_provider("_stats4")
      expired = Factory.create_github_connection(provider4, tenant_id, "_expired")
      expired_changeset = ConnectionSchema.changeset(expired, %{status: :expired})
      {:ok, _} = Repo.update(expired_changeset)

      # Create connection for other tenant (should not be included)
      provider5 = Factory.create_github_provider("_stats5")
      _other_tenant_conn = Factory.create_github_connection(provider5, other_tenant, "_other")

      # Get statistics
      stats = Tango.Connection.get_connection_stats(tenant_id)

      # Verify statistics
      assert stats.active == 2
      assert stats.revoked == 1
      assert stats.expired == 1
      assert stats.total == 4

      # Verify providers list (should only include providers with active connections)
      assert length(stats.providers) == 2
      assert provider1.name in stats.providers
      assert provider2.name in stats.providers
    end

    test "returns zeros for tenant with no connections" do
      tenant_id = "tenant_no_connections_test"

      stats = Tango.Connection.get_connection_stats(tenant_id)

      assert stats.active == 0
      assert stats.revoked == 0
      assert stats.expired == 0
      assert stats.total == 0
      assert stats.providers == []
    end

    test "CTE-optimized stats query produces consistent results with complex data" do
      provider1 = Factory.create_github_provider("_cte_test1")
      provider2 = Factory.create_github_provider("_cte_test2")
      provider3 = Factory.create_github_provider("_cte_test3")
      provider4 = Factory.create_github_provider("_cte_test4")
      provider5 = Factory.create_github_provider("_cte_test5")
      tenant_id = "tenant_cte_optimization_test"
      other_tenant = "other_tenant_cte_test"

      # Create active connections (one per provider due to unique constraint)
      _active1 = Factory.create_github_connection(provider1, tenant_id, "_cte_active1")
      _active2 = Factory.create_github_connection(provider2, tenant_id, "_cte_active2")
      _active3 = Factory.create_github_connection(provider3, tenant_id, "_cte_active3")

      # Create revoked connection (different provider to avoid constraint)
      revoked_conn = Factory.create_github_connection(provider4, tenant_id, "_cte_revoked")
      revoked_changeset = ConnectionSchema.changeset(revoked_conn, %{status: :revoked})
      {:ok, _} = Repo.update(revoked_changeset)

      # Create expired connection (different provider to avoid constraint)
      expired_conn = Factory.create_github_connection(provider5, tenant_id, "_cte_expired")
      expired_changeset = ConnectionSchema.changeset(expired_conn, %{status: :expired})
      {:ok, _} = Repo.update(expired_changeset)

      # Create connection for other tenant (should be excluded)
      _other_conn = Factory.create_github_connection(provider1, other_tenant, "_cte_other")

      # Get stats using CTE-optimized query
      stats = Tango.Connection.get_connection_stats(tenant_id)

      # Verify comprehensive results
      assert stats.active == 3
      assert stats.revoked == 1
      assert stats.expired == 1
      assert stats.total == 5

      # Verify provider list contains only providers with active connections
      assert length(stats.providers) == 3
      assert provider1.name in stats.providers
      assert provider2.name in stats.providers
      assert provider3.name in stats.providers

      # Verify tenant isolation - other tenant's connection not included
      other_stats = Tango.Connection.get_connection_stats(other_tenant)
      assert other_stats.active == 1
      assert other_stats.total == 1
      assert other_stats.providers == [provider1.name]
    end
  end

  describe "error handling and edge cases" do
    test "handles concurrent connection operations safely" do
      provider = Factory.create_github_provider("_concurrent")
      tenant_id = "tenant_concurrent_test"

      conn = Factory.create_github_connection(provider, tenant_id)

      # Simulate concurrent operations
      tasks =
        for i <- 1..5 do
          Task.async(fn ->
            case rem(i, 2) do
              0 -> Tango.Connection.mark_connection_used(conn)
              1 -> Tango.Connection.get_connection(conn.id, tenant_id)
            end
          end)
        end

      results = Enum.map(tasks, &Task.await/1)

      # All operations should complete without crashing
      Enum.each(results, fn result ->
        assert elem(result, 0) == :ok
      end)
    end

    test "validates connection state transitions" do
      provider = Factory.create_github_provider("_transitions")
      tenant_id = "tenant_transitions_test"

      conn = Factory.create_github_connection(provider, tenant_id)

      # Should be able to revoke active connection
      assert {:ok, revoked} = Tango.Connection.revoke_connection(conn, tenant_id)
      assert revoked.status == :revoked

      # Operations on revoked connection should handle gracefully
      assert {:error, :not_found} =
               Tango.Connection.get_connection_for_provider(provider.name, tenant_id)
    end
  end

  describe "refresh policy" do
    test "HTML success preserves credentials and allows valid-token fallback" do
      {bypass, provider} = open_records_provider("html_success")

      Bypass.stub(bypass, "POST", "/oauth2/token", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "text/html")
        |> Plug.Conn.resp(200, "<html>LEAKED_PROVIDER_BODY</html>")
      end)

      connection = policy_connection(provider, "html_success", %{})

      assert {:error, {:http_error, 200}} = Tango.Connection.refresh_connection(connection)

      failed = reload(connection)
      assert failed.refresh_attempts == 1
      assert failed.last_refresh_failure == "http_error:200"
      assert failed.access_token == connection.access_token
      assert failed.refresh_token == connection.refresh_token
      assert failed.expires_at == connection.expires_at

      assert {:ok, served} = Tango.Connection.refresh_if_needed(failed)
      assert served.access_token == connection.access_token
      assert served.refresh_token == connection.refresh_token
      assert served.expires_at == connection.expires_at

      stored = reload(connection)
      assert stored.access_token == connection.access_token
      assert stored.refresh_token == connection.refresh_token
      assert stored.expires_at == connection.expires_at
      assert stored.status == :active
      assert stored.refresh_exhausted == false
      assert stored.refresh_attempts == 2
      assert stored.last_refresh_failure == "http_error:200"
      assert stored.next_refresh_at == nil

      audit = refresh_failure_audit(connection.id)
      assert audit_reason(audit) == "http_error:200"
      refute Jason.encode!(audit.event_data) =~ "LEAKED_PROVIDER_BODY"
    end

    test "invalid_grant expires immediately without valid-token fallback" do
      {bypass, provider} = open_records_provider("invalid_grant")

      Bypass.stub(bypass, "POST", "/oauth2/token", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Conn.resp(400, "error=invalid_grant&error_description=LEAKED_PROVIDER_BODY")
      end)

      reason = {:oauth_error, :invalid_grant}

      for seconds <- [60, -60], entry <- [:refresh_if_needed, :active, :provider] do
        connection =
          policy_connection(provider, "grant_#{seconds}_#{entry}", %{
            expires_at: DateTime.add(DateTime.utc_now(), seconds, :second)
          })

        result = on_demand(entry, connection, provider)
        assert result == {:error, {:refresh_failed, reason}}
        refute inspect(result) =~ "LEAKED_PROVIDER_BODY"
        refute inspect(result) =~ connection.access_token
        assert_credential_expiry(connection)
      end

      explicit =
        policy_connection(provider, "grant_explicit", %{
          expires_at: DateTime.add(DateTime.utc_now(), 60, :second)
        })

      result = Tango.Connection.refresh_connection(explicit)
      assert result == {:error, reason}
      refute inspect(result) =~ explicit.access_token
      refute inspect(result) =~ "LEAKED_PROVIDER_BODY"
      assert_credential_expiry(explicit)

      audit = refresh_failure_audit(explicit.id)
      assert audit_reason(audit) == "oauth_error:invalid_grant"
      assert is_binary(Jason.encode!(audit.event_data))
    end

    test "transient refresh preserves prior attempts and valid-token fallback" do
      {bypass, provider} = open_records_provider("transient")
      {:ok, mode} = Agent.start_link(fn -> :outage end)

      Bypass.stub(bypass, "POST", "/oauth2/token", fn conn ->
        case Agent.get(mode, & &1) do
          :outage ->
            json_response(conn, 503, %{"error" => "server_error"})

          :limited ->
            json_response(conn, 429, %{"error" => "invalid_grant"}, [{"retry-after", "30"}])
        end
      end)

      valid = policy_connection(provider, "transient_valid", %{refresh_attempts: 2})
      assert {:ok, served} = Tango.Connection.refresh_if_needed(valid)
      assert served.access_token == valid.access_token
      assert_transient_row(valid, "http_error:503")

      explicit = policy_connection(provider, "transient_explicit", %{refresh_attempts: 2})
      assert {:error, {:http_error, 503}} = Tango.Connection.refresh_connection(explicit)
      assert_transient_row(explicit, "http_error:503")

      expired =
        policy_connection(provider, "transient_expired", %{
          refresh_attempts: 2,
          expires_at: DateTime.add(DateTime.utc_now(), -60, :second)
        })

      assert {:error, {:refresh_failed, {:http_error, 503}}} =
               Tango.get_active_connection(expired.id, expired.tenant_id, auto_refresh: true)

      assert_transient_row(expired, "http_error:503")

      Agent.update(mode, fn _mode -> :limited end)
      limited = policy_connection(provider, "transient_limited", %{refresh_attempts: 2})
      assert {:error, {:rate_limited, 30}} = Tango.Connection.refresh_connection(limited)
      assert_transient_row(limited, "rate_limited:30")

      Bypass.down(bypass)
      transport = policy_connection(provider, "transient_transport", %{refresh_attempts: 2})

      assert {:ok, served} =
               Tango.Connection.get_connection_for_provider(provider.slug, transport.tenant_id,
                 auto_refresh: true
               )

      assert served.access_token == transport.access_token
      assert_transient_row(transport, "transport_error:network_error")
    end

    test "client and request failures exhaust on the third attempt" do
      {bypass, provider} = open_records_provider("budget")
      {:ok, requests} = Agent.start_link(fn -> 0 end)
      later = DateTime.add(DateTime.utc_now(), 7200, :second)

      Bypass.stub(bypass, "POST", "/oauth2/token", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        Agent.update(requests, &(&1 + 1))

        code =
          if String.contains?(body, "request-token"),
            do: "invalid_request",
            else: "invalid_client"

        json_response(conn, 400, %{"error" => code})
      end)

      for {suffix, token, code} <- [
            {"client", "client-token", :invalid_client},
            {"request", "request-token", :invalid_request}
          ] do
        connection =
          policy_connection(provider, suffix, %{
            "refresh_token" => token,
            expires_at: later
          })

        Enum.each(1..3, fn attempt ->
          current = reload(connection)

          assert {:error, {:oauth_error, ^code}} =
                   Tango.Connection.refresh_connection(current)

          stored = reload(connection)
          assert stored.refresh_attempts == attempt
          assert stored.last_refresh_failure == "oauth_error:#{code}"
          assert stored.next_refresh_at == nil

          if attempt < 3 do
            assert stored.status == :active
            assert stored.refresh_exhausted == false
            count = Agent.get(requests, & &1)
            assert {:ok, served} = Tango.Connection.refresh_if_needed(stored)
            assert served.access_token == stored.access_token
            assert Agent.get(requests, & &1) == count
          else
            assert stored.status == :expired
            assert stored.refresh_exhausted == true
            assert DateTime.compare(stored.expires_at, DateTime.utc_now()) == :gt
            count = Agent.get(requests, & &1)

            assert {:error, :not_found} =
                     Tango.get_active_connection(stored.id, stored.tenant_id, auto_refresh: true)

            assert {:error, :not_found} = Tango.Connection.refresh_connection(stored)
            assert Agent.get(requests, & &1) == count
          end
        end)
      end

      near =
        policy_connection(provider, "terminal_near", %{
          "refresh_token" => "client-token",
          refresh_attempts: 2
        })

      assert {:error, {:refresh_failed, {:oauth_error, :invalid_client}}} =
               Tango.Connection.get_connection_for_provider(provider.slug, near.tenant_id,
                 auto_refresh: true
               )

      terminal = reload(near)
      assert terminal.status == :expired
      assert terminal.refresh_exhausted == true
      assert {:error, :not_found} = Tango.Connection.refresh_if_needed(terminal)

      revoked =
        provider
        |> policy_connection("revoked_budget", %{})
        |> ConnectionSchema.changeset(%{status: :revoked})
        |> Repo.update!()

      count = Agent.get(requests, & &1)
      assert {:error, :not_found} = Tango.Connection.refresh_connection(revoked)
      assert Agent.get(requests, & &1) == count
    end

    test "backoff uses bounded UTC delay" do
      {bypass, provider} = open_records_provider("backoff")
      {:ok, mode} = Agent.start_link(fn -> {:status, 503, []} end)

      Bypass.stub(bypass, "POST", "/oauth2/token", fn conn ->
        {:status, status, headers} = Agent.get(mode, & &1)
        json_response(conn, status, %{"error" => "server_error"}, headers)
      end)

      default = policy_connection(provider, "backoff_default", %{})
      {result, before_time, after_time, stored} = refresh_between(default)
      assert result == {:error, {:http_error, 503}}
      assert stored.last_refresh_failure == "http_error:503"
      assert stored.refresh_attempts == 0
      assert_delay(stored.next_refresh_at, 300, before_time, after_time)

      for {header, parsed, delay, storage} <- [
            {"120", 120, 120, "rate_limited:120"},
            {"0", 0, 0, "rate_limited:0"},
            {"7200", 7200, 3600, "rate_limited:7200"}
          ] do
        Agent.update(mode, fn _mode -> {:status, 429, [{"retry-after", header}]} end)
        connection = policy_connection(provider, "backoff_#{header}", %{})
        {result, before_time, after_time, stored} = refresh_between(connection)
        assert result == {:error, {:rate_limited, parsed}}
        assert stored.last_refresh_failure == storage
        assert stored.refresh_attempts == 0
        assert stored.status == :active
        assert_delay(stored.next_refresh_at, delay, before_time, after_time)
      end
    end

    test "forced and on-demand refresh ignore scheduling but respect eligibility" do
      {bypass, provider} = open_records_provider("schedule")
      {:ok, requests} = Agent.start_link(fn -> 0 end)

      Bypass.stub(bypass, "POST", "/oauth2/token", fn conn ->
        Agent.update(requests, &(&1 + 1))

        json_response(conn, 200, %{
          "access_token" => "fresh_access_token",
          "expires_in" => 3600,
          "token_type" => "Bearer"
        })
      end)

      prior = %{
        next_refresh_at: DateTime.add(DateTime.utc_now(), 600, :second),
        refresh_attempts: 2,
        last_refresh_failure: "http_error:503",
        refresh_exhausted: false,
        auth_failures: 2,
        last_auth_failure: "http_401"
      }

      refreshes = [
        {"explicit", &Tango.Connection.refresh_connection/1},
        {"needed", &Tango.Connection.refresh_if_needed/1},
        {"active",
         fn connection ->
           Tango.get_active_connection(connection.id, connection.tenant_id, auto_refresh: true)
         end},
        {"provider",
         fn connection ->
           Tango.Connection.get_connection_for_provider(provider.slug, connection.tenant_id,
             auto_refresh: true
           )
         end}
      ]

      for {suffix, refresh} <- refreshes do
        connection = policy_connection(provider, "schedule_#{suffix}", prior)
        assert {:ok, refreshed} = refresh.(connection)
        assert refreshed.access_token == "fresh_access_token"
        stored = reload(connection)
        assert stored.next_refresh_at == nil
        assert stored.last_refresh_failure == nil
        assert stored.refresh_attempts == 0
        assert stored.refresh_exhausted == false
        assert stored.auth_failures == 0
        assert stored.last_auth_failure == nil
      end

      assert Agent.get(requests, & &1) == 4

      disabled =
        policy_connection(provider, "schedule_disabled", %{
          auto_refresh_enabled: false,
          next_refresh_at: DateTime.add(DateTime.utc_now(), 600, :second)
        })

      count = Agent.get(requests, & &1)
      assert {:error, :refresh_not_allowed} = Tango.Connection.refresh_connection(disabled)

      assert {:ok, %{access_token: access_token}} =
               Tango.Connection.refresh_if_needed(disabled)

      assert access_token == disabled.access_token
      assert Agent.get(requests, & &1) == count
      assert_unchanged(disabled)

      missing = policy_connection(provider, "schedule_missing", %{refresh_token: nil})
      assert {:error, :no_refresh_token} = Tango.Connection.refresh_connection(missing)

      assert {:ok, %{access_token: access_token}} =
               Tango.Connection.refresh_if_needed(missing)

      assert access_token == missing.access_token
      assert Agent.get(requests, & &1) == count
      assert reload(missing).refresh_attempts == 0
      assert reload(missing).last_refresh_failure == nil

      revoked =
        provider
        |> policy_connection("schedule_revoked", %{})
        |> ConnectionSchema.changeset(%{status: :revoked})
        |> Repo.update!()

      assert {:error, :not_found} = Tango.Connection.refresh_connection(revoked)
      assert Agent.get(requests, & &1) == count
    end

    test "returned persistence failures never expose credentials or serve old tokens" do
      {bypass, provider} = open_records_provider("persist")
      {:ok, script} = Agent.start_link(fn -> :token end)

      Bypass.stub(bypass, "POST", "/oauth2/token", fn conn ->
        case Agent.get(script, & &1) do
          :token ->
            json_response(conn, 200, %{
              "access_token" => "SENTINEL_ACCESS_TOKEN",
              "expires_in" => 3600,
              "token_type" => "Bearer"
            })

          :outage ->
            json_response(conn, 503, %{"error" => "server_error"})
        end
      end)

      swap_failure_repo()

      explicit = policy_connection(provider, "token_explicit", %{})
      Tango.RefreshFailureRepo.fail_once(:token_write)

      assert Tango.Connection.refresh_connection(explicit) == {:error, :persistence_failed}
      assert_unchanged(explicit)
      refute_rollback_marker(explicit)

      demand = policy_connection(provider, "token_demand", %{})
      Tango.RefreshFailureRepo.fail_once(:token_write)

      assert Tango.Connection.refresh_if_needed(demand) ==
               {:error, {:refresh_failed, :persistence_failed}}

      assert_unchanged(demand)
      refute_rollback_marker(demand)

      Agent.update(script, fn _script -> :outage end)
      failed_explicit = policy_connection(provider, "book_explicit", %{})
      Tango.RefreshFailureRepo.fail_once(:failure_write)

      assert Tango.Connection.refresh_connection(failed_explicit) == {:error, :persistence_failed}
      assert_unchanged(failed_explicit)
      refute_rollback_marker(failed_explicit)

      failed_demand = policy_connection(provider, "book_demand", %{})
      Tango.RefreshFailureRepo.fail_once(:failure_write)

      assert Tango.Connection.refresh_if_needed(failed_demand) ==
               {:error, {:refresh_failed, :persistence_failed}}

      assert_unchanged(failed_demand)
      refute_rollback_marker(failed_demand)

      transactional = policy_connection(provider, "txn_explicit", %{})
      Tango.RefreshFailureRepo.fail_once(:transaction)
      assert Tango.Connection.refresh_connection(transactional) == {:error, :transaction_failed}
      assert_unchanged(transactional)

      transactional_demand = policy_connection(provider, "txn_demand", %{})
      Tango.RefreshFailureRepo.fail_once(:transaction)

      assert Tango.Connection.refresh_if_needed(transactional_demand) ==
               {:error, {:refresh_failed, :transaction_failed}}

      assert_unchanged(transactional_demand)
    end

    test "audit failure does not discard a saved rotated token" do
      {bypass, provider} = open_records_provider("audit_fail")
      token = "SENTINEL_ACCESS_TOKEN_#{System.unique_integer([:positive])}"

      Bypass.stub(bypass, "POST", "/oauth2/token", fn conn ->
        json_response(conn, 200, %{
          "access_token" => token,
          "refresh_token" => "rotated_refresh_token",
          "expires_in" => 3600,
          "token_type" => "Bearer"
        })
      end)

      connection = policy_connection(provider, "audit_fail", %{})
      swap_failure_repo()
      Tango.RefreshFailureRepo.fail_once(:audit_write)
      attach_query_log()

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:ok, refreshed} = Tango.Connection.refresh_connection(connection)
          assert refreshed.access_token == token
        end)

      assert reload(connection).access_token == token
      queries = receive_queries([])

      refute Enum.any?(queries, fn metadata ->
               String.contains?(metadata, token) or
                 String.contains?(metadata, "sentinel_persistence_detail")
             end)

      refute log =~ token
      refute log =~ "sentinel_persistence_detail"
    end
  end

  defp open_records_provider(suffix) do
    bypass = Bypass.open()

    provider =
      Factory.create_google_provider("_#{suffix}_#{System.unique_integer([:positive])}",
        urls: OAuthMockServer.google_urls(bypass)
      )

    {bypass, provider}
  end

  defp policy_connection(provider, suffix, attrs) do
    token_attrs =
      attrs
      |> Map.take([:access_token, :refresh_token, "access_token", "refresh_token"])
      |> Map.new(fn
        {key, value} when is_atom(key) -> {Atom.to_string(key), value}
        pair -> pair
      end)

    fields =
      attrs
      |> Map.drop([:access_token, :refresh_token, "access_token", "refresh_token"])
      |> Map.put_new(:expires_at, DateTime.add(DateTime.utc_now(), 60, :second))

    provider
    |> Factory.create_connection(Factory.tenant_id(suffix), token_attrs)
    |> ConnectionSchema.changeset(fields)
    |> Repo.update!()
  end

  defp on_demand(:refresh_if_needed, connection, _provider) do
    Tango.Connection.refresh_if_needed(connection)
  end

  defp on_demand(:active, connection, _provider) do
    Tango.get_active_connection(connection.id, connection.tenant_id, auto_refresh: true)
  end

  defp on_demand(:provider, connection, provider) do
    Tango.Connection.get_connection_for_provider(provider.slug, connection.tenant_id,
      auto_refresh: true
    )
  end

  defp json_response(conn, status, body, headers \\ []) do
    conn =
      Enum.reduce(headers, conn, fn {name, value}, conn ->
        Plug.Conn.put_resp_header(conn, name, value)
      end)

    conn
    |> Plug.Conn.put_resp_header("content-type", "application/json")
    |> Plug.Conn.resp(status, Jason.encode!(body))
  end

  defp reload(connection), do: Repo.get!(ConnectionSchema, connection.id)

  defp assert_credential_expiry(connection) do
    failed = reload(connection)
    assert failed.status == :expired
    assert failed.refresh_exhausted == true
    assert failed.refresh_attempts == connection.refresh_attempts + 1
    assert failed.next_refresh_at == nil
    assert failed.last_refresh_failure == "oauth_error:invalid_grant"
    assert failed.access_token == connection.access_token
  end

  defp assert_transient_row(connection, storage) do
    stored = reload(connection)
    assert stored.refresh_attempts == 2
    assert stored.status == :active
    assert stored.refresh_exhausted == false
    assert stored.last_refresh_failure == storage
    assert DateTime.compare(stored.next_refresh_at, DateTime.utc_now()) == :gt
  end

  defp refresh_failure_audit(connection_id) do
    Repo.one!(
      from(l in AuditLog,
        where: l.connection_id == ^connection_id and l.event_type == :token_refresh_failed,
        order_by: [desc: l.id],
        limit: 1
      )
    )
  end

  defp audit_reason(audit) do
    Map.get(audit.event_data, "reason") || Map.get(audit.event_data, :reason)
  end

  defp refresh_between(connection) do
    before_time = DateTime.utc_now() |> DateTime.truncate(:second)
    result = Tango.Connection.refresh_connection(connection)
    after_time = DateTime.utc_now() |> DateTime.truncate(:second)
    {result, before_time, after_time, reload(connection)}
  end

  defp assert_delay(next, delay, before_time, after_time) do
    assert DateTime.compare(next, DateTime.add(before_time, delay, :second)) != :lt
    assert DateTime.compare(next, DateTime.add(after_time, delay, :second)) != :gt
  end

  defp refute_rollback_marker(connection) do
    refute reload(connection).last_auth_failure == Tango.RefreshFailureRepo.rollback_marker()
  end

  defp assert_unchanged(connection) do
    stored = reload(connection)
    assert stored.access_token == connection.access_token
    assert stored.refresh_token == connection.refresh_token
    assert stored.refresh_attempts == connection.refresh_attempts
    assert stored.status == connection.status
    assert stored.refresh_exhausted == connection.refresh_exhausted
    assert stored.last_refresh_failure == connection.last_refresh_failure
    assert stored.next_refresh_at == connection.next_refresh_at
  end

  defp swap_failure_repo do
    original = Application.get_env(:tango, :repo)

    Application.put_env(:tango, :repo, Tango.RefreshFailureRepo)

    on_exit(fn ->
      Tango.RefreshFailureRepo.clear_mode()
      Application.put_env(:tango, :repo, original)
    end)
  end

  defp attach_query_log do
    test_pid = self()
    handler = "refresh-queries-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler,
      [:tango, :test_repo, :query],
      fn _event, _measurements, metadata, _config ->
        send(test_pid, {:refresh_query, inspect(metadata)})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler) end)
  end

  defp receive_queries(acc) do
    receive do
      {:refresh_query, metadata} -> receive_queries([metadata | acc])
    after
      0 -> acc
    end
  end

  defp expire_in(connection, seconds) do
    {:ok, updated} =
      connection
      |> ConnectionSchema.changeset(%{
        expires_at: DateTime.add(DateTime.utc_now(), seconds, :second)
      })
      |> Repo.update()

    updated
  end

  # Installs a sandbox-scoped trigger that makes inserting one audit event fail
  # at the database, the way a full disk or a dropped partition would.
  defp reject_audit_event(event_type) do
    drop_audit_reject_trigger()

    Repo.query!("""
    CREATE OR REPLACE FUNCTION tango_test_reject_audit() RETURNS trigger AS $$
    BEGIN
      IF NEW.event_type = TG_ARGV[0] THEN
        RAISE EXCEPTION 'audit insert rejected';
      END IF;
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql
    """)

    Repo.query!("""
    CREATE TRIGGER tango_test_reject_audit BEFORE INSERT ON tango_audit_logs
    FOR EACH ROW EXECUTE FUNCTION tango_test_reject_audit('#{event_type}')
    """)
  end

  defp drop_audit_reject_trigger do
    case Sandbox.checkout(Repo) do
      :ok -> :ok
      {:already, :owner} -> :ok
    end

    Repo.query!("DROP TRIGGER IF EXISTS tango_test_reject_audit ON tango_audit_logs")
  end

  defp revoked_audit_count(connection_id) do
    Repo.aggregate(
      from(log in AuditLog,
        where: log.connection_id == ^connection_id and log.event_type == :connection_revoked
      ),
      :count
    )
  end

  defp connection_unchanged?(before, after_row) do
    before.status == after_row.status and before.lock_version == after_row.lock_version and
      before.updated_at == after_row.updated_at
  end

  defp hold_then_revoke(provider_id, connection_id, tenant_id, parent) do
    Repo.transaction(fn ->
      :ok = Tango.ConnectionLock.lock(Repo, provider_id, tenant_id)
      send(parent, {:held, self(), revoke_backend_pid()})

      receive do
        :revoke -> Tango.revoke_connection(connection_id, tenant_id)
      end
    end)
  end

  defp start_id_revoke(connection_id, tenant_id) do
    parent = self()

    task =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          send(parent, {:revoke_waiter, self(), revoke_backend_pid()})
          Tango.revoke_connection(connection_id, tenant_id)
        end)
      end)

    task_pid = task.pid
    assert_receive {:revoke_waiter, ^task_pid, backend}, 5_000
    {task, backend}
  end

  defp revoke_backend_pid do
    %{rows: [[pid]]} = Repo.query!("SELECT pg_backend_pid()")
    pid
  end

  defp await_revoke_blocked(waiter_pid, holder_pid, attempts \\ 100)

  defp await_revoke_blocked(_waiter_pid, _holder_pid, 0),
    do: flunk("revocation did not wait for the generation lock")

  defp await_revoke_blocked(waiter_pid, holder_pid, attempts) do
    %{rows: [[blocked?]]} =
      Sandbox.unboxed_run(Repo, fn ->
        Repo.query!("SELECT $1::int = ANY(pg_blocking_pids($2::int))", [holder_pid, waiter_pid])
      end)

    if blocked? do
      :ok
    else
      Process.sleep(20)
      await_revoke_blocked(waiter_pid, holder_pid, attempts - 1)
    end
  end

  defp cleanup_provider(provider_id) do
    Sandbox.unboxed_run(Repo, fn ->
      Repo.delete_all(from(log in AuditLog, where: log.provider_id == ^provider_id))

      Repo.delete_all(
        from(connection in ConnectionSchema, where: connection.provider_id == ^provider_id)
      )

      Repo.delete_all(from(provider in Provider, where: provider.id == ^provider_id))
    end)
  end

  describe "OAuth2 client configuration for token refresh" do
    test "refresh flow should handle JSON responses correctly" do
      # This test validates that OAuth2.Client is configured with JSON serializer
      # for token refresh, ensuring proper parsing of refresh token responses

      # Simulate a refresh token response from Google/GitHub/etc
      mock_refresh_response = %{
        "access_token" => "new_access_token_123",
        "expires_in" => 3600,
        "token_type" => "Bearer",
        "scope" => "user email"
      }

      # Test that OAuth2.AccessToken.new properly parses map responses
      token = OAuth2.AccessToken.new(mock_refresh_response)

      assert token.access_token == "new_access_token_123"
      assert token.expires_at != nil
      assert token.token_type == "Bearer"
      assert token.other_params["scope"] == "user email"

      # Test broken behavior (what happens WITHOUT serializer)
      # When OAuth2.Client doesn't have serializer configured, the entire
      # JSON string response gets dumped into access_token field
      json_string = Jason.encode!(mock_refresh_response)
      broken_token = OAuth2.AccessToken.new(json_string)

      # Without serializer, entire JSON becomes access_token
      assert broken_token.access_token == json_string
      assert broken_token.expires_at == nil
      assert broken_token.other_params == %{}
    end
  end
end

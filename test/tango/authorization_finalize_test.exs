defmodule Tango.AuthorizationFinalizeTest do
  use Tango.DatabaseCase, async: false

  alias Tango.Factory
  alias Tango.Schemas.{Authorization, Connection}

  setup do
    previous_origins = Application.get_env(:tango, :allowed_completion_origins)
    Application.put_env(:tango, :allowed_completion_origins, ["https://app.example.test"])

    on_exit(fn ->
      if previous_origins,
        do: Application.put_env(:tango, :allowed_completion_origins, previous_origins),
        else: Application.delete_env(:tango, :allowed_completion_origins)
    end)

    provider =
      Factory.create_provider(%{
        default_scopes: ["records.read"],
        config: %{
          "display_name" => "Finalize Test",
          "client_id" => "finalize-client",
          "auth_url" => "https://provider.example.test/authorize",
          "token_url" => "https://provider.example.test/token"
        }
      })

    %{provider: provider, tenant: Factory.tenant_id("finalize")}
  end

  test "consumer rollback restores the active generation and leaves the handle usable", ctx do
    existing = connection(ctx, scopes: ["records.read"])
    {handle, candidate} = candidate(ctx, existing: existing)
    opts = finalize_opts(ctx, candidate, existing.id)

    multi =
      Ecto.Multi.new()
      |> Tango.multi_finalize_authorization(:grant, handle, ctx.tenant, opts)
      |> Ecto.Multi.run(:consumer, fn _repo, _changes -> {:error, :consumer_rejected} end)

    assert {:error, :consumer, :consumer_rejected, _} = Repo.transaction(multi)
    assert Repo.get!(Connection, existing.id).status == :active
    refute Repo.get!(Authorization, candidate.id).consumed_at

    assert {:ok, %{grant: %{connection: replacement}}} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 handle,
                 ctx.tenant,
                 opts
               )
             )

    assert replacement.id != existing.id
    assert Repo.get!(Connection, existing.id).status == :revoked
  end

  test "generation is the connection id and replay is rejected", ctx do
    existing = connection(ctx)
    {handle, candidate} = candidate(ctx, existing: existing)
    opts = finalize_opts(ctx, candidate, existing.id)

    assert {:ok, %{grant: %{connection: replacement, authorization: summary}}} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 handle,
                 ctx.tenant,
                 opts
               )
             )

    assert summary == %{
             provider: ctx.provider.slug,
             subject: "subject-1",
             claims: %{"label" => "safe"},
             granted_scopes: ["records.read"],
             intent_reference: candidate.intent_reference
           }

    consumed = Repo.get!(Authorization, candidate.id)
    assert consumed.consumed_at
    assert consumed.access_token == nil
    assert consumed.refresh_token == nil
    assert replacement.refresh_token == "candidate-refresh"

    assert {:error, :grant, :completion_consumed, _} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 handle,
                 ctx.tenant,
                 opts
               )
             )
  end

  test "refresh token is inherited only for the same grant, subject, client, and provider", ctx do
    existing = connection(ctx, scopes: ["records.read", "records.write"])
    {handle, candidate} = candidate(ctx, existing: existing, refresh_token: nil)

    assert {:ok, %{grant: %{connection: replacement}}} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 handle,
                 ctx.tenant,
                 finalize_opts(ctx, candidate, existing.id)
               )
             )

    assert replacement.refresh_token == existing.refresh_token
  end

  test "refresh during consent keeps the same connection generation", ctx do
    existing = connection(ctx, scopes: ["records.read"])
    {handle, candidate} = candidate(ctx, existing: existing, refresh_token: nil)

    refreshed =
      existing
      |> Connection.refresh_changeset(%{
        "access_token" => "refreshed-during-consent",
        "refresh_token" => "rotated-refresh-token",
        "token_type" => "Bearer",
        "expires_in" => 3600,
        "scope" => "records.read"
      })
      |> Repo.update!()

    assert refreshed.id == existing.id
    assert refreshed.lock_version > existing.lock_version

    assert {:ok, %{grant: %{connection: replacement}}} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 handle,
                 ctx.tenant,
                 finalize_opts(ctx, candidate, existing.id)
               )
             )

    assert replacement.refresh_token == "rotated-refresh-token"
  end

  test "added scopes, unknown legacy client, and missing required API scope reject", ctx do
    for {existing_opts, candidate_opts, required_scopes, error} <- [
          {[scopes: ["records.read"]],
           [scopes: ["records.read", "records.write"], refresh_token: nil], ["records.read"],
           :refresh_token_required},
          {[oauth_client_id: nil], [refresh_token: nil], ["records.read"], :client_changed},
          {[], [scopes: ["offline_access"], refresh_token: "fresh"], ["records.read"],
           :missing_scopes}
        ] do
      tenant_ctx = %{ctx | tenant: Factory.tenant_id("finalize-case")}
      existing = connection(tenant_ctx, existing_opts)

      {handle, candidate} =
        candidate(tenant_ctx, Keyword.put(candidate_opts, :existing, existing))

      opts =
        finalize_opts(tenant_ctx, candidate, existing.id)
        |> Keyword.put(:required_scopes, required_scopes)

      assert {:error, :grant, ^error, _} =
               Repo.transaction(
                 Tango.multi_finalize_authorization(
                   Ecto.Multi.new(),
                   :grant,
                   handle,
                   tenant_ctx.tenant,
                   opts
                 )
               )
    end
  end

  test "optional refresh allows scope expansion without retaining an incompatible token", ctx do
    existing = connection(ctx, scopes: ["records.read"])

    {handle, candidate} =
      candidate(ctx,
        existing: existing,
        scopes: ["records.read", "records.write"],
        refresh_token: nil
      )

    opts =
      finalize_opts(ctx, candidate, existing.id)
      |> Keyword.put(:require_refresh_token, false)
      |> Keyword.put(:required_scopes, ["records.read", "records.write"])

    assert {:ok, %{grant: %{connection: replacement}}} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 handle,
                 ctx.tenant,
                 opts
               )
             )

    assert is_nil(replacement.refresh_token)
    assert replacement.granted_scopes == ["records.read", "records.write"]
  end

  test "legacy connections without client or subject metadata drop the old refresh token",
       ctx do
    for legacy_opts <- [[oauth_client_id: nil], [account_subject: nil]] do
      tenant_ctx = %{ctx | tenant: Factory.tenant_id("finalize-legacy")}

      existing =
        connection(tenant_ctx, Keyword.put(legacy_opts, :refresh_token, "legacy-refresh"))

      {handle, candidate} = candidate(tenant_ctx, existing: existing, refresh_token: nil)

      opts =
        finalize_opts(tenant_ctx, candidate, existing.id)
        |> Keyword.put(:require_refresh_token, false)

      assert {:ok, %{grant: %{connection: replacement}}} =
               Repo.transaction(
                 Tango.multi_finalize_authorization(
                   Ecto.Multi.new(),
                   :grant,
                   handle,
                   tenant_ctx.tenant,
                   opts
                 )
               )

      assert is_nil(replacement.refresh_token)
      assert Repo.get!(Connection, existing.id).status == :revoked
    end
  end

  test "legacy connections without client metadata reject when refresh is required", ctx do
    existing = connection(ctx, oauth_client_id: nil, refresh_token: "legacy-refresh")
    {handle, candidate} = candidate(ctx, existing: existing, refresh_token: nil)

    assert {:error, :grant, :client_changed, _} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 handle,
                 ctx.tenant,
                 finalize_opts(ctx, candidate, existing.id)
               )
             )

    assert Repo.get!(Connection, existing.id).status == :active
  end

  test "providers without refresh tokens can expand scopes when refresh is not required", ctx do
    existing =
      connection(ctx,
        scopes: ["records.read"],
        refresh_token: nil,
        oauth_client_id: nil,
        account_subject: nil
      )

    {handle, candidate} =
      candidate(ctx,
        existing: existing,
        scopes: ["records.read", "records.write"],
        refresh_token: nil
      )

    opts =
      finalize_opts(ctx, candidate, existing.id)
      |> Keyword.put(:require_refresh_token, false)
      |> Keyword.put(:required_scopes, ["records.read", "records.write"])

    assert {:ok, %{grant: %{connection: replacement}}} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 handle,
                 ctx.tenant,
                 opts
               )
             )

    assert is_nil(replacement.refresh_token)
    assert replacement.granted_scopes == ["records.read", "records.write"]
    assert Repo.get!(Connection, existing.id).status == :revoked
  end

  test "offline_access may be omitted when a candidate refresh token and API scopes exist", ctx do
    {handle, candidate} =
      candidate(ctx, scopes: ["records.read"], refresh_token: "candidate-refresh")

    opts =
      finalize_opts(ctx, candidate, nil)
      |> Keyword.put(:required_scopes, ["records.read"])

    assert {:ok, %{grant: %{connection: replacement}}} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 handle,
                 ctx.tenant,
                 opts
               )
             )

    assert replacement.granted_scopes == ["records.read"]
  end

  test "revoked expected generations and expired generations with a newer active reject", ctx do
    revoked = connection(ctx)
    {revoked_handle, revoked_candidate} = candidate(ctx, existing: revoked)
    revoked |> Ecto.Changeset.change(status: :revoked) |> Repo.update!()

    assert {:error, :grant, :stale_connection, _} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 revoked_handle,
                 ctx.tenant,
                 finalize_opts(ctx, revoked_candidate, revoked.id)
               )
             )

    expired_ctx = %{ctx | tenant: Factory.tenant_id("expired-replaced")}
    expired = connection(expired_ctx) |> Ecto.Changeset.change(status: :expired) |> Repo.update!()
    {handle, candidate} = candidate(expired_ctx, existing: expired)
    _newer = connection(expired_ctx)

    assert {:error, :grant, :stale_connection, _} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 handle,
                 expired_ctx.tenant,
                 finalize_opts(expired_ctx, candidate, expired.id)
               )
             )
  end

  test "expired expected generation reconnects when no active replacement exists", ctx do
    existing = connection(ctx) |> Ecto.Changeset.change(status: :expired) |> Repo.update!()
    {handle, candidate} = candidate(ctx, existing: existing)
    {stale_handle, stale_candidate} = candidate(ctx, existing: existing)

    assert {:ok, %{grant: %{connection: %{status: :active}}}} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 handle,
                 ctx.tenant,
                 finalize_opts(ctx, candidate, existing.id)
               )
             )

    assert Repo.get!(Connection, existing.id).status == :revoked

    assert {:error, :grant, :stale_connection, _} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 stale_handle,
                 ctx.tenant,
                 finalize_opts(ctx, stale_candidate, existing.id)
               )
             )
  end

  test "only one candidate can replace a generation or win an initial connect", ctx do
    existing = connection(ctx)
    {first_handle, first} = candidate(ctx, existing: existing)
    {second_handle, second} = candidate(ctx, existing: existing)

    assert {:ok, _} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 first_handle,
                 ctx.tenant,
                 finalize_opts(ctx, first, existing.id)
               )
             )

    assert {:error, :grant, :stale_connection, _} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 second_handle,
                 ctx.tenant,
                 finalize_opts(ctx, second, existing.id)
               )
             )

    initial_ctx = %{ctx | tenant: Factory.tenant_id("initial-race")}
    {first_handle, first} = candidate(initial_ctx, refresh_token: "first-refresh")
    {second_handle, second} = candidate(initial_ctx, refresh_token: "second-refresh")

    assert {:ok, _} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 first_handle,
                 initial_ctx.tenant,
                 finalize_opts(initial_ctx, first, nil)
               )
             )

    assert {:error, :grant, :stale_connection, _} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 second_handle,
                 initial_ctx.tenant,
                 finalize_opts(initial_ctx, second, nil)
               )
             )
  end

  test "active connection may expire during consent and provider client changes reject", ctx do
    existing = connection(ctx)
    {handle, candidate} = candidate(ctx, existing: existing)
    existing |> Ecto.Changeset.change(status: :expired) |> Repo.update!()

    assert {:ok, _} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 handle,
                 ctx.tenant,
                 finalize_opts(ctx, candidate, existing.id)
               )
             )

    changed_ctx = %{ctx | tenant: Factory.tenant_id("changed-client")}
    {handle, candidate} = candidate(changed_ctx, [])

    {:ok, changed_provider} =
      Tango.update_provider(ctx.provider, %{
        config: Map.put(ctx.provider.config, "client_id", "replacement-client")
      })

    assert {:error, :grant, :client_changed, _} =
             Repo.transaction(
               Tango.multi_finalize_authorization(
                 Ecto.Multi.new(),
                 :grant,
                 handle,
                 changed_ctx.tenant,
                 finalize_opts(%{changed_ctx | provider: changed_provider}, candidate, nil)
               )
             )
  end

  test "finalization rejects a repo other than Tango's configured repo", ctx do
    {handle, candidate} = candidate(ctx, [])

    multi =
      Tango.multi_finalize_authorization(
        Ecto.Multi.new(),
        :grant,
        handle,
        ctx.tenant,
        finalize_opts(ctx, candidate, nil)
      )

    [{:grant, {:run, operation}}] = Ecto.Multi.to_list(multi)
    assert {:error, :repo_mismatch} = operation.(:different_repo, %{})
  end

  defp connection(ctx, opts \\ []) do
    attrs = %{
      account_subject: Keyword.get(opts, :account_subject, "subject-1"),
      oauth_client_id: Keyword.get(opts, :oauth_client_id, ctx.provider.config["client_id"])
    }

    attrs =
      case Keyword.fetch(opts, :refresh_token) do
        {:ok, token} -> Map.put(attrs, :refresh_token, token)
        :error -> attrs
      end

    Factory.create_connection(ctx.provider, ctx.tenant, %{
      "scope" => Enum.join(Keyword.get(opts, :scopes, ["records.read"]), " ")
    })
    |> Ecto.Changeset.change(attrs)
    |> Repo.update!()
  end

  defp candidate(ctx, opts) do
    existing = Keyword.get(opts, :existing)
    handle = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    intent = "intent-#{System.unique_integer([:positive])}"

    {:ok, session} =
      Tango.create_authorization_session(ctx.provider.slug, ctx.tenant,
        scopes: Keyword.get(opts, :scopes, ["records.read"]),
        redirect_uri: "https://api.example.test/callback",
        completion_origin: "https://app.example.test",
        intent_reference: intent,
        expected_connection_id: existing && existing.id,
        expected_subject: existing && existing.account_subject
      )

    attrs = %{
      provider_id: ctx.provider.id,
      oauth_session_id: session.id,
      tenant_id: ctx.tenant,
      handle_hash: :crypto.hash(:sha256, handle),
      access_token: "candidate-access",
      refresh_token: Keyword.get(opts, :refresh_token, "candidate-refresh"),
      token_type: "Bearer",
      token_expires_at: DateTime.add(DateTime.utc_now(), 3600, :second),
      granted_scopes: Keyword.get(opts, :scopes, ["records.read"]),
      expected_connection_id: existing && existing.id,
      expected_subject: existing && existing.account_subject,
      oauth_client_id: session.oauth_client_id,
      intent_reference: intent,
      completion_origin: session.completion_origin,
      account_subject: "subject-1",
      identity_claims: %{"label" => "safe"},
      verified_connection_id: existing && existing.id,
      verified_at: DateTime.utc_now(),
      expires_at: DateTime.add(DateTime.utc_now(), 600, :second)
    }

    {:ok, stored} = %Authorization{} |> Authorization.changeset(attrs) |> Repo.insert()
    {handle, stored}
  end

  defp finalize_opts(ctx, candidate, expected_id) do
    [
      required_scopes: ["records.read"],
      require_refresh_token: true,
      intent_reference: candidate.intent_reference,
      provider: ctx.provider.slug,
      expected_connection_id: expected_id
    ]
  end
end

defmodule Tango.AuthorizationConsumeTest do
  use Tango.DatabaseCase, async: false

  alias Tango.Factory
  alias Tango.Schemas.{Authorization, Connection, OAuthSession, Provider}

  defmodule Verifier do
    @behaviour Tango.AuthorizationVerifier

    @impl true
    def verify(_provider, credential, opts) do
      refute Keyword.has_key?(opts, :connection_id)
      assert credential.access_token == "synthetic-consume-access"
      if action = opts[:action], do: action.()

      case opts[:error] do
        nil ->
          {:ok,
           %{subject: opts[:subject] || "account-synthetic", claims: %{}, continuity: :initial}}

        error ->
          {:error, error}
      end
    end
  end

  defmodule OrganizationClient do
    def fetch_membership(access_token, organization_id, opts) do
      case Req.get(
             Keyword.fetch!(opts, :base_url) <> "/organizations/#{organization_id}/membership",
             headers: [{"authorization", "Bearer #{access_token}"}],
             receive_timeout: 5_000,
             retry: false
           ) do
        {:ok, %{status: 200, body: body}} -> {:ok, body}
        _ -> {:error, :invalid_identity}
      end
    end
  end

  defmodule OrganizationAdminVerifier do
    @behaviour Tango.AuthorizationVerifier

    @impl true
    def verify(_provider, %{access_token: access_token}, opts) do
      organization_id = Keyword.fetch!(opts, :organization_id)
      client = Keyword.fetch!(opts, :client)

      with {:ok,
            %{
              "account_id" => subject,
              "organization_id" => ^organization_id,
              "state" => "active",
              "role" => "admin"
            }} <- client.fetch_membership(access_token, organization_id, opts),
           true <- is_binary(subject) and byte_size(subject) > 0 do
        {:ok,
         %{
           subject: subject,
           claims: %{"organization_id" => organization_id, "role" => "admin"},
           continuity: :initial
         }}
      else
        _ -> {:error, :invalid_identity}
      end
    end
  end

  setup do
    bypass = Bypass.open()
    previous_origins = Application.get_env(:tango, :allowed_completion_origins)
    Application.put_env(:tango, :allowed_completion_origins, ["https://app.example.test"])

    on_exit(fn ->
      if is_nil(previous_origins),
        do: Application.delete_env(:tango, :allowed_completion_origins),
        else: Application.put_env(:tango, :allowed_completion_origins, previous_origins)
    end)

    provider =
      Factory.create_provider(%{
        metadata: %{
          "token_response_metadata" => ["workspace_id", "completion_mode", "expected_subject"]
        },
        config: %{
          "client_id" => "synthetic-consume-client",
          "auth_url" => "http://localhost:#{bypass.port}/oauth/authorize",
          "token_url" => "http://localhost:#{bypass.port}/oauth/token"
        }
      })

    %{provider: provider, tenant: Factory.tenant_id("consume"), bypass: bypass}
  end

  test "consume binds a subject independently of a connection and permits discovery", ctx do
    for subject <- [nil, "account-synthetic"] do
      assert {:ok, session} = create_session(ctx, expected_subject: subject)
      assert session.completion_mode == :consume
      assert session.expected_connection_id == nil
      assert session.expected_subject == subject
    end
  end

  test "consume rejects invalid bindings and validates mode first", ctx do
    for binding <- [
          expected_connection_id: 1,
          expected_connection_id: "1",
          expected_subject: "",
          expected_subject: "  ",
          expected_subject: 1
        ] do
      assert {:error, :invalid_completion_options} = create_session(ctx, [binding])
    end

    for mode <- [nil, "consume", :other] do
      assert {:error, :invalid_completion_mode} =
               create_session(ctx, completion_mode: mode, expected_connection_id: -1)
    end

    assert {:error, :invalid_completion_mode} =
             Tango.create_session(ctx.provider.slug, ctx.tenant, completion_mode: :consume)

    assert {:error, :stale_connection} =
             create_session(ctx,
               completion_mode: :connection,
               expected_subject: "account-synthetic"
             )
  end

  test "staging and verification ignore attempted policy overrides alongside active connection",
       ctx do
    active = Factory.create_connection(ctx.provider, ctx.tenant) |> Repo.reload!()
    {:ok, session} = create_session(ctx, expected_subject: "account-synthetic")

    assert {:ok, url} =
             Tango.authorize_url(session.session_token,
               redirect_uri: session.redirect_uri,
               completion_mode: :connection,
               expected_subject: "attacker"
             )

    state = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("state")
    expect_token(ctx.bypass)

    result =
      Tango.Auth.process_popup_callback(%{
        "state" => state,
        "code" => "synthetic-code",
        "completion_mode" => "connection",
        "expected_subject" => "attacker"
      })

    assert %{payload: %{completion_handle: handle}} = result
    candidate = candidate(handle)
    assert candidate.completion_mode == :consume
    assert candidate.expected_subject == "account-synthetic"

    assert candidate.provider_data == %{
             "workspace_id" => "workspace-synthetic",
             "completion_mode" => "connection",
             "expected_subject" => "attacker"
           }

    assert {:ok, summary} = verify(ctx, session, handle, connection_id: active.id)
    assert summary.expected_connection_id == nil
    assert summary.has_refresh_token
    assert summary.subject == "account-synthetic"
    assert Repo.get!(Connection, active.id) == active
    assert Repo.aggregate(Connection, :count) == 1
  end

  test "discovered subject verifies with initial continuity", ctx do
    {session, handle} = stage(ctx)
    assert {:ok, %{subject: "account-synthetic"}} = verify(ctx, session, handle)
    assert candidate(handle).verified_at
  end

  test "wrong subject and terminal verifier rejection clear secrets", ctx do
    for opts <- [[subject: "wrong-subject"], [error: :invalid_identity]] do
      {session, handle} = stage(ctx, expected_subject: "account-synthetic")
      assert {:error, _} = verify(ctx, session, handle, opts)
      stored = candidate(handle)
      assert stored.consumed_at
      assert stored.access_token == nil
      assert stored.refresh_token == nil
      assert stored.provider_data == %{}
    end
  end

  test "transient errors leave consume candidate retryable", ctx do
    {session, handle} = stage(ctx)
    assert {:error, :network_error} = verify(ctx, session, handle, error: :network_error)
    refute candidate(handle).consumed_at
    assert {:ok, _} = verify(ctx, session, handle)
  end

  test "verification rejects inactive provider and changed OAuth client before verifier", ctx do
    for {change, reason} <- [
          {%{active: false}, :invalid_completion},
          {%{config: Map.put(ctx.provider.config, "client_id", "changed-client")},
           :client_changed}
        ] do
      {:ok, provider} =
        Tango.update_provider(Repo.get!(Provider, ctx.provider.id), %{
          active: true,
          config: ctx.provider.config
        })

      current_ctx = %{ctx | provider: provider}
      {session, handle} = stage(current_ctx)
      {:ok, _} = Tango.update_provider(provider, change)

      assert {:error, ^reason} =
               verify(current_ctx, session, handle,
                 action: fn -> flunk("verifier must not run") end
               )
    end
  end

  test "verification rechecks provider and session bindings after verifier returns", ctx do
    mutations = [
      {fn session ->
         Tango.update_provider(ctx.provider, %{active: false})
         session
       end, :invalid_completion},
      {fn session ->
         Tango.update_provider(ctx.provider, %{
           config: Map.put(ctx.provider.config, "client_id", "changed-client")
         })

         session
       end, :client_changed},
      {fn session ->
         session
         |> Ecto.Changeset.change(%{expected_subject: "changed-subject"})
         |> Repo.update!()
       end, :completion_mode_mismatch},
      {fn session ->
         session |> Ecto.Changeset.change(%{completion_mode: :connection}) |> Repo.update!()
       end, :completion_mode_mismatch}
    ]

    for {mutation, reason} <- mutations do
      {:ok, provider} =
        Tango.update_provider(Repo.get!(Provider, ctx.provider.id), %{
          active: true,
          config: ctx.provider.config
        })

      current_ctx = %{ctx | provider: provider}
      {session, handle} = stage(current_ctx)

      assert {:error, ^reason} =
               verify(current_ctx, session, handle, action: fn -> mutation.(session) end)

      refute candidate(handle).verified_at
      if reason == :completion_mode_mismatch, do: refute(candidate(handle).consumed_at)
    end
  end

  test "verification rejects changed candidate bindings without consuming it", ctx do
    {session, handle} = stage(ctx)

    candidate(handle)
    |> Ecto.Changeset.change(%{expected_subject: "changed-subject"})
    |> Repo.update!()

    assert {:error, :completion_mode_mismatch} =
             verify(ctx, session, handle, action: fn -> flunk("verifier must not run") end)

    refute candidate(handle).consumed_at
  end

  test "matching session and candidate edits during verification cannot change the bound subject",
       ctx do
    {session, handle} = stage(ctx)

    action = fn ->
      session |> Ecto.Changeset.change(%{expected_subject: "changed-subject"}) |> Repo.update!()

      candidate(handle)
      |> Ecto.Changeset.change(%{expected_subject: "changed-subject"})
      |> Repo.update!()
    end

    assert {:error, :completion_mode_mismatch} =
             verify(ctx, session, handle, subject: "changed-subject", action: action)

    refute candidate(handle).consumed_at
    refute candidate(handle).verified_at
  end

  test "consumption during verification cannot resurrect candidate", ctx do
    {session, handle} = stage(ctx)

    action = fn ->
      task =
        Task.async(fn ->
          candidate(handle)
          |> Ecto.Changeset.change(%{
            consumed_at: DateTime.utc_now() |> DateTime.truncate(:second),
            access_token: nil,
            refresh_token: nil,
            provider_data: %{}
          })
          |> Repo.update!()
        end)

      Task.await(task)
    end

    assert {:error, :completion_consumed} = verify(ctx, session, handle, action: action)
    stored = candidate(handle)
    assert stored.consumed_at
    refute stored.verified_at
    assert stored.access_token == nil
  end

  test "token endpoint metadata without an access token still fails", ctx do
    {:ok, session} = create_session(ctx)
    expect_token(ctx.bypass, %{"scope" => "records.read", "token_type" => "Bearer"})

    assert {:error, _} =
             Tango.stage_authorization(encoded_state(session), "synthetic-code", ctx.tenant,
               redirect_uri: session.redirect_uri
             )

    assert Repo.aggregate(Authorization, :count) == 0
  end

  test "successful consumption erases credentials and returns exactly the safe proof", ctx do
    active = Factory.create_connection(ctx.provider, ctx.tenant) |> Repo.reload!()
    {session, handle} = stage(ctx, expected_subject: "account-synthetic")
    assert {:ok, verification} = verify(ctx, session, handle)

    assert verification == %{
             provider: ctx.provider.slug,
             subject: "account-synthetic",
             claims: %{},
             granted_scopes: ["records.read"],
             intent_reference: session.intent_reference,
             expected_connection_id: nil,
             has_refresh_token: true
           }

    before_count = Repo.aggregate(Connection, :count)
    multi = consume_multi(ctx, session, handle)

    assert {:ok, %{proof: proof}} = Repo.transaction(multi)

    assert Enum.sort(Map.keys(proof)) ==
             Enum.sort([:provider, :subject, :claims, :granted_scopes, :intent_reference])

    assert proof == %{
             provider: ctx.provider.slug,
             subject: "account-synthetic",
             claims: %{},
             granted_scopes: ["records.read"],
             intent_reference: session.intent_reference
           }

    assert Repo.aggregate(Connection, :count) == before_count
    assert Repo.get!(Connection, active.id) == active
    stored = candidate(handle)
    assert stored.consumed_at
    assert is_nil(stored.access_token)
    assert is_nil(stored.refresh_token)
    assert stored.provider_data == %{}
    assert {:error, :proof, :completion_consumed, _} = Repo.transaction(multi)
  end

  test "organization administrator example consumes bounded claims after an active membership check",
       ctx do
    for {state, role, organization_id, accepted?} <- [
          {"active", "admin", "org-synthetic", true},
          {"inactive", "admin", "org-synthetic", false},
          {"active", "member", "org-synthetic", false},
          {"active", "admin", "other-organization", false}
        ] do
      {session, handle} = stage(ctx)

      Bypass.expect_once(ctx.bypass, "GET", "/organizations/org-synthetic/membership", fn conn ->
        assert Plug.Conn.get_req_header(conn, "authorization") ==
                 ["Bearer synthetic-consume-access"]

        body = %{
          "account_id" => "account-synthetic",
          "organization_id" => organization_id,
          "state" => state,
          "role" => role,
          "unrelated" => "omit-from-claims"
        }

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, Jason.encode!(body))
      end)

      verifier =
        {OrganizationAdminVerifier,
         client: OrganizationClient,
         organization_id: "org-synthetic",
         base_url: "http://localhost:#{ctx.bypass.port}"}

      result =
        Tango.verify_authorization(handle, ctx.tenant, verifier,
          provider: ctx.provider.slug,
          intent_reference: session.intent_reference
        )

      if accepted? do
        assert {:ok, %{subject: "account-synthetic"}} = result
        assert {:ok, %{proof: proof}} = Repo.transaction(consume_multi(ctx, session, handle))
        assert proof.claims == %{"organization_id" => "org-synthetic", "role" => "admin"}
        assert proof.subject == "account-synthetic"
        assert candidate(handle).access_token == nil
        assert Repo.aggregate(Connection, :count) == 0
      else
        assert {:error, :invalid_identity} = result
        assert candidate(handle).consumed_at
        assert candidate(handle).access_token == nil
      end
    end
  end

  test "host rollback preserves staged credentials and permits identical completion retry", ctx do
    {session, handle} = stage(ctx)
    assert {:ok, _} = verify(ctx, session, handle)
    before = candidate(handle)
    multi = consume_multi(ctx, session, handle)
    rollback = Ecto.Multi.run(multi, :host_write, fn _repo, _changes -> {:error, :rejected} end)

    assert {:error, :host_write, :rejected, _} = Repo.transaction(rollback)
    assert candidate(handle) == before

    assert {:error, :invalid_session} =
             Tango.stage_authorization(encoded_state(session), "synthetic-code", ctx.tenant,
               redirect_uri: session.redirect_uri
             )

    assert {:ok, %{proof: %{subject: "account-synthetic"}}} = Repo.transaction(multi)
    assert Repo.get!(OAuthSession, session.id).exchanged_at
    assert Repo.aggregate(Authorization, :count) == 1
    assert Repo.aggregate(Connection, :count) == 0
  end

  test "consume checks tenant provider intent and scopes without spending proof", ctx do
    {session, handle} = stage(ctx)
    assert {:ok, _} = verify(ctx, session, handle)

    for {tenant, opts, reason} <- [
          {"other-tenant", [], :invalid_completion},
          {ctx.tenant, [provider: "other-provider"], :invalid_completion},
          {ctx.tenant, [intent_reference: "other-intent"], :intent_mismatch},
          {ctx.tenant, [required_scopes: ["records.write"]], :missing_scopes}
        ] do
      assert {:error, :proof, ^reason, _} =
               Repo.transaction(consume_multi(%{ctx | tenant: tenant}, session, handle, opts))

      refute candidate(handle).consumed_at
    end

    assert {:ok, _} = Repo.transaction(consume_multi(ctx, session, handle))
  end

  test "consume rejects invalid options and malformed input with stable errors", ctx do
    {session, handle} = stage(ctx)
    assert {:ok, _} = verify(ctx, session, handle)

    for opts <- [
          [expected_connection_id: nil],
          [require_refresh_token: false],
          [completion_mode: :consume],
          [expected_subject: "account-synthetic"],
          ["invalid"],
          %{provider: ctx.provider.slug}
        ] do
      multi =
        Tango.Authorization.multi_consume_authorization(
          Ecto.Multi.new(),
          :proof,
          handle,
          ctx.tenant,
          opts
        )

      assert {:error, :proof, :invalid_completion_options, _} = Repo.transaction(multi)
    end

    for scopes <- [nil, "records.read", [1], [""], ["records.read" | :invalid]] do
      assert {:error, :proof, :invalid_scopes, _} =
               Repo.transaction(consume_multi(ctx, session, handle, required_scopes: scopes))
    end

    for {bad_handle, tenant} <- [{nil, ctx.tenant}, {"bad-handle", ctx.tenant}, {handle, nil}] do
      multi =
        Tango.Authorization.multi_consume_authorization(
          Ecto.Multi.new(),
          :proof,
          bad_handle,
          tenant,
          []
        )

      assert {:error, :proof, :invalid_completion, _} = Repo.transaction(multi)
    end

    for opts <- [[intent_reference: session.intent_reference], [provider: ctx.provider.slug]] do
      multi =
        Tango.Authorization.multi_consume_authorization(
          Ecto.Multi.new(),
          :proof,
          handle,
          ctx.tenant,
          opts
        )

      assert {:error, :proof, :invalid_completion, _} = Repo.transaction(multi)
    end

    refute candidate(handle).consumed_at
  end

  test "consume rejects unverified expired token expired candidate and altered proof", ctx do
    for {change, reason} <- [
          {%{verified_at: nil}, :verification_required},
          {%{
             expires_at:
               DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)
           }, :expired_completion},
          {%{
             token_expires_at:
               DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)
           }, :token_expired},
          {%{account_subject: "wrong-subject"}, :account_mismatch}
        ] do
      {session, handle} = stage(ctx, expected_subject: "account-synthetic")
      assert {:ok, _} = verify(ctx, session, handle)
      candidate(handle) |> Ecto.Changeset.change(change) |> Repo.update!()
      assert {:error, :proof, ^reason, _} = Repo.transaction(consume_multi(ctx, session, handle))
      refute candidate(handle).consumed_at
    end
  end

  test "consume rechecks active provider client and session bindings", ctx do
    for {change, reason} <- [
          {%{active: false}, :invalid_completion},
          {%{config: Map.put(ctx.provider.config, "client_id", "changed-client")},
           :client_changed}
        ] do
      {:ok, provider} =
        Tango.update_provider(Repo.get!(Provider, ctx.provider.id), %{
          active: true,
          config: ctx.provider.config
        })

      {session, handle} = stage(%{ctx | provider: provider})
      assert {:ok, _} = verify(ctx, session, handle)
      {:ok, _} = Tango.update_provider(provider, change)
      assert {:error, :proof, ^reason, _} = Repo.transaction(consume_multi(ctx, session, handle))
      refute candidate(handle).consumed_at
    end

    {:ok, _} =
      Tango.update_provider(Repo.get!(Provider, ctx.provider.id), %{
        active: true,
        config: ctx.provider.config
      })

    {session, handle} = stage(ctx)
    assert {:ok, _} = verify(ctx, session, handle)
    session |> Ecto.Changeset.change(expected_subject: "other-subject") |> Repo.update!()

    assert {:error, :proof, :completion_mode_mismatch, _} =
             Repo.transaction(consume_multi(ctx, session, handle))

    refute candidate(handle).consumed_at
  end

  test "wrong completion paths do not spend candidates", ctx do
    {session, handle} = stage(ctx)
    assert {:ok, _} = verify(ctx, session, handle)
    opts = [provider: ctx.provider.slug, intent_reference: session.intent_reference]
    multi = Tango.multi_finalize_authorization(Ecto.Multi.new(), :grant, handle, ctx.tenant, opts)
    assert {:error, :grant, :completion_mode_mismatch, _} = Repo.transaction(multi)
    refute candidate(handle).consumed_at
    assert {:ok, _} = Repo.transaction(consume_multi(ctx, session, handle))

    {session, handle} = stage(ctx, completion_mode: :connection)
    assert {:ok, _} = verify(ctx, session, handle)

    assert {:error, :proof, :completion_mode_mismatch, _} =
             Repo.transaction(consume_multi(ctx, session, handle))

    refute candidate(handle).consumed_at
    opts = [provider: ctx.provider.slug, intent_reference: session.intent_reference]
    multi = Tango.multi_finalize_authorization(Ecto.Multi.new(), :grant, handle, ctx.tenant, opts)
    assert {:ok, _} = Repo.transaction(multi)
  end

  test "consume rejects another transaction repo before inspecting input", ctx do
    multi = consume_multi(ctx, %{intent_reference: "intent-synthetic"}, "invalid")
    [{:proof, {:run, operation}}] = Ecto.Multi.to_list(multi)
    assert {:error, :repo_mismatch} = operation.(:different_repo, %{})
  end

  defp consume_multi(ctx, session, handle, opts \\ []) do
    Tango.Authorization.multi_consume_authorization(
      Ecto.Multi.new(),
      :proof,
      handle,
      ctx.tenant,
      Keyword.merge(
        [
          provider: ctx.provider.slug,
          intent_reference: session.intent_reference,
          required_scopes: ["records.read"]
        ],
        opts
      )
    )
  end

  defp create_session(ctx, opts \\ []) do
    Tango.create_authorization_session(
      ctx.provider.slug,
      ctx.tenant,
      Keyword.merge(
        [
          completion_mode: :consume,
          scopes: ["records.read"],
          redirect_uri: "https://api.example.test/callback",
          completion_origin: "https://app.example.test",
          intent_reference: "intent-synthetic"
        ],
        opts
      )
    )
  end

  defp stage(ctx, opts \\ []) do
    {:ok, session} = create_session(ctx, opts)
    expect_token(ctx.bypass)

    {:ok, completion} =
      Tango.stage_authorization(encoded_state(session), "synthetic-code", ctx.tenant,
        redirect_uri: session.redirect_uri
      )

    {session, completion.completion_handle}
  end

  defp encoded_state(session) do
    {:ok, url} = Tango.Auth.authorization_url(session)
    url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("state")
  end

  defp verify(ctx, session, handle, opts \\ []) do
    Tango.verify_authorization(handle, ctx.tenant, {Verifier, opts},
      provider: ctx.provider.slug,
      intent_reference: session.intent_reference
    )
  end

  defp candidate(handle),
    do: Repo.get_by!(Authorization, handle_hash: :crypto.hash(:sha256, handle))

  defp expect_token(
         bypass,
         response \\ %{
           "access_token" => "synthetic-consume-access",
           "refresh_token" => "synthetic-consume-refresh",
           "token_type" => "Bearer",
           "scope" => "records.read",
           "workspace_id" => "workspace-synthetic",
           "completion_mode" => "connection",
           "expected_subject" => "attacker"
         }
       ) do
    Bypass.expect_once(bypass, "POST", "/oauth/token", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(response))
    end)
  end
end

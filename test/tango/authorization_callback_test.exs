defmodule Tango.AuthorizationCallbackTest do
  use Tango.DatabaseCase, async: false

  import ExUnit.CaptureLog
  import Plug.Conn
  import Plug.Test

  alias Ecto.Adapters.SQL
  alias Tango.API.Router
  alias Tango.Factory
  alias Tango.Schemas.{AuditLog, Authorization, Connection, OAuthSession}

  @origin "https://app.example.test"
  @redirect_uri "https://api.example.test/callback"
  @code "authcode-sentinel-1234567890"
  @api_key "Bearer lets-dance-the-tango"

  defmodule InitialVerifier do
    @behaviour Tango.AuthorizationVerifier

    @impl true
    def verify(_provider, %{access_token: "candidate-access-secret"}, _opts) do
      {:ok, %{subject: "subject-1", claims: %{"label" => "Example"}, continuity: :initial}}
    end
  end

  setup do
    bypass = Bypass.open()
    previous_origins = Application.get_env(:tango, :allowed_completion_origins)
    Application.put_env(:tango, :allowed_completion_origins, [@origin])

    on_exit(fn ->
      if previous_origins do
        Application.put_env(:tango, :allowed_completion_origins, previous_origins)
      else
        Application.delete_env(:tango, :allowed_completion_origins)
      end
    end)

    provider =
      Factory.create_provider(%{
        default_scopes: ["records.read"],
        config: %{
          "display_name" => "Callback Test",
          "client_id" => "callback-client",
          "auth_url" => "http://localhost:#{bypass.port}/oauth/authorize",
          "token_url" => "http://localhost:#{bypass.port}/oauth/token"
        }
      })

    %{bypass: bypass, provider: provider, tenant: Factory.tenant_id("callback")}
  end

  describe "popup callback HTML" do
    test "carries only the opaque handle to the session's exact origin", ctx do
      session = authorization_session(ctx)
      state = encoded_state(session)
      expect_token(ctx.bypass)

      conn = callback(code: @code, state: state)
      html = conn.resp_body

      assert conn.status == 200
      refute html =~ "candidate-access-secret"
      refute html =~ "candidate-refresh-secret"
      refute html =~ @code
      refute html =~ "console.log"
      refute html =~ "console."
      assert html =~ "completion_handle"
      refute html =~ ~s|postMessage(payload, '*')|
      refute html =~ "'*'"
      refute html =~ ~s("*")
      refute html =~ "location.origin"
      assert html =~ "window.opener.postMessage(payload, completionOrigin)"

      payload = extract_payload(html)
      handle = payload["completion_handle"]

      assert payload == %{
               "type" => "oauth_complete",
               "completion_handle" => handle,
               "intent_reference" => "intent-1"
             }

      assert byte_size(Base.url_decode64!(handle, padding: false)) == 32
      assert extract_origin(html) == @origin

      candidate = Repo.one!(Authorization)
      assert candidate.handle_hash == :crypto.hash(:sha256, handle)
      assert candidate.access_token == "candidate-access-secret"
      assert Repo.aggregate(Connection, :count) == 0
    end

    test "the handle completes only through trusted server-side verification", ctx do
      session = authorization_session(ctx)
      expect_token(ctx.bypass)

      handle = callback(code: @code, state: encoded_state(session)) |> extract_payload()
      handle = handle["completion_handle"]

      assert {:ok, summary} =
               Tango.verify_authorization(handle, ctx.tenant, {InitialVerifier, []},
                 intent_reference: "intent-1",
                 provider: ctx.provider.slug
               )

      assert summary.subject == "subject-1"
      refute inspect(summary) =~ "candidate-access-secret"
    end

    test "an expired completion cannot be verified", ctx do
      session = authorization_session(ctx)
      expect_token(ctx.bypass)

      handle =
        callback(code: @code, state: encoded_state(session))
        |> extract_payload()
        |> Map.fetch!("completion_handle")

      Repo.one!(Authorization)
      |> Ecto.Changeset.change(%{
        expires_at: DateTime.add(DateTime.utc_now(), -1, :second) |> DateTime.truncate(:second)
      })
      |> Repo.update!()

      assert {:error, :expired_completion} =
               Tango.verify_authorization(handle, ctx.tenant, {InitialVerifier, []},
                 intent_reference: "intent-1",
                 provider: ctx.provider.slug
               )
    end

    test "provider token failure reports a stable category without the response body", ctx do
      session = authorization_session(ctx)
      expect_oauth_denial(ctx.bypass)

      html = callback(code: @code, state: encoded_state(session)).resp_body

      refute html =~ "denial-body-secret"
      refute html =~ "candidate-"
      refute html =~ "console.log"
      assert html =~ "window.opener.postMessage(payload, completionOrigin)"

      assert extract_payload(html) == %{
               "type" => "oauth_error",
               "error" => "invalid_grant",
               "intent_reference" => "intent-1"
             }

      assert extract_origin(html) == @origin
      assert Repo.aggregate(Authorization, :count) == 0
    end

    test "a replayed callback fails with a stable category", ctx do
      session = authorization_session(ctx)
      state = encoded_state(session)
      expect_token(ctx.bypass)

      assert callback(code: @code, state: state) |> extract_payload() |> Map.fetch!("type") ==
               "oauth_complete"

      replay = callback(code: @code, state: state).resp_body

      assert extract_payload(replay) == %{
               "type" => "oauth_error",
               "error" => "invalid_session",
               "intent_reference" => "intent-1"
             }

      assert extract_origin(replay) == @origin
      assert Repo.aggregate(Authorization, :count) == 1
    end

    test "an expired session fails with a stable category and stages nothing", ctx do
      session = authorization_session(ctx)
      state = encoded_state(session)

      session
      |> Ecto.Changeset.change(%{
        expires_at: DateTime.add(DateTime.utc_now(), -1, :second) |> DateTime.truncate(:second)
      })
      |> Repo.update!()

      html = callback(code: @code, state: state).resp_body

      assert extract_payload(html)["error"] == "invalid_session"
      assert Repo.aggregate(Authorization, :count) == 0
    end

    test "provider denial reports only the mapped category", ctx do
      session = authorization_session(ctx)

      html =
        callback(
          error: "access_denied",
          error_description: "<script>alert('xss')</script> candidate-access-secret",
          state: encoded_state(session)
        ).resp_body

      refute html =~ "<script>alert"
      refute html =~ "candidate-access-secret"

      assert extract_payload(html) == %{
               "type" => "oauth_error",
               "error" => "access_denied",
               "intent_reference" => "intent-1"
             }

      assert extract_origin(html) == @origin

      audit =
        Repo.one!(from(log in AuditLog, where: log.event_type == :oauth_denied))

      assert audit.event_data["oauth_error"] == "access_denied"
      assert audit.session_id =~ ~r/\A[0-9a-f]{64}\z/
      refute inspect(audit.event_data) =~ "alert"
      refute inspect(audit.event_data) =~ "candidate-access-secret"
    end

    test "missing code reports a stable category", ctx do
      session = authorization_session(ctx)
      html = callback(state: encoded_state(session)).resp_body

      assert extract_payload(html)["error"] == "missing_callback_params"
      assert Repo.aggregate(Authorization, :count) == 0
    end

    test "unknown or malformed state posts nothing", _ctx do
      for params <- [[], [code: @code], [code: @code, state: "not-a-state"]] do
        html = callback(params).resp_body

        assert html =~ "const payload = null;"
        assert html =~ "const completionOrigin = null;"
        refute html =~ "'*'"
      end
    end

    test "a legacy session without a completion origin is not exchanged by the popup", ctx do
      {:ok, legacy} =
        Tango.create_session(ctx.provider.slug, ctx.tenant, redirect_uri: @redirect_uri)

      {:ok, url} = Tango.authorize_url(legacy.session_token)

      state =
        url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("state")

      html = callback(code: @code, state: state).resp_body

      assert html =~ "const payload = null;"
      assert html =~ "const completionOrigin = null;"
      assert Repo.get!(OAuthSession, legacy.id).exchanged_at == nil
      assert Repo.aggregate(Connection, :count) == 0
    end

    test "an origin that is no longer allowed receives nothing and nothing is staged", ctx do
      session = authorization_session(ctx)
      state = encoded_state(session)
      Application.put_env(:tango, :allowed_completion_origins, ["https://other.example.test"])

      html = callback(code: @code, state: state).resp_body

      assert html =~ "const payload = null;"
      assert html =~ "const completionOrigin = null;"
      assert Repo.aggregate(Authorization, :count) == 0
      assert Repo.get!(OAuthSession, session.id).exchanged_at == nil
    end

    test "hostile intent references cannot break out of the script element", ctx do
      hostile = "</script><script>alert(1)</script><!--"
      session = authorization_session(ctx, hostile)
      expect_token(ctx.bypass)

      html = callback(code: @code, state: encoded_state(session)).resp_body

      refute html =~ "<script>alert"
      refute html =~ "<!--"
      assert length(Regex.scan(~r{</script>}, html)) == 1
      assert extract_payload(html)["intent_reference"] == hostile
    end

    test "sets a restrictive CSP, no-store, and no-referrer on the callback response", ctx do
      session = authorization_session(ctx)
      expect_token(ctx.bypass)

      conn = callback(code: @code, state: encoded_state(session))
      [csp] = get_resp_header(conn, "content-security-policy")

      assert csp =~ "default-src 'none'"
      assert csp =~ "script-src 'unsafe-inline'"
      assert csp =~ "base-uri 'none'"
      assert csp =~ "frame-ancestors 'none'"
      refute csp =~ "*"
      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "referrer-policy") == ["no-referrer"]
      assert conn.resp_body =~ "Content-Security-Policy"

      [_, meta_csp] =
        Regex.run(~r/http-equiv="Content-Security-Policy" content="([^"]*)"/, conn.resp_body)

      # frame-ancestors is ignored in a <meta> policy, so it is header-only.
      assert meta_csp <> "; frame-ancestors 'none'" == csp
    end
  end

  describe "generic API endpoints" do
    test "exchange refuses staged sessions without consuming them or calling the provider",
         ctx do
      session = authorization_session(ctx)
      state = encoded_state(session)

      conn =
        conn(:post, "/exchange", %{
          "state" => state,
          "code" => @code,
          "redirect_uri" => @redirect_uri
        })
        |> put_req_header("content-type", "application/json")
        |> put_req_header("x-tenant-id", ctx.tenant)
        |> put_req_header("authorization", @api_key)
        |> Router.call(Router.init([]))

      assert conn.status == 400
      assert %{"error" => "invalid_session"} = Jason.decode!(conn.resp_body)
      assert Repo.get!(OAuthSession, session.id).exchanged_at == nil
      assert Repo.aggregate(Connection, :count) == 0
      assert Repo.aggregate(Authorization, :count) == 0
    end

    test "exchange never returns an access token to the caller", ctx do
      {state, _session} = legacy_state(ctx)
      expect_token(ctx.bypass)

      conn =
        conn(:post, "/exchange", %{
          "state" => state,
          "code" => @code,
          "redirect_uri" => @redirect_uri,
          "include_token" => "true"
        })
        |> put_req_header("content-type", "application/json")
        |> put_req_header("x-tenant-id", ctx.tenant)
        |> put_req_header("authorization", @api_key)
        |> Router.call(Router.init([]))

      assert conn.status == 200
      refute conn.resp_body =~ "candidate-access-secret"
      refute conn.resp_body =~ "access_token"
    end

    test "verification and finalization are not routable", ctx do
      for path <- ["/verify", "/finalize", "/stage", "/complete", "/authorizations"] do
        conn =
          conn(:post, path, %{"completion_handle" => "x"})
          |> put_req_header("content-type", "application/json")
          |> put_req_header("x-tenant-id", ctx.tenant)
          |> put_req_header("authorization", @api_key)
          |> Router.call(Router.init([]))

        assert conn.status == 404
      end
    end

    test "failed exchange does not log or return the provider response body", ctx do
      {state, _session} = legacy_state(ctx)
      expect_oauth_denial(ctx.bypass)

      {conn, log} =
        with_log(fn ->
          conn(:post, "/exchange", %{
            "state" => state,
            "code" => @code,
            "redirect_uri" => @redirect_uri
          })
          |> put_req_header("content-type", "application/json")
          |> put_req_header("x-tenant-id", ctx.tenant)
          |> put_req_header("authorization", @api_key)
          |> Router.call(Router.init([]))
        end)

      refute conn.resp_body =~ "denial-body-secret"
      refute log =~ "denial-body-secret"
      refute log =~ "authcode"
    end
  end

  describe "trusted direct exchange" do
    test "rejects staged sessions and leaves them claimable", ctx do
      session = authorization_session(ctx)
      state = encoded_state(session)

      assert {:error, :invalid_session} =
               Tango.exchange_code(state, @code, ctx.tenant, redirect_uri: @redirect_uri)

      assert Repo.get!(OAuthSession, session.id).exchanged_at == nil
      assert Repo.aggregate(Connection, :count) == 0

      expect_token(ctx.bypass)

      assert {:ok, %{completion_handle: _}} =
               Tango.stage_authorization(state, @code, ctx.tenant, redirect_uri: @redirect_uri)
    end

    test "still exchanges legacy sessions and logs no credentials", ctx do
      {state, _session} = legacy_state(ctx)
      expect_token(ctx.bypass)

      log =
        capture_log([level: :debug], fn ->
          assert {:ok, %Connection{}} =
                   Tango.exchange_code(state, @code, ctx.tenant, redirect_uri: @redirect_uri)
        end)

      assert_log_is_credential_free(log, state)
    end

    test "failed exchange logs no provider body or credentials", ctx do
      {state, _session} = legacy_state(ctx)
      expect_oauth_denial(ctx.bypass)

      log =
        capture_log([level: :debug], fn ->
          assert {:error, {:oauth_error, :invalid_grant}} =
                   Tango.exchange_code(state, @code, ctx.tenant, redirect_uri: @redirect_uri)
        end)

      assert_log_is_credential_free(log, state)
    end
  end

  describe "logging on the staged path" do
    test "success callback logs no credentials", ctx do
      session = authorization_session(ctx)
      state = encoded_state(session)
      expect_token(ctx.bypass)

      log =
        capture_log([level: :debug], fn ->
          assert callback(code: @code, state: state).status == 200
        end)

      assert_log_is_credential_free(log, state)
    end

    test "failure callback logs no credentials or provider body", ctx do
      session = authorization_session(ctx)
      state = encoded_state(session)
      expect_oauth_denial(ctx.bypass)

      log =
        capture_log([level: :debug], fn ->
          assert callback(code: @code, state: state).status == 200
        end)

      assert_log_is_credential_free(log, state)
    end

    test "provider denial callback logs no description", ctx do
      session = authorization_session(ctx)
      state = encoded_state(session)

      log =
        capture_log([level: :debug], fn ->
          callback(error: "access_denied", error_description: "description-secret", state: state)
        end)

      refute log =~ "description-secret"
      refute log =~ String.slice(state, 0, 20)
    end
  end

  describe "SQL telemetry and log parameters" do
    test "consume callback verification proof and cleanup expose no synthetic secrets", ctx do
      {:ok, provider} =
        Tango.update_provider(ctx.provider, %{
          metadata: %{"token_response_metadata" => ["workspace_id"]}
        })

      ctx = %{ctx | provider: provider}
      session = authorization_session(ctx, "consume-redaction", completion_mode: :consume)
      state = encoded_state(session)
      expect_token(ctx.bypass, %{"workspace_id" => "synthetic-workspace-identity"})

      {queries, log} =
        with_log([level: :debug], fn ->
          capture_queries(fn ->
            response = callback(code: @code, state: state)
            payload = extract_payload(response)
            handle = Map.fetch!(payload, "completion_handle")

            assert payload == %{
                     "type" => "oauth_complete",
                     "completion_handle" => handle,
                     "intent_reference" => "consume-redaction"
                   }

            assert {:ok, summary} =
                     Tango.verify_authorization(handle, ctx.tenant, {InitialVerifier, []},
                       intent_reference: session.intent_reference,
                       provider: provider.slug
                     )

            multi =
              Tango.Authorization.multi_consume_authorization(
                Ecto.Multi.new(),
                :proof,
                handle,
                ctx.tenant,
                intent_reference: session.intent_reference,
                provider: provider.slug
              )

            assert {:ok, %{proof: proof}} = Repo.transaction(multi)

            assert Enum.sort(Map.keys(proof)) ==
                     Enum.sort([:provider, :subject, :claims, :granted_scopes, :intent_reference])

            for public <- [response.resp_body, summary, proof],
                sentinel <- [
                  "candidate-access-secret",
                  "candidate-refresh-secret",
                  "synthetic-workspace-identity",
                  @code
                ] do
              refute term_contains?(public, sentinel)
            end

            stored = Repo.get_by!(Authorization, oauth_session_id: session.id)
            assert stored.consumed_at
            assert stored.access_token == nil
            assert stored.refresh_token == nil
            assert stored.provider_data == %{}
            assert {:ok, 1} = Tango.cleanup_expired_authorizations()
            refute Repo.get(Authorization, stored.id)
          end)
        end)

      assert_log_is_credential_free(log, state)
      assert_queries_are_credential_free(queries)
      refute Enum.any?(queries, &(&1.query =~ "tango_connections"))
      audits = Repo.all(AuditLog)
      refute audits == []

      for audit <- audits,
          sentinel <- [
            "candidate-access-secret",
            "candidate-refresh-secret",
            "synthetic-workspace-identity",
            @code
          ] do
        refute term_contains?(audit, sentinel)
      end

      assert Repo.aggregate(Connection, :count) == 0
    end

    test "candidate staging never exposes plaintext tokens in query params", ctx do
      session = authorization_session(ctx)
      state = encoded_state(session)
      expect_token(ctx.bypass)

      queries =
        capture_queries(fn ->
          assert callback(code: @code, state: state).status == 200
        end)

      assert Enum.any?(queries, &(&1.query =~ ~s|INSERT INTO "tango_authorizations"|))
      assert_queries_are_credential_free(queries)
    end

    test "direct exchange never exposes plaintext tokens in query params", ctx do
      {state, _session} = legacy_state(ctx)
      expect_token(ctx.bypass)

      queries =
        capture_queries(fn ->
          assert {:ok, %Connection{access_token: "candidate-access-secret"}} =
                   Tango.exchange_code(state, @code, ctx.tenant, redirect_uri: @redirect_uri)
        end)

      assert Enum.any?(queries, &(&1.query =~ ~s|INSERT INTO "tango_connections"|))
      assert_queries_are_credential_free(queries)
    end

    test "finalization never exposes plaintext tokens in query params", ctx do
      session = authorization_session(ctx)
      expect_token(ctx.bypass)

      handle =
        callback(code: @code, state: encoded_state(session))
        |> extract_payload()
        |> Map.fetch!("completion_handle")

      queries =
        capture_queries(fn ->
          assert {:ok, _summary} =
                   Tango.verify_authorization(handle, ctx.tenant, {InitialVerifier, []},
                     intent_reference: "intent-1",
                     provider: ctx.provider.slug
                   )

          assert {:ok, %{finalize: %{connection: connection}}} =
                   Ecto.Multi.new()
                   |> Tango.multi_finalize_authorization(:finalize, handle, ctx.tenant,
                     required_scopes: ["records.read"],
                     intent_reference: "intent-1",
                     provider: ctx.provider.slug
                   )
                   |> Repo.transaction()

          # The caller still receives the usable plaintext credential.
          assert connection.access_token == "candidate-access-secret"
          assert connection.refresh_token == "candidate-refresh-secret"
        end)

      assert Enum.any?(queries, &(&1.query =~ ~s|INSERT INTO "tango_connections"|))
      assert_queries_are_credential_free(queries)
      assert Repo.one!(Connection).access_token == "candidate-access-secret"
    end

    test "token refresh never exposes plaintext tokens in query params", ctx do
      connection =
        Factory.create_connection(ctx.provider, ctx.tenant, %{
          "access_token" => "stale-access-token",
          "refresh_token" => "stale-refresh-token"
        })

      Bypass.expect_once(ctx.bypass, "POST", "/oauth/token", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "access_token" => "candidate-access-secret",
            "refresh_token" => "candidate-refresh-secret",
            "token_type" => "Bearer",
            "expires_in" => 3600
          })
        )
      end)

      queries =
        capture_queries(fn ->
          assert {:ok, refreshed} = Tango.refresh_connection(connection)
          assert refreshed.access_token == "candidate-access-secret"
        end)

      assert Enum.any?(queries, &(&1.query =~ ~s|UPDATE "tango_connections"|))
      assert_queries_are_credential_free(queries)
      assert Repo.get!(Connection, connection.id).refresh_token == "candidate-refresh-secret"
    end

    test "redacted placeholders hold no credential and leave no process state behind", ctx do
      session = authorization_session(ctx)
      expect_token(ctx.bypass)

      queries =
        capture_queries(fn -> callback(code: @code, state: encoded_state(session)) end)

      placeholders =
        queries
        |> Enum.flat_map(&((&1.cast_params || []) ++ (&1.params || [])))
        |> Enum.filter(&match?(%Tango.RedactedParams.Secret{}, &1))

      assert length(placeholders) == 2

      for placeholder <- placeholders do
        assert Map.keys(placeholder) -- [:__struct__] == [:ref]
        assert :error = Tango.RedactedParams.fetch(placeholder)
      end

      assert Enum.filter(Process.get_keys(), &match?({Tango.RedactedParams, _}, &1)) == []
    end

    test "the stored candidate still decrypts and verifies after redaction", ctx do
      session = authorization_session(ctx)
      expect_token(ctx.bypass)
      callback(code: @code, state: encoded_state(session))

      candidate = Repo.one!(Authorization)
      assert candidate.access_token == "candidate-access-secret"
      assert candidate.refresh_token == "candidate-refresh-secret"

      %{rows: [[raw_access, raw_refresh]]} =
        SQL.query!(
          Repo,
          "SELECT access_token, refresh_token FROM tango_authorizations WHERE id = $1",
          [candidate.id]
        )

      refute raw_access =~ "candidate-access-secret"
      refute raw_refresh =~ "candidate-refresh-secret"
    end
  end

  describe "staged exchange audit" do
    test "success records a credential-free token_exchange event", ctx do
      session = authorization_session(ctx)
      state = encoded_state(session)
      expect_token(ctx.bypass)

      assert {:ok, completion} =
               Tango.stage_authorization(state, @code, ctx.tenant, redirect_uri: @redirect_uri)

      audit = Repo.one!(from(log in AuditLog, where: log.event_type == :token_exchange))

      assert audit.success
      assert audit.tenant_id == ctx.tenant
      assert audit.provider_id == ctx.provider.id
      assert audit.connection_id == nil
      assert audit.error_code == nil
      assert audit.session_id =~ ~r/\A[0-9a-f]{64}\z/
      assert audit.event_data["staged"] == true
      assert audit.event_data["scopes_granted"] == ["records.read", "records.write"]
      assert audit.event_data["token_type"] == "Bearer"
      assert audit.event_data["token_expires_at"]

      dump = inspect(audit)
      refute dump =~ "candidate-access-secret"
      refute dump =~ "candidate-refresh-secret"
      refute dump =~ @code
      refute dump =~ completion.completion_handle
      refute dump =~ String.slice(state, 0, 20)
      refute dump =~ session.session_token
      refute dump =~ session.state
    end

    test "token endpoint failure records a stable category without the response body", ctx do
      session = authorization_session(ctx)
      state = encoded_state(session)
      expect_oauth_denial(ctx.bypass)

      assert {:error, {:oauth_error, :invalid_grant}} =
               Tango.stage_authorization(state, @code, ctx.tenant, redirect_uri: @redirect_uri)

      audit = Repo.one!(from(log in AuditLog, where: log.event_type == :token_exchange))

      refute audit.success
      assert audit.tenant_id == ctx.tenant
      assert audit.provider_id == ctx.provider.id
      assert audit.error_code == :invalid_grant
      assert audit.session_id =~ ~r/\A[0-9a-f]{64}\z/
      assert audit.event_data["staged"] == true
      assert audit.event_data["category"] == "invalid_grant"

      dump = inspect(audit)
      refute dump =~ "denial-body-secret"
      refute dump =~ @code
      refute dump =~ String.slice(state, 0, 20)
      refute dump =~ session.session_token
    end

    test "replayed and invalid sessions add no exchange audit", ctx do
      session = authorization_session(ctx)
      state = encoded_state(session)
      expect_token(ctx.bypass)

      assert {:ok, _completion} =
               Tango.stage_authorization(state, @code, ctx.tenant, redirect_uri: @redirect_uri)

      assert {:error, :invalid_session} =
               Tango.stage_authorization(state, @code, ctx.tenant, redirect_uri: @redirect_uri)

      assert Repo.aggregate(
               from(log in AuditLog, where: log.event_type == :token_exchange),
               :count
             ) ==
               1
    end

    test "popup callback records the same sanitized events", ctx do
      ok = authorization_session(ctx, "intent-ok")
      expect_token(ctx.bypass)
      callback(code: @code, state: encoded_state(ok))

      failed = authorization_session(ctx, "intent-failed")
      expect_oauth_denial(ctx.bypass)
      callback(code: @code, state: encoded_state(failed))

      events =
        Repo.all(
          from(log in AuditLog, where: log.event_type == :token_exchange, order_by: log.id)
        )

      assert Enum.map(events, & &1.success) == [true, false]
      assert Enum.map(events, & &1.error_code) == [nil, :invalid_grant]
      refute inspect(events) =~ "denial-body-secret"
      refute inspect(events) =~ "candidate-access-secret"
    end
  end

  describe "cleanup_expired_authorizations/0" do
    test "wipes and removes expired consume candidates while preserving live consume candidates",
         ctx do
      expired = stage_candidate(ctx, "expired-consume", completion_mode: :consume)
      live = stage_candidate(ctx, "live-consume", completion_mode: :consume)

      expired
      |> Ecto.Changeset.change(
        expires_at: DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)
      )
      |> Repo.update!()

      queries =
        capture_queries(fn -> assert {:ok, 1} = Tango.cleanup_expired_authorizations() end)

      assert_queries_are_credential_free(queries)
      refute Repo.get(Authorization, expired.id)
      assert Repo.get!(Authorization, live.id) == live
      assert Repo.aggregate(Connection, :count) == 0
    end

    test "deletes expired and consumed candidates and keeps live ones", ctx do
      live = stage_candidate(ctx, "live")
      expired = stage_candidate(ctx, "expired")
      consumed = stage_candidate(ctx, "consumed")
      past = DateTime.add(DateTime.utc_now(), -60, :second) |> DateTime.truncate(:second)

      expired |> Ecto.Changeset.change(%{expires_at: past}) |> Repo.update!()

      consumed
      |> Ecto.Changeset.change(%{
        consumed_at: DateTime.utc_now() |> DateTime.truncate(:second),
        access_token: nil,
        refresh_token: nil
      })
      |> Repo.update!()

      assert {:ok, 2} = Tango.cleanup_expired_authorizations()

      assert Repo.get(Authorization, live.id)
      refute Repo.get(Authorization, expired.id)
      refute Repo.get(Authorization, consumed.id)
      assert {:ok, 0} = Tango.cleanup_expired_authorizations()
    end

    test "wipes token columns before deleting an unconsumed expired candidate", ctx do
      expired = stage_candidate(ctx, "expired")
      past = DateTime.add(DateTime.utc_now(), -60, :second) |> DateTime.truncate(:second)
      expired |> Ecto.Changeset.change(%{expires_at: past}) |> Repo.update!()

      test_pid = self()
      handler = "cleanup-order-#{System.unique_integer([:positive])}"

      :telemetry.attach(
        handler,
        [:tango, :test_repo, :query],
        fn _event, _measurements, %{query: query}, _config ->
          if String.contains?(query, "tango_authorizations"),
            do: send(test_pid, {:authorization_query, query})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler) end)

      assert {:ok, 1} = Tango.cleanup_expired_authorizations()

      statements = collect_authorization_queries([])

      wipe = Enum.find_index(statements, &(&1 =~ ~r/^UPDATE .*"access_token" = /))
      delete = Enum.find_index(statements, &(&1 =~ ~r/^DELETE /))

      assert is_integer(wipe), "expected a token-wiping UPDATE, got: #{inspect(statements)}"
      assert is_integer(delete), "expected a DELETE, got: #{inspect(statements)}"
      assert wipe < delete
    end

    test "records a safe audit entry and leaves connections and sessions alone", ctx do
      expired = stage_candidate(ctx, "expired")
      past = DateTime.add(DateTime.utc_now(), -60, :second) |> DateTime.truncate(:second)
      expired |> Ecto.Changeset.change(%{expires_at: past}) |> Repo.update!()

      connection = Factory.create_connection(ctx.provider, ctx.tenant)

      assert {:ok, 1} = Tango.cleanup_expired_authorizations()

      audit =
        Repo.one!(
          from(log in AuditLog,
            where: log.event_type == :session_expired,
            where: fragment("?->>'cleanup_type' = 'authorization_candidates'", log.event_data)
          )
        )

      assert audit.success
      assert audit.event_data["expired_authorizations_count"] == 1
      refute inspect(audit) =~ "candidate-access-secret"
      refute inspect(audit) =~ "candidate-refresh-secret"
      refute inspect(audit) =~ Base.url_encode64(expired.handle_hash, padding: false)

      assert Repo.get!(Connection, connection.id)
      assert Repo.get!(OAuthSession, expired.oauth_session_id)
    end

    test "does not write an audit entry when nothing was deleted", _ctx do
      assert {:ok, 0} = Tango.cleanup_expired_authorizations()

      assert Repo.aggregate(
               from(log in AuditLog,
                 where:
                   fragment("?->>'cleanup_type' = 'authorization_candidates'", log.event_data)
               ),
               :count
             ) == 0
    end

    test "documents the consumer scheduling contract" do
      {:docs_v1, _, _, _, _, _, docs} = Code.fetch_docs(Tango)

      assert {_, _, _, %{"en" => doc}, _} =
               Enum.find(docs, fn {{kind, name, arity}, _, _, _, _} ->
                 kind == :function and name == :cleanup_expired_authorizations and arity == 0
               end)

      assert doc =~ "Tango.cleanup_expired_sessions"
      assert doc =~ "schedule"
    end
  end

  # Collects every query event the Repo emits while `fun` runs. The `cast_params`
  # and `params` here are exactly what the Ecto query logger would print.
  defp capture_queries(fun) do
    test_pid = self()
    handler = "callback-queries-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler,
      [:tango, :test_repo, :query],
      fn _event, _measurements, metadata, _config ->
        send(test_pid, {:captured_query, Map.take(metadata, [:query, :params, :cast_params])})
      end,
      nil
    )

    try do
      fun.()
    after
      :telemetry.detach(handler)
    end

    drain_captured_queries([])
  end

  defp drain_captured_queries(acc) do
    receive do
      {:captured_query, query} -> drain_captured_queries([query | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp assert_queries_are_credential_free(queries) do
    refute queries == []

    sentinels = [
      @code,
      "candidate-access-secret",
      "candidate-refresh-secret",
      "stale-access-token",
      "stale-refresh-token"
    ]

    for query <- queries, sentinel <- sentinels do
      message = "#{sentinel} leaked through query metadata of: #{query.query}"

      # Handlers read the metadata as data, so inspect-level redaction is not enough.
      refute term_contains?(query, sentinel), message

      refute inspect(query, limit: :infinity, printable_limit: :infinity, structs: false) =~
               sentinel,
             message

      refute :binary.match(:erlang.term_to_binary(query), sentinel) != :nomatch, message
    end
  end

  # Walks maps, lists, tuples, and structs (as plain maps) looking for `needle`
  # inside any binary.
  defp term_contains?(term, needle) when is_binary(term), do: String.contains?(term, needle)

  defp term_contains?(term, needle) when is_struct(term),
    do: term |> Map.from_struct() |> term_contains?(needle)

  defp term_contains?(term, needle) when is_map(term),
    do:
      Enum.any?(term, fn {key, value} ->
        term_contains?(key, needle) or term_contains?(value, needle)
      end)

  defp term_contains?(term, needle) when is_list(term),
    do: Enum.any?(term, &term_contains?(&1, needle))

  defp term_contains?(term, needle) when is_tuple(term),
    do: term |> Tuple.to_list() |> term_contains?(needle)

  defp term_contains?(_term, _needle), do: false

  defp collect_authorization_queries(acc) do
    receive do
      {:authorization_query, query} -> collect_authorization_queries(acc ++ [query])
    after
      0 -> acc
    end
  end

  defp callback(params) do
    query =
      params |> Enum.map(fn {key, value} -> {to_string(key), value} end) |> URI.encode_query()

    conn(:get, "/callback?" <> query)
    |> Router.call(Router.init([]))
  end

  defp extract_payload(%Plug.Conn{resp_body: html}), do: extract_payload(html)

  defp extract_payload(html) do
    [_, json] = Regex.run(~r/const payload = (.+);\n/, html)
    Jason.decode!(json)
  end

  defp extract_origin(html) do
    [_, json] = Regex.run(~r/const completionOrigin = (.+);\n/, html)
    Jason.decode!(json)
  end

  defp assert_log_is_credential_free(log, state) do
    refute log =~ "candidate-access-secret"
    refute log =~ "candidate-refresh-secret"
    refute log =~ "denial-body-secret"
    refute log =~ "authcode"
    refute log =~ String.slice(state, 0, 20)
  end

  defp authorization_session(ctx, intent \\ "intent-1", opts \\ []) do
    {:ok, session} =
      Tango.create_authorization_session(
        ctx.provider.slug,
        ctx.tenant,
        Keyword.merge(
          [
            scopes: ["records.read", "records.write"],
            redirect_uri: @redirect_uri,
            completion_origin: @origin,
            intent_reference: intent
          ],
          opts
        )
      )

    session
  end

  defp legacy_state(ctx) do
    {:ok, session} =
      Tango.create_session(ctx.provider.slug, ctx.tenant, redirect_uri: @redirect_uri)

    {:ok, url} = Tango.authorize_url(session.session_token)
    state = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("state")
    {state, session}
  end

  defp encoded_state(session) do
    {:ok, url} = Tango.Auth.authorization_url(session)
    url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("state")
  end

  defp stage_candidate(ctx, intent, opts \\ []) do
    session = authorization_session(ctx, intent, opts)
    expect_token(ctx.bypass)

    {:ok, _completion} =
      Tango.stage_authorization(encoded_state(session), @code, ctx.tenant,
        redirect_uri: @redirect_uri
      )

    Repo.get_by!(Authorization, oauth_session_id: session.id)
  end

  defp expect_token(bypass, extra \\ %{}) do
    Bypass.expect_once(bypass, "POST", "/oauth/token", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(
        200,
        Jason.encode!(
          Map.merge(
            %{
              "access_token" => "candidate-access-secret",
              "refresh_token" => "candidate-refresh-secret",
              "token_type" => "Bearer",
              "expires_in" => 3600,
              "scope" => "records.read records.write"
            },
            extra
          )
        )
      )
    end)
  end

  defp expect_oauth_denial(bypass) do
    Bypass.expect_once(bypass, "POST", "/oauth/token", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(
        400,
        Jason.encode!(%{
          "error" => "invalid_grant",
          "error_description" => "denial-body-secret"
        })
      )
    end)
  end
end

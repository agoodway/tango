defmodule Tango.AuthorizationTest do
  use Tango.DatabaseCase, async: false

  import ExUnit.CaptureLog

  alias Ecto.Adapters.SQL
  alias Tango.Factory
  alias Tango.Schemas.{Authorization, Connection, OAuthSession}

  defmodule UpgradeVerifier do
    @behaviour Tango.AuthorizationVerifier

    @impl true
    def verify(_provider, %{access_token: "candidate-access-secret"}, opts) do
      {:ok,
       %{
         subject: "subject-1",
         claims: %{"label" => "Example"},
         continuity: {:connection, Keyword.fetch!(opts, :connection_id)}
       }}
    end
  end

  defmodule InitialVerifier do
    @behaviour Tango.AuthorizationVerifier

    @impl true
    def verify(_provider, %{access_token: "candidate-access-secret"}, _opts) do
      {:ok, %{subject: "subject-1", claims: %{"label" => "Example"}, continuity: :initial}}
    end
  end

  defmodule WrongInitialContinuityVerifier do
    @behaviour Tango.AuthorizationVerifier

    @impl true
    def verify(_provider, _credential, _opts) do
      {:ok, %{subject: "subject-1", claims: %{}, continuity: {:connection, -1}}}
    end
  end

  defmodule DirectVerifier do
    @behaviour Tango.AuthorizationVerifier

    @impl true
    def verify(_provider, %{access_token: access_token}, opts) when is_binary(access_token) do
      {:ok,
       %{
         subject: "subject-1",
         claims: %{"label" => "Example"},
         continuity: {:connection, Keyword.fetch!(opts, :connection_id)}
       }}
    end
  end

  defmodule FailingVerifier do
    @behaviour Tango.AuthorizationVerifier

    @impl true
    def verify(_provider, _credential, _opts), do: {:error, :invalid_identity}
  end

  defmodule TransientVerifier do
    @behaviour Tango.AuthorizationVerifier

    @impl true
    def verify(_provider, _credential, _opts), do: {:error, :network_error}
  end

  defmodule MismatchedVerifier do
    @behaviour Tango.AuthorizationVerifier

    @impl true
    def verify(_provider, _credential, opts) do
      {:ok,
       %{
         subject: "subject-2",
         claims: %{},
         continuity: {:connection, Keyword.fetch!(opts, :connection_id)}
       }}
    end
  end

  defmodule InvalidClaimsVerifier do
    @behaviour Tango.AuthorizationVerifier

    @impl true
    def verify(_provider, _credential, opts) do
      {:ok,
       %{
         subject: "subject-1",
         claims: %{"nested" => %{"access_token" => "must-not-survive"}},
         continuity: {:connection, Keyword.fetch!(opts, :connection_id)}
       }}
    end
  end

  setup do
    bypass = Bypass.open()
    previous_origins = Application.get_env(:tango, :allowed_completion_origins)
    Application.put_env(:tango, :allowed_completion_origins, ["https://app.example.test"])

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
          "display_name" => "Authorization Test",
          "client_id" => "authorization-client",
          "auth_url" => "http://localhost:#{bypass.port}/oauth/authorize",
          "token_url" => "http://localhost:#{bypass.port}/oauth/token"
        }
      })

    %{bypass: bypass, provider: provider, tenant: Factory.tenant_id("authorization")}
  end

  test "stage stores an opaque encrypted candidate without replacing the active connection",
       ctx do
    active = active_connection(ctx)
    session = authorization_session(ctx, active)
    state = encoded_state(session)
    expect_token(ctx.bypass)

    log =
      capture_log(fn ->
        assert {:ok, completion} =
                 Tango.stage_authorization(state, "single-use-code", ctx.tenant,
                   redirect_uri: session.redirect_uri
                 )

        assert byte_size(Base.url_decode64!(completion.completion_handle, padding: false)) == 32
        assert completion.intent_reference == session.intent_reference
        assert completion.completion_origin == session.completion_origin
        assert DateTime.diff(completion.expires_at, DateTime.utc_now()) in 598..600

        candidate = Repo.one!(Authorization)
        assert candidate.handle_hash == :crypto.hash(:sha256, completion.completion_handle)
        refute candidate.handle_hash == completion.completion_handle
        assert candidate.access_token == "candidate-access-secret"
        assert candidate.refresh_token == "candidate-refresh-secret"
        assert candidate.expected_connection_id == active.id
        assert candidate.granted_scopes == ["records.read", "records.write"]

        raw =
          SQL.query!(
            Repo,
            "SELECT access_token, refresh_token FROM tango_authorizations WHERE id = $1",
            [candidate.id]
          ).rows

        refute inspect(raw) =~ "candidate-access-secret"
        refute inspect(raw) =~ "candidate-refresh-secret"
      end)

    refute log =~ "candidate-access-secret"
    refute log =~ "candidate-refresh-secret"

    unchanged = Repo.get!(Connection, active.id)
    assert unchanged.id == active.id
    assert unchanged.access_token == active.access_token
    assert unchanged.status == :active
    assert Repo.aggregate(Connection, :count) == 1
  end

  test "stage is single-use and failed exchange consumes the session", ctx do
    session = authorization_session(ctx)
    state = encoded_state(session)
    expect_token(ctx.bypass)

    assert {:ok, _completion} =
             Tango.stage_authorization(state, "single-use-code", ctx.tenant,
               redirect_uri: session.redirect_uri
             )

    assert {:error, :invalid_session} =
             Tango.stage_authorization(state, "single-use-code", ctx.tenant,
               redirect_uri: session.redirect_uri
             )

    failed_session = authorization_session(ctx, nil, "intent-failed")
    failed_state = encoded_state(failed_session)
    expect_oauth_denial(ctx.bypass)

    denial_log =
      capture_log(fn ->
        assert {:error, {:oauth_error, :invalid_grant}} =
                 Tango.stage_authorization(failed_state, "denied-code", ctx.tenant,
                   redirect_uri: failed_session.redirect_uri
                 )
      end)

    refute denial_log =~ "denial-body-secret"
    refute denial_log =~ "denied-code"

    assert Repo.get!(OAuthSession, failed_session.id).exchanged_at

    assert {:error, :invalid_session} =
             Tango.stage_authorization(failed_state, "denied-code", ctx.tenant,
               redirect_uri: failed_session.redirect_uri
             )
  end

  test "stage rejects wrong tenant, redirect, expired session, and changed OAuth client", ctx do
    session = authorization_session(ctx)
    state = encoded_state(session)

    assert {:error, :invalid_session} =
             Tango.stage_authorization(state, "code", "wrong-tenant",
               redirect_uri: session.redirect_uri
             )

    assert {:error, :invalid_session} =
             Tango.stage_authorization(state, "code", ctx.tenant,
               redirect_uri: "https://api.example.test/other"
             )

    expired_state = encoded_state(session)

    expired =
      session
      |> Ecto.Changeset.change(%{
        expires_at: DateTime.add(DateTime.utc_now(), -1, :second) |> DateTime.truncate(:second)
      })
      |> Repo.update!()

    assert {:error, :invalid_session} =
             Tango.stage_authorization(expired_state, "code", ctx.tenant,
               redirect_uri: expired.redirect_uri
             )

    changed = authorization_session(ctx, nil, "intent-client")
    changed_state = encoded_state(changed)

    {:ok, _provider} =
      Tango.update_provider(ctx.provider, %{
        config: Map.put(ctx.provider.config, "client_id", "replacement-client")
      })

    assert {:error, :client_changed} =
             Tango.stage_authorization(changed_state, "code", ctx.tenant,
               redirect_uri: changed.redirect_uri
             )
  end

  test "stage does not invent granted scopes when token response omits scope", ctx do
    session = authorization_session(ctx)
    state = encoded_state(session)
    expect_token(ctx.bypass, Map.delete(token_response(), "scope"))

    assert {:ok, completion} =
             Tango.stage_authorization(state, "code", ctx.tenant,
               redirect_uri: session.redirect_uri
             )

    candidate = candidate_for_handle(completion.completion_handle)
    assert candidate.granted_scopes == []
  end

  test "verify persists safe identity proof and requires tenant, provider, and intent", ctx do
    active = active_connection(ctx)
    session = authorization_session(ctx, active)
    completion = stage(ctx, session)

    assert {:error, :invalid_completion} =
             Tango.verify_authorization(
               completion.completion_handle,
               "wrong-tenant",
               {UpgradeVerifier, []},
               intent_reference: session.intent_reference,
               provider: ctx.provider.slug
             )

    other_provider = Factory.create_provider()

    assert {:error, :invalid_completion} =
             Tango.verify_authorization(
               completion.completion_handle,
               ctx.tenant,
               {UpgradeVerifier, []},
               intent_reference: session.intent_reference,
               provider: other_provider.slug
             )

    assert {:error, :intent_mismatch} =
             Tango.verify_authorization(
               completion.completion_handle,
               ctx.tenant,
               {UpgradeVerifier, []},
               intent_reference: "superseded-intent",
               provider: ctx.provider.slug
             )

    assert {:ok, summary} =
             Tango.verify_authorization(
               completion.completion_handle,
               ctx.tenant,
               {UpgradeVerifier, caller_value: "server-owned"},
               intent_reference: session.intent_reference,
               provider: ctx.provider.slug
             )

    assert summary == %{
             provider: ctx.provider.slug,
             subject: "subject-1",
             claims: %{"label" => "Example"},
             granted_scopes: ["records.read", "records.write"],
             expected_connection_id: active.id,
             intent_reference: session.intent_reference,
             has_refresh_token: true
           }

    candidate = candidate_for_handle(completion.completion_handle)
    assert candidate.account_subject == "subject-1"
    assert candidate.identity_claims == %{"label" => "Example"}
    assert candidate.verified_connection_id == active.id
    assert candidate.verified_at
    refute candidate.consumed_at
  end

  test "terminal verification failures consume and wipe credentials", ctx do
    for {verifier, index} <-
          Enum.with_index([FailingVerifier, MismatchedVerifier, InvalidClaimsVerifier]) do
      verifier_ctx = %{ctx | tenant: "#{ctx.tenant}-#{index}"}
      active = active_connection(verifier_ctx, "#{index}")
      session = authorization_session(verifier_ctx, active, "intent-#{index}")
      completion = stage(verifier_ctx, session)

      assert {:error, _reason} =
               Tango.verify_authorization(
                 completion.completion_handle,
                 verifier_ctx.tenant,
                 {verifier, []},
                 intent_reference: session.intent_reference,
                 provider: verifier_ctx.provider.slug
               )

      candidate = candidate_for_handle(completion.completion_handle)
      assert candidate.consumed_at
      assert candidate.access_token == nil
      assert candidate.refresh_token == nil

      assert {:error, :completion_consumed} =
               Tango.verify_authorization(
                 completion.completion_handle,
                 verifier_ctx.tenant,
                 {verifier, []},
                 intent_reference: session.intent_reference,
                 provider: verifier_ctx.provider.slug
               )
    end
  end

  test "transient verifier failures remain retryable until candidate expiry", ctx do
    session = authorization_session(ctx)
    completion = stage(ctx, session)

    opts = [intent_reference: session.intent_reference, provider: ctx.provider.slug]

    assert {:error, :network_error} =
             Tango.verify_authorization(
               completion.completion_handle,
               ctx.tenant,
               {TransientVerifier, []},
               opts
             )

    candidate = candidate_for_handle(completion.completion_handle)
    refute candidate.consumed_at
    assert candidate.access_token == "candidate-access-secret"

    candidate
    |> Ecto.Changeset.change(%{
      expires_at: DateTime.add(DateTime.utc_now(), -1, :second) |> DateTime.truncate(:second)
    })
    |> Repo.update!()

    assert {:error, :expired_completion} =
             Tango.verify_authorization(
               completion.completion_handle,
               ctx.tenant,
               {InitialVerifier, []},
               opts
             )
  end

  test "initial and upgrade continuity proofs are enforced", ctx do
    initial_session = authorization_session(ctx)
    initial_completion = stage(ctx, initial_session)

    assert {:error, :account_mismatch} =
             Tango.verify_authorization(
               initial_completion.completion_handle,
               ctx.tenant,
               {WrongInitialContinuityVerifier, []},
               intent_reference: initial_session.intent_reference,
               provider: ctx.provider.slug
             )

    active = active_connection(ctx, "continuity")
    upgrade_session = authorization_session(ctx, active, "intent-continuity")
    upgrade_completion = stage(ctx, upgrade_session)

    assert {:error, :account_mismatch} =
             Tango.verify_authorization(
               upgrade_completion.completion_handle,
               ctx.tenant,
               {InitialVerifier, []},
               intent_reference: upgrade_session.intent_reference,
               provider: ctx.provider.slug
             )
  end

  test "verify_connection_identity binds only the exact active generation", ctx do
    connection =
      active_connection(ctx)
      |> Ecto.Changeset.change(%{account_subject: nil})
      |> Repo.update!()

    assert {:ok, %{subject: "subject-1", claims: %{"label" => "Example"}}} =
             Tango.verify_connection_identity(connection.id, ctx.tenant, {DirectVerifier, []})

    assert Repo.get!(Connection, connection.id).account_subject == "subject-1"

    assert {:error, :not_found} =
             Tango.verify_connection_identity(connection.id, "wrong-tenant", {DirectVerifier, []})

    connection
    |> Ecto.Changeset.change(%{status: :revoked})
    |> Repo.update!()

    assert {:error, :stale_connection} =
             Tango.verify_connection_identity(connection.id, ctx.tenant, {DirectVerifier, []})
  end

  defp active_connection(ctx, suffix \\ "default") do
    Factory.create_connection(ctx.provider, "#{ctx.tenant}-#{suffix}", %{
      "access_token" => "active-token-#{suffix}",
      "refresh_token" => "active-refresh-#{suffix}",
      "scope" => "records.read"
    })
    |> Ecto.Changeset.change(%{
      tenant_id: ctx.tenant,
      account_subject: "subject-1",
      oauth_client_id: ctx.provider.config["client_id"]
    })
    |> Repo.update!()
  end

  defp authorization_session(ctx, connection \\ nil, intent \\ "intent-1") do
    opts = [
      scopes: ["records.read", "records.write"],
      redirect_uri: "https://api.example.test/callback",
      completion_origin: "https://app.example.test",
      intent_reference: intent
    ]

    opts =
      if connection do
        Keyword.merge(opts,
          expected_connection_id: connection.id,
          expected_subject: connection.account_subject
        )
      else
        opts
      end

    {:ok, session} = Tango.create_authorization_session(ctx.provider.slug, ctx.tenant, opts)
    session
  end

  defp encoded_state(session) do
    {:ok, url} = Tango.Auth.authorization_url(session)
    url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("state")
  end

  defp stage(ctx, session) do
    expect_token(ctx.bypass)

    {:ok, completion} =
      Tango.stage_authorization(encoded_state(session), "code", ctx.tenant,
        redirect_uri: session.redirect_uri
      )

    completion
  end

  defp candidate_for_handle(handle) do
    Repo.get_by!(Authorization, handle_hash: :crypto.hash(:sha256, handle))
  end

  defp expect_token(bypass, response \\ token_response()) do
    Bypass.expect_once(bypass, "POST", "/oauth/token", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(response))
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

  defp token_response do
    %{
      "access_token" => "candidate-access-secret",
      "refresh_token" => "candidate-refresh-secret",
      "token_type" => "Bearer",
      "expires_in" => 3600,
      "scope" => "records.read records.write"
    }
  end
end

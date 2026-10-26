defmodule Tango.TokenResponseMetadataTest do
  use Tango.DatabaseCase, async: false

  alias Tango.{Factory, TokenResponseMetadata}
  alias Tango.Schemas.{Authorization, Connection}

  @origin "https://metadata.example.test"
  @callback_uri "https://metadata.example.test/api/oauth/callback"
  @metadata %{"token_response_metadata" => ["instance_url", "team.id"]}

  defmodule RecordingVerifier do
    @behaviour Tango.AuthorizationVerifier

    @impl true
    def verify(_provider, credential, opts) do
      send(Keyword.fetch!(opts, :test_pid), {:credential, credential})

      continuity =
        case Keyword.fetch(opts, :connection_id) do
          {:ok, id} -> {:connection, id}
          :error -> :initial
        end

      {:ok, %{subject: "subject-synthetic", claims: %{}, continuity: continuity}}
    end
  end

  defmodule RejectingVerifier do
    @behaviour Tango.AuthorizationVerifier

    @impl true
    def verify(_provider, _credential, _opts), do: {:error, :invalid_identity}
  end

  describe "extract/2" do
    test "retains configured scalar fields, reading dotted paths from nested objects" do
      params = %{
        "instance_url" => "https://instance.example.test",
        "team" => %{"id" => "T123", "name" => "Synthetic"},
        "is_sandbox" => false,
        "shard" => 7,
        "ratio" => 0.5,
        "unlisted" => "unretained"
      }

      metadata = %{
        "token_response_metadata" => ["instance_url", "team.id", "is_sandbox", "shard", "ratio"]
      }

      assert TokenResponseMetadata.extract(params, metadata) ==
               {:ok,
                %{
                  "instance_url" => "https://instance.example.test",
                  "team.id" => "T123",
                  "is_sandbox" => false,
                  "shard" => 7,
                  "ratio" => 0.5
                }}
    end

    test "skips absent, nil, non-scalar, and unreachable nested values" do
      params = %{
        "nil_value" => nil,
        "object" => %{"id" => "nested"},
        "list" => ["a"],
        "team" => "not-an-object"
      }

      fields = ["absent", "nil_value", "object", "list", "team.id", "object.missing"]

      assert TokenResponseMetadata.extract(params, %{"token_response_metadata" => fields}) ==
               {:ok, %{}}
    end

    test "skips secret-like field names even when configured" do
      params = %{
        "id_token" => "synthetic-id-token",
        "client_secret" => "synthetic-secret",
        "nangoWebhookSecret" => "synthetic-webhook-secret",
        "code" => "synthetic-code",
        "authorization" => "synthetic-authorization",
        "instance_url" => "https://instance.example.test"
      }

      assert TokenResponseMetadata.extract(params, %{
               "token_response_metadata" => Map.keys(params)
             }) == {:ok, %{"instance_url" => "https://instance.example.test"}}
    end

    test "returns an empty map when no fields are configured" do
      assert TokenResponseMetadata.extract(%{"instance_url" => "x"}, %{}) == {:ok, %{}}

      assert TokenResponseMetadata.extract(%{"instance_url" => "x"}, %{
               "token_response_metadata" => nil
             }) == {:ok, %{}}
    end

    test "rejects retained fields larger than 4 KiB of JSON" do
      metadata = %{"token_response_metadata" => ["instance_url"]}

      assert {:ok, _data} =
               TokenResponseMetadata.extract(
                 %{"instance_url" => String.duplicate("a", 4000)},
                 metadata
               )

      assert TokenResponseMetadata.extract(
               %{"instance_url" => String.duplicate("a", 4097)},
               metadata
             ) == {:error, :invalid_grant_metadata}
    end
  end

  describe "Tango.Validation.sensitive_key?/1" do
    test "matches credential-like names as strings or atoms" do
      for key <- [
            "access_token",
            "refresh_token",
            "id_token",
            "client_secret",
            "password",
            "passwd",
            "api_key",
            "apiKey",
            "session_token",
            "code_verifier",
            "Authorization",
            "set_cookie",
            "headers",
            "credentials",
            "private_key",
            "signing_key",
            "encryption_key",
            "signature",
            "client_assertion",
            "jwt",
            "nonce",
            "code",
            "auth_code",
            "team.code",
            :client_secret,
            :access_token
          ] do
        assert Tango.Validation.sensitive_key?(key), "expected #{inspect(key)} to be sensitive"
      end
    end

    test "leaves ordinary metadata names alone" do
      for key <- [
            "instance_url",
            "team.id",
            "bot_user_id",
            "workspace_id",
            "zipcode",
            "encoded",
            :region,
            42
          ] do
        refute Tango.Validation.sensitive_key?(key), "expected #{inspect(key)} to be allowed"
      end
    end

    test "validate_metadata removes only credential keys" do
      assert Tango.Validation.validate_metadata(%{
               "id_token" => "x",
               :client_secret => "y",
               "token_type" => "bearer",
               "label" => "kept"
             }) == {:ok, %{"token_type" => "bearer", "label" => "kept"}}
    end
  end

  describe "staged authorization" do
    setup do
      original = Application.get_env(:tango, :allowed_completion_origins)
      Application.put_env(:tango, :allowed_completion_origins, [@origin])
      on_exit(fn -> Application.put_env(:tango, :allowed_completion_origins, original) end)
      bypass = Bypass.open()

      provider =
        Factory.create_provider(%{
          client_secret: "synthetic-client-secret",
          default_scopes: ["records:write"],
          metadata: @metadata,
          config: %{
            "client_id" => "client-synthetic",
            "auth_url" => "http://localhost:#{bypass.port}/authorize",
            "token_url" => "http://localhost:#{bypass.port}/token"
          }
        })

      %{bypass: bypass, provider: provider, tenant: Factory.tenant_id("metadata")}
    end

    test "the verifier receives retained provider_data; consumption clears it", ctx do
      expect_exchange(ctx.bypass, token_response())
      {session, state} = session(ctx)
      assert {:ok, %{completion_handle: handle}} = stage(ctx, state)

      candidate = Repo.get_by!(Authorization, oauth_session_id: session.id)

      assert candidate.provider_data == %{
               "instance_url" => "https://instance.example.test",
               "team.id" => "T123"
             }

      assert candidate.access_token == "synthetic-access-token"

      assert {:ok, %{subject: "subject-synthetic"}} = verify(ctx, handle)

      assert_received {:credential,
                       %{
                         access_token: "synthetic-access-token",
                         granted_scopes: ["records:write"],
                         provider_data: %{
                           "instance_url" => "https://instance.example.test",
                           "team.id" => "T123"
                         }
                       }}

      assert {:ok, %{metadata: %{connection: connection}}} = finalize(ctx, handle)
      assert connection.access_token == "synthetic-access-token"
      assert connection.refresh_token == "synthetic-refresh-token"
      refute Map.has_key?(Map.from_struct(connection), :provider_data)

      consumed = Repo.get!(Authorization, candidate.id)
      assert consumed.consumed_at
      assert consumed.provider_data == %{}
      assert is_nil(consumed.access_token)
    end

    test "a provider without token_response_metadata hands the verifier an empty map", ctx do
      {:ok, provider} = Tango.update_provider(ctx.provider, %{metadata: %{}})
      ctx = %{ctx | provider: provider}
      expect_exchange(ctx.bypass, token_response())
      {session, state} = session(ctx)
      assert {:ok, %{completion_handle: handle}} = stage(ctx, state)
      assert Repo.get_by!(Authorization, oauth_session_id: session.id).provider_data == %{}
      assert {:ok, _identity} = verify(ctx, handle)
      assert_received {:credential, %{provider_data: provider_data}}
      assert provider_data == %{}
    end

    test "a failed verification consumes the candidate and clears provider_data", ctx do
      expect_exchange(ctx.bypass, token_response())
      {session, state} = session(ctx)
      assert {:ok, %{completion_handle: handle}} = stage(ctx, state)

      assert {:error, :invalid_identity} =
               Tango.verify_authorization(handle, ctx.tenant, {RejectingVerifier, []},
                 provider: ctx.provider.slug,
                 intent_reference: "metadata-intent"
               )

      candidate = Repo.get_by!(Authorization, oauth_session_id: session.id)
      assert candidate.consumed_at
      assert candidate.provider_data == %{}
    end

    test "expired candidate cleanup clears provider_data before deleting", ctx do
      expect_exchange(ctx.bypass, token_response())
      {session, state} = session(ctx)
      assert {:ok, _completion} = stage(ctx, state)

      Repo.get_by!(Authorization, oauth_session_id: session.id)
      |> Ecto.Changeset.change(expires_at: DateTime.utc_now() |> DateTime.truncate(:second))
      |> Repo.update!()

      handler = "metadata-cleanup-#{System.unique_integer([:positive])}"
      pid = self()

      :telemetry.attach(
        handler,
        [:tango, :test_repo, :query],
        fn _, _, metadata, _ -> send(pid, {:query, metadata.query}) end,
        nil
      )

      try do
        assert {:ok, 1} = Tango.cleanup_expired_authorizations()
      after
        :telemetry.detach(handler)
      end

      assert_received {:query, "UPDATE " <> _ = wipe}
      assert wipe =~ "provider_data"
      assert Repo.aggregate(Authorization, :count) == 0
    end

    test "oversized retained metadata fails the exchange without staging", ctx do
      expect_exchange(
        ctx.bypass,
        Map.put(token_response(), "instance_url", String.duplicate("a", 5000))
      )

      {_session, state} = session(ctx)
      assert {:error, {:oauth_error, :invalid_grant_metadata}} = stage(ctx, state)
      assert Repo.aggregate(Authorization, :count) == 0
    end

    test "re-authorizing the same subject replaces the generation", ctx do
      expect_exchange(ctx.bypass, token_response())
      {_session, state} = session(ctx)
      assert {:ok, %{completion_handle: handle}} = stage(ctx, state)
      assert {:ok, _identity} = verify(ctx, handle)
      assert {:ok, %{metadata: %{connection: first}}} = finalize(ctx, handle)
      assert_received {:credential, _first_credential}

      expect_exchange(
        ctx.bypass,
        Map.merge(token_response(), %{
          "access_token" => "synthetic-access-token-2",
          "instance_url" => "https://instance-2.example.test"
        })
      )

      {_session, state} = session(ctx, first)
      assert {:ok, %{completion_handle: handle}} = stage(ctx, state)
      assert {:ok, %{subject: "subject-synthetic"}} = verify(ctx, handle)

      assert_received {:credential,
                       %{
                         access_token: "synthetic-access-token-2",
                         provider_data: %{"instance_url" => "https://instance-2.example.test"}
                       }}

      assert {:ok, %{metadata: %{connection: second}}} =
               finalize(ctx, handle, expected_connection_id: first.id)

      assert second.id != first.id
      assert second.access_token == "synthetic-access-token-2"
      assert Repo.get!(Connection, first.id).status == :revoked
      assert Repo.get!(Connection, second.id).status == :active
    end

    test "verify_connection_identity hands the verifier an empty provider_data", ctx do
      expect_exchange(ctx.bypass, token_response())
      {_session, state} = session(ctx)
      assert {:ok, %{completion_handle: handle}} = stage(ctx, state)
      assert {:ok, _identity} = verify(ctx, handle)
      assert {:ok, %{metadata: %{connection: connection}}} = finalize(ctx, handle)
      assert_received {:credential, _staged_credential}

      assert {:ok, %{subject: "subject-synthetic"}} =
               Tango.verify_connection_identity(
                 connection.id,
                 ctx.tenant,
                 {RecordingVerifier, test_pid: self()}
               )

      assert_received {:credential,
                       %{
                         access_token: "synthetic-access-token",
                         granted_scopes: ["records:write"],
                         provider_data: provider_data
                       }}

      assert provider_data == %{}
    end

    test "the legacy direct exchange ignores token_response_metadata", ctx do
      expect_exchange(ctx.bypass, token_response())

      {:ok, session} =
        Tango.create_session(ctx.provider.slug, ctx.tenant, redirect_uri: @callback_uri)

      {:ok, url} = Tango.authorize_url(session.session_token, redirect_uri: @callback_uri)

      state =
        url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("state")

      assert {:ok, connection} =
               Tango.exchange_code(state, "synthetic-code", ctx.tenant,
                 redirect_uri: @callback_uri
               )

      assert connection.access_token == "synthetic-access-token"
    end
  end

  test "schema tokens are redacted from inspect output" do
    for struct <- [
          %Authorization{
            access_token: "synthetic-inspect-a",
            refresh_token: "synthetic-inspect-r"
          },
          %Connection{access_token: "synthetic-inspect-a", refresh_token: "synthetic-inspect-r"}
        ] do
      output = inspect(struct)
      refute output =~ "synthetic-inspect-a"
      refute output =~ "synthetic-inspect-r"
    end
  end

  defp token_response,
    do: %{
      "access_token" => "synthetic-access-token",
      "refresh_token" => "synthetic-refresh-token",
      "token_type" => "bearer",
      "expires_in" => 3600,
      "scope" => "records:write",
      "instance_url" => "https://instance.example.test",
      "team" => %{"id" => "T123", "name" => "Synthetic team"},
      "id_token" => "synthetic-id-token"
    }

  defp expect_exchange(bypass, response) do
    Bypass.expect_once(bypass, "POST", "/token", fn conn ->
      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.resp(200, Jason.encode!(response))
    end)
  end

  defp session(ctx, connection \\ nil) do
    opts = [
      scopes: ["records:write"],
      redirect_uri: @callback_uri,
      completion_origin: @origin,
      intent_reference: "metadata-intent"
    ]

    opts =
      if connection,
        do:
          Keyword.merge(opts,
            expected_connection_id: connection.id,
            expected_subject: connection.account_subject
          ),
        else: opts

    {:ok, session} = Tango.create_authorization_session(ctx.provider.slug, ctx.tenant, opts)
    {:ok, url} = Tango.Auth.authorization_url(session)
    params = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    {session, params["state"]}
  end

  defp stage(ctx, state),
    do:
      Tango.stage_authorization(state, "synthetic-code", ctx.tenant, redirect_uri: @callback_uri)

  defp verify(ctx, handle),
    do:
      Tango.verify_authorization(handle, ctx.tenant, {RecordingVerifier, test_pid: self()},
        provider: ctx.provider.slug,
        intent_reference: "metadata-intent"
      )

  defp finalize(ctx, handle, opts \\ []) do
    Ecto.Multi.new()
    |> Tango.multi_finalize_authorization(
      :metadata,
      handle,
      ctx.tenant,
      Keyword.merge([provider: ctx.provider.slug, intent_reference: "metadata-intent"], opts)
    )
    |> Repo.transaction()
  end
end

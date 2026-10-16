defmodule Tango.AuthorizationSessionTest do
  use Tango.DatabaseCase, async: false

  alias Tango.Auth
  alias Tango.Factory

  setup do
    bypass = Bypass.open()
    previous_origins = Application.get_env(:tango, :allowed_completion_origins)

    Application.put_env(
      :tango,
      :allowed_completion_origins,
      ["https://app.example.test", "http://localhost:4000"]
    )

    on_exit(fn ->
      if previous_origins do
        Application.put_env(:tango, :allowed_completion_origins, previous_origins)
      else
        Application.delete_env(:tango, :allowed_completion_origins)
      end
    end)

    provider =
      Factory.create_google_provider("_#{bypass.port}",
        urls: %{
          "auth_url" => "http://localhost:#{bypass.port}/oauth/authorize",
          "token_url" => "http://localhost:#{bypass.port}/oauth/token"
        }
      )

    {:ok, provider} =
      Tango.update_provider(provider, %{default_scopes: ["provider.default"]})

    %{provider: provider, tenant: Factory.tenant_id("authorization"), bypass: bypass}
  end

  test "session scopes and parameters remain authoritative after provider changes", %{
    provider: provider,
    tenant: tenant
  } do
    assert {:ok, session} =
             Tango.create_authorization_session(provider.slug, tenant,
               scopes: ["records.read"],
               redirect_uri: "https://api.example.test/callback",
               completion_origin: "https://app.example.test",
               intent_reference: "intent-1",
               auth_params: %{"prompt" => "consent"}
             )

    assert session.scopes == ["records.read"]
    assert session.oauth_client_id == provider.config["client_id"]
    assert session.auth_params == %{"prompt" => "consent"}

    {:ok, _provider} =
      Tango.update_provider(provider, %{default_scopes: ["provider.changed"]})

    assert {:ok, url} = Auth.authorization_url(session)
    query = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    assert query["scope"] == "records.read"
    assert query["prompt"] == "consent"
    assert query["client_id"] == session.oauth_client_id

    assert {:ok, legacy_url} =
             Auth.authorize_url(session.session_token,
               redirect_uri: session.redirect_uri,
               scopes: ["attempted.override"]
             )

    legacy_query = legacy_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert legacy_query["scope"] == "records.read"
  end

  test "legacy sessions leave scopes unbound so authorize_url can supply them", %{
    provider: provider,
    tenant: tenant
  } do
    assert {:ok, session} =
             Tango.create_session(provider.slug, tenant,
               redirect_uri: "https://api.example.test/callback"
             )

    assert session.scopes == []

    assert {:ok, url} =
             Auth.authorize_url(session.session_token,
               redirect_uri: "https://api.example.test/callback",
               scopes: ["legacy.override"]
             )

    query = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["scope"] == "legacy.override"

    assert {:ok, default_url} =
             Auth.authorize_url(session.session_token,
               redirect_uri: "https://api.example.test/callback"
             )

    default_query = default_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert default_query["scope"] == "provider.default"
  end

  test "rejects reserved caller authorization parameters", %{
    provider: provider,
    tenant: tenant
  } do
    for reserved <-
          ~w(state redirect_uri client_id response_type scope code_challenge code_challenge_method) do
      assert {:error, :reserved_auth_parameter} =
               Tango.create_authorization_session(provider.slug, tenant,
                 scopes: ["records.read"],
                 redirect_uri: "https://api.example.test/callback",
                 completion_origin: "https://app.example.test",
                 intent_reference: "intent-#{reserved}",
                 auth_params: %{reserved => "caller-value"}
               )
    end
  end

  test "completion origins must be configured exact origins", %{
    provider: provider,
    tenant: tenant
  } do
    invalid_origins = [
      "*",
      "https://app.example.test/path",
      "https://app.example.test?query=1",
      "https://app.example.test#fragment",
      "http://app.example.test",
      "https://other.example.test"
    ]

    for origin <- invalid_origins do
      assert {:error, :invalid_completion_origin} =
               Tango.create_authorization_session(provider.slug, tenant,
                 scopes: ["records.read"],
                 redirect_uri: "https://api.example.test/callback",
                 completion_origin: origin,
                 intent_reference: "intent-origin"
               )
    end

    Application.put_env(
      :tango,
      :allowed_completion_origins,
      ["https://app.example.test", "http://localhost:4000", "https://*.example.test"]
    )

    assert {:error, :invalid_completion_origin} =
             Tango.create_authorization_session(provider.slug, tenant,
               scopes: ["records.read"],
               redirect_uri: "https://api.example.test/callback",
               completion_origin: "https://*.example.test",
               intent_reference: "intent-wildcard"
             )

    assert {:ok, session} =
             Tango.create_authorization_session(provider.slug, tenant,
               scopes: ["records.read"],
               redirect_uri: "https://api.example.test/callback",
               completion_origin: "http://localhost:4000",
               intent_reference: "intent-local"
             )

    assert session.completion_origin == "http://localhost:4000"
  end

  test "rejects explicit expiration beyond configured session maximum", %{
    provider: provider,
    tenant: tenant
  } do
    previous_timeout = Application.get_env(:tango, :session_timeout)
    Application.put_env(:tango, :session_timeout, 60)

    on_exit(fn ->
      if previous_timeout do
        Application.put_env(:tango, :session_timeout, previous_timeout)
      else
        Application.delete_env(:tango, :session_timeout)
      end
    end)

    assert {:error, :invalid_expiration} =
             Tango.create_authorization_session(provider.slug, tenant,
               scopes: ["records.read"],
               redirect_uri: "https://api.example.test/callback",
               completion_origin: "https://app.example.test",
               intent_reference: "intent-expiration",
               expires_at: DateTime.add(DateTime.utc_now(), 120, :second)
             )
  end

  test "expected connections are tenant/provider bound", %{
    provider: provider,
    tenant: tenant
  } do
    connection =
      provider
      |> Factory.create_connection(tenant)
      |> Ecto.Changeset.change(%{account_subject: "subject-1"})
      |> Repo.update!()

    assert {:ok, session} =
             Tango.create_authorization_session(provider.slug, tenant,
               scopes: ["records.read"],
               redirect_uri: "https://api.example.test/callback",
               completion_origin: "https://app.example.test",
               intent_reference: "intent-upgrade",
               expected_connection_id: connection.id,
               expected_subject: "subject-1"
             )

    assert session.expected_connection_id == connection.id
    assert session.expected_subject == "subject-1"

    assert {:error, :account_mismatch} =
             Tango.create_authorization_session(provider.slug, tenant,
               scopes: ["records.read"],
               redirect_uri: "https://api.example.test/callback",
               completion_origin: "https://app.example.test",
               intent_reference: "intent-wrong-subject",
               expected_connection_id: connection.id,
               expected_subject: "subject-2"
             )

    assert {:error, :stale_connection} =
             Tango.create_authorization_session(provider.slug, Factory.tenant_id("other"),
               scopes: ["records.read"],
               redirect_uri: "https://api.example.test/callback",
               completion_origin: "https://app.example.test",
               intent_reference: "intent-wrong-owner",
               expected_connection_id: connection.id,
               expected_subject: "subject-1"
             )
  end

  test "expected connections reject revoked and superseded expired generations", %{
    provider: provider,
    tenant: tenant
  } do
    revoked =
      provider
      |> Factory.create_connection(tenant)
      |> Ecto.Changeset.change(%{status: :revoked, account_subject: "subject-1"})
      |> Repo.update!()

    assert {:error, :stale_connection} =
             authorization_session(provider, tenant, revoked.id, "revoked")

    expired_tenant = "#{tenant}-expired"

    expired =
      provider
      |> Factory.create_connection(expired_tenant)
      |> Ecto.Changeset.change(%{status: :expired, account_subject: "subject-1"})
      |> Repo.update!()

    assert {:ok, _session} =
             authorization_session(provider, expired_tenant, expired.id, "expired")

    _replacement =
      provider
      |> Factory.create_connection(expired_tenant)
      |> Ecto.Changeset.change(%{account_subject: "subject-1"})
      |> Repo.update!()

    assert {:error, :stale_connection} =
             authorization_session(provider, expired_tenant, expired.id, "superseded")
  end

  defp authorization_session(provider, tenant, expected_connection_id, intent_suffix) do
    Tango.create_authorization_session(provider.slug, tenant,
      scopes: ["records.read"],
      redirect_uri: "https://api.example.test/callback",
      completion_origin: "https://app.example.test",
      intent_reference: "intent-#{intent_suffix}",
      expected_connection_id: expected_connection_id,
      expected_subject: "subject-1"
    )
  end
end

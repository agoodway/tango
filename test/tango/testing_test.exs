defmodule Tango.TestingTest do
  use Tango.DatabaseCase, async: false

  import ExUnit.CaptureLog

  alias Ecto.Adapters.SQL
  alias Tango.Testing

  test "provider defaults are unique and overrideable" do
    first = Testing.insert_provider!()
    second = Testing.insert_provider!()

    assert first.id != second.id
    assert first.slug != second.slug
    assert first.name != second.name
    assert first.default_scopes == ["records.read"]
    assert second.default_scopes == ["records.read"]
    assert is_binary(first.client_secret) and first.client_secret != ""
    assert first.client_secret != second.client_secret
    assert example_test_endpoint?(first.config["auth_url"], "/authorize")
    assert example_test_endpoint?(first.config["token_url"], "/token")
    assert example_test_endpoint?(second.config["auth_url"], "/authorize")
    assert first.config["auth_url"] != second.config["auth_url"]
    assert first.config["token_url"] != second.config["token_url"]
    assert is_binary(first.config["client_id"]) and first.config["client_id"] != ""
    assert first.config["client_id"] != second.config["client_id"]

    suffix = System.unique_integer([:positive])
    name = "custom_name_#{suffix}"
    slug = "custom_slug_#{suffix}"
    custom = Testing.insert_provider!(%{name: name, slug: slug})

    assert custom.name == name
    assert custom.slug == slug
    assert custom.default_scopes == ["records.read"]
    assert example_test_endpoint?(custom.config["auth_url"], "/authorize")

    assert {:ok, loaded} = Tango.get_provider_by_id(custom.id)
    assert loaded.slug == slug
    assert loaded.name == name
    assert loaded.config["client_id"] == custom.config["client_id"]
    assert loaded.client_secret == custom.client_secret
  end

  test "connections preserve explicit nullable fields" do
    provider = Testing.insert_provider!()
    tenant = unique_tenant("nullable")
    expires_at = DateTime.utc_now() |> DateTime.truncate(:second)

    omitted =
      Testing.insert_connection!(provider, tenant, %{
        status: :expired,
        refresh_token: nil,
        granted_scopes: nil,
        account_subject: nil,
        expires_at: nil
      })

    assert is_binary(omitted.access_token) and omitted.access_token != ""
    assert omitted.refresh_token == nil
    assert omitted.granted_scopes == nil
    assert omitted.account_subject == nil
    assert omitted.expires_at == nil
    assert omitted.status == :expired
    assert omitted.oauth_client_id == provider.config["client_id"]

    revoked =
      Testing.insert_connection!(provider, tenant, %{
        status: :revoked,
        access_token: "access-kept",
        refresh_token: "refresh-kept",
        granted_scopes: ["records.write"],
        account_subject: "subject-kept",
        expires_at: expires_at
      })

    assert revoked.access_token == "access-kept"
    assert revoked.refresh_token == "refresh-kept"
    assert revoked.granted_scopes == ["records.write"]
    assert revoked.account_subject == "subject-kept"
    assert revoked.expires_at == expires_at
    assert revoked.status == :revoked

    active = Testing.insert_connection!(provider, tenant)

    assert active.status == :active
    assert active.granted_scopes == ["records.read"]
    assert active.oauth_client_id == provider.config["client_id"]
    assert is_binary(active.access_token) and active.access_token != ""
    assert is_binary(active.refresh_token) and active.refresh_token != ""
    assert active.access_token != omitted.access_token
    assert active.refresh_token != revoked.refresh_token

    for connection <- [omitted, revoked, active] do
      assert {:ok, info} = Tango.get_connection_info(connection.id, tenant)
      assert info.id == connection.id
      assert info.status == connection.status
      assert info.tenant_id == tenant
      assert info.provider_slug == provider.slug
      assert info.account_subject == connection.account_subject
      assert info.granted_scopes == connection.granted_scopes
      assert info.expires_at == connection.expires_at
    end

    log =
      capture_log(fn ->
        assert_raise Ecto.InvalidChangesetError, fn ->
          Testing.insert_connection!(provider, tenant, %{access_token: nil})
        end
      end)

    assert log == ""
  end

  test "routing arguments cannot be overridden" do
    provider = Testing.insert_provider!()
    other = Testing.insert_provider!()
    tenant = unique_tenant("routing")
    decoy = unique_tenant("decoy")

    connection =
      Testing.insert_connection!(provider, tenant, %{
        provider_id: other.id,
        tenant_id: decoy,
        oauth_client_id: "caller-client"
      })

    assert connection.provider_id == provider.id
    assert connection.tenant_id == tenant
    assert connection.oauth_client_id == "caller-client"

    assert {:ok, info} = Tango.get_connection_info(connection.id, tenant)
    assert info.provider_slug == provider.slug
    assert info.tenant_id == tenant
    assert Tango.get_connection_info(connection.id, decoy) == {:error, :not_found}
  end

  test "fixtures obey encryption and constraints" do
    provider = Testing.insert_provider!()
    tenant = unique_tenant("encrypt")

    sentinel =
      "sentinel-access-" <> Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)

    {connection, events, log} =
      capture_write(fn ->
        Testing.insert_connection!(provider, tenant, %{access_token: sentinel})
      end)

    assert connection.access_token == sentinel

    assert {:ok, info} = Tango.get_connection_info(connection.id, tenant)
    assert info.id == connection.id
    assert info.status == :active
    assert info.provider_slug == provider.slug

    %{rows: [[stored]]} =
      SQL.query!(Repo, "SELECT access_token FROM tango_connections WHERE id = $1", [connection.id])

    assert is_binary(stored)
    assert :binary.match(stored, sentinel) == :nomatch
    refute Enum.any?(events, &(inspect(&1) =~ sentinel))
    refute log =~ sentinel

    assert_raise Ecto.ConstraintError, ~r/tango_connections_provider_id_tenant_id_index/, fn ->
      Testing.insert_connection!(provider, tenant)
    end
  end

  defp example_test_endpoint?(url, suffix) when is_binary(url) do
    uri = URI.parse(url)
    uri.scheme == "https" and uri.host == "example.test" and String.ends_with?(uri.path, suffix)
  end

  defp example_test_endpoint?(_url, _suffix), do: false

  defp unique_tenant(prefix), do: "#{prefix}_#{System.unique_integer([:positive])}"

  defp capture_write(fun) do
    test_pid = self()
    handler = "testing-queries-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler,
      [:tango, :test_repo, :query],
      fn _event, _measurements, metadata, _config ->
        send(test_pid, {:testing_query, Map.take(metadata, [:query, :params, :cast_params])})
      end,
      nil
    )

    try do
      log =
        capture_log(fn ->
          send(test_pid, {:testing_result, fun.()})
        end)

      result =
        receive do
          {:testing_result, result} -> result
        after
          0 -> flunk("insert did not return")
        end

      {result, drain_queries([]), log}
    after
      :telemetry.detach(handler)
    end
  end

  defp drain_queries(acc) do
    receive do
      {:testing_query, query} -> drain_queries([query | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end

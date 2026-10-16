defmodule Demo.GithubConnectTest do
  use Demo.DataCase, async: false

  alias Demo.GithubFlow
  alias Tango.Schemas.{Authorization, Connection}

  @tenant "demo-user-1"

  setup do
    GithubFlow.use_req_test()
    GithubFlow.stub_github()
    bypass = Bypass.open()
    GithubFlow.create_provider(bypass)
    %{bypass: bypass}
  end

  test "a staged handle is verified, finalized, and becomes the active connection", %{
    bypass: bypass
  } do
    %{handle: handle, intent_reference: intent} = GithubFlow.stage(bypass, @tenant)

    assert {:ok, %Connection{} = connection} =
             Demo.GithubConnect.complete(handle, intent, @tenant)

    assert connection.status == :active
    assert connection.account_subject == "42"
    assert connection.tenant_id == @tenant
    assert connection.granted_scopes == ["user:email", "repo"]
    assert connection.access_token == GithubFlow.access_token()
    assert connection.refresh_token == GithubFlow.refresh_token()

    assert {:ok, active} = Tango.get_connection_for_provider("github", @tenant)
    assert active.id == connection.id

    candidate = Repo.one!(Authorization)
    assert candidate.consumed_at
    assert candidate.access_token == nil
    assert candidate.refresh_token == nil
  end

  test "a consumed handle cannot connect twice", %{bypass: bypass} do
    %{handle: handle, intent_reference: intent} = GithubFlow.stage(bypass, @tenant)

    assert {:ok, _connection} = Demo.GithubConnect.complete(handle, intent, @tenant)
    assert {:error, _reason} = Demo.GithubConnect.complete(handle, intent, @tenant)
    assert Repo.aggregate(Connection, :count) == 1
  end

  test "another tenant cannot complete the handle", %{bypass: bypass} do
    %{handle: handle, intent_reference: intent} = GithubFlow.stage(bypass, @tenant)

    assert {:error, _reason} = Demo.GithubConnect.complete(handle, intent, "other-tenant")
    assert Repo.aggregate(Connection, :count) == 0
  end

  test "an intent that differs from the session's connects nothing", %{bypass: bypass} do
    %{handle: handle} = GithubFlow.stage(bypass, @tenant)

    assert {:error, _reason} = Demo.GithubConnect.complete(handle, "different-intent", @tenant)
    assert Repo.aggregate(Connection, :count) == 0
  end

  test "reconnecting the same GitHub account replaces the active connection", %{bypass: bypass} do
    %{handle: first_handle, intent_reference: first_intent} = GithubFlow.stage(bypass, @tenant)
    {:ok, first} = Demo.GithubConnect.complete(first_handle, first_intent, @tenant)

    %{handle: second_handle, intent_reference: second_intent} =
      GithubFlow.stage(bypass, @tenant,
        expected_connection_id: first.id,
        expected_subject: first.account_subject
      )

    assert {:ok, second} =
             Demo.GithubConnect.complete(second_handle, second_intent, @tenant, first.id)

    assert second.id != first.id
    assert second.account_subject == "42"
    assert Repo.get!(Connection, first.id).status == :revoked
    assert {:ok, active} = Tango.get_connection_for_provider("github", @tenant)
    assert active.id == second.id
  end

  test "reconnecting as a different GitHub account is rejected", %{bypass: bypass} do
    %{handle: first_handle, intent_reference: first_intent} = GithubFlow.stage(bypass, @tenant)
    {:ok, first} = Demo.GithubConnect.complete(first_handle, first_intent, @tenant)

    GithubFlow.stub_github(99, "someone-else")

    %{handle: second_handle, intent_reference: second_intent} =
      GithubFlow.stage(bypass, @tenant,
        expected_connection_id: first.id,
        expected_subject: first.account_subject
      )

    assert {:error, _reason} =
             Demo.GithubConnect.complete(second_handle, second_intent, @tenant, first.id)

    assert Repo.get!(Connection, first.id).status == :active
    assert Repo.aggregate(Connection, :count) == 1
  end
end

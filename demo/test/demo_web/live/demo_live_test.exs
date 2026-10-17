defmodule DemoWeb.DemoLiveTest do
  use DemoWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias Demo.GithubFlow
  alias Tango.Schemas.Connection

  test "refresh outage retains the active generation and displays a safe failure" do
    provider = Tango.Testing.insert_provider!(%{slug: "github"})

    connection =
      Tango.Testing.insert_connection!(provider, "demo-user-1", %{account_subject: "42"})

    assert {:noreply, socket} =
             DemoWeb.DemoLive.handle_async(
               :fetch_github_profile,
               {:ok, {:error, {:refresh_failed, {:http_error, 503}}}},
               profile_socket()
             )

    assert socket.assigns.connected_provider == "github"
    assert socket.assigns.expected_connection_id == connection.id
    assert socket.assigns.expected_subject == "42"
    assert %Tango.ConnectionInfo{id: id} = socket.assigns.connection_details
    assert id == connection.id
    assert socket.assigns.loading_profile == false
    assert Phoenix.Flash.get(socket.assigns.flash, :error) =~ "http_error:503"
  end

  test "expired refresh credentials show reconnect instead of a connected button" do
    provider = Tango.Testing.insert_provider!(%{slug: "github"})
    Tango.Testing.insert_connection!(provider, "demo-user-1", %{status: :expired})

    assert {:noreply, socket} =
             DemoWeb.DemoLive.handle_async(
               :fetch_github_profile,
               {:ok, {:error, {:refresh_failed, {:oauth_error, :invalid_grant}}}},
               profile_socket()
             )

    assert socket.assigns.connected_provider == nil
    assert socket.assigns.expected_connection_id == nil
    assert socket.assigns.expected_subject == nil
    assert socket.assigns.connection_details == nil
    assert socket.assigns.loading_profile == false
    assert Phoenix.Flash.get(socket.assigns.flash, :error) =~ "oauth_error:invalid_grant"
  end

  defp profile_socket do
    %Phoenix.LiveView.Socket{}
    |> Phoenix.LiveView.clear_flash()
    |> Phoenix.Component.assign(%{
      tenant_id: "demo-user-1",
      connected_provider: "github",
      expected_connection_id: -1,
      expected_subject: "old-subject",
      loading_profile: true
    })
  end

  test "renders the connect button with no credential material", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/")

    assert html =~ ~s(phx-hook="TangoOAuth")
    assert html =~ "Connect GitHub"
    refute html =~ "access_token"
    refute html =~ "refresh_token"
  end

  test "a completion handle that cannot be verified connects nothing", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/")

    send(view.pid, {"oauth_connected", %{completion_handle: "bogus", intent_reference: "intent"}})

    html = render_async(view, 2_000)

    assert html =~ "OAuth connection could not be verified"
    assert html =~ "Connect GitHub"
    refute html =~ "Connected to GitHub"
  end

  describe "completing a staged authorization" do
    setup do
      GithubFlow.use_req_test()
      GithubFlow.stub_github()
      bypass = Bypass.open()
      GithubFlow.create_provider(bypass)
      %{bypass: bypass}
    end

    test "a valid handle connects GitHub and shows the profile without exposing tokens", %{
      conn: conn,
      bypass: bypass
    } do
      %{handle: handle, intent_reference: intent} = GithubFlow.stage(bypass, "demo-user-1")

      {:ok, view, _html} = live(conn, "/")
      Req.Test.allow(Demo.GithubClient, self(), view.pid)

      send(view.pid, {"oauth_connected", component_message(handle, intent)})

      # Completion starts the profile fetch only once it succeeds, so await both tasks.
      render_async(view, 2_000)
      html = render_async(view, 2_000)

      assert html =~ "Connected to GitHub"
      assert html =~ "@octocat"
      refute html =~ "could not be verified"
      refute html =~ GithubFlow.access_token()
      refute html =~ GithubFlow.refresh_token()

      assert {:ok, %Connection{status: :active, account_subject: "42"}} =
               Tango.get_connection_for_provider("github", "demo-user-1")
    end

    test "a handle for another tenant connects nothing", %{conn: conn, bypass: bypass} do
      %{handle: handle, intent_reference: intent} = GithubFlow.stage(bypass, "someone-else")

      {:ok, view, _html} = live(conn, "/")
      send(view.pid, {"oauth_connected", %{completion_handle: handle, intent_reference: intent}})

      html = render_async(view, 2_000)

      assert html =~ "OAuth connection could not be verified"
      refute html =~ "Connected to GitHub"
      assert {:error, _} = Tango.get_connection_for_provider("github", "demo-user-1")
    end
  end

  describe "callbacks that carry credentials" do
    @legacy_payloads [
      %{
        provider: "github",
        tenant_id: "demo-user-1",
        access_token: "gho_legacy_browser_token",
        refresh_token: "ghr_legacy_browser_token"
      },
      %{provider: "github", connection: %{access_token: "gho_legacy_browser_token"}},
      %{
        completion_handle: "handle",
        intent_reference: "intent",
        access_token: "gho_legacy_browser_token"
      }
    ]

    for index <- 0..(length(@legacy_payloads) - 1) do
      test "a callback message with access_token is rejected without connecting (#{index})", %{
        conn: conn
      } do
        payload = Enum.at(@legacy_payloads, unquote(index))
        {:ok, view, _html} = live(conn, "/")

        send(view.pid, {"oauth_connected", payload})
        html = render(view)

        assert Process.alive?(view.pid)
        assert html =~ "OAuth connection could not be verified"
        assert html =~ "Connect GitHub"
        refute html =~ "Connected to GitHub"
        refute html =~ "gho_legacy_browser_token"
        refute html =~ "ghr_legacy_browser_token"
        assert {:error, _} = Tango.get_connection_for_provider("github", "demo-user-1")
      end
    end

    test "a browser oauth_complete event carrying access_token is rejected by the component", %{
      conn: conn
    } do
      {:ok, view, _html} = live(conn, "/")

      view
      |> with_target("#github-oauth")
      |> render_hook("oauth_complete", %{
        "completion_handle" => "handle",
        "intent_reference" => "intent",
        "access_token" => "gho_legacy_browser_token"
      })

      html = render(view)

      assert Process.alive?(view.pid)
      refute html =~ "Connected to GitHub"
      refute html =~ "gho_legacy_browser_token"
      assert {:error, _} = Tango.get_connection_for_provider("github", "demo-user-1")
    end
  end

  defp component_message(handle, intent) do
    # The exact shape Tango.Live.OAuthComponent sends to its parent.
    %{
      provider: "github",
      tenant_id: "demo-user-1",
      completion_handle: handle,
      intent_reference: intent
    }
  end

  test "the demo completes connections from a handle, never a token" do
    source = File.read!(Path.expand("../../../lib/demo_web/live/demo_live.ex", __DIR__))

    assert source =~ "completion_handle"
    assert source =~ "Demo.GithubConnect.complete"
    refute source =~ ~r/%\{token: /
    refute source =~ "fetch_github_profile, token"
  end

  test "the tenant for completion comes from the socket, not the browser message" do
    source = File.read!(Path.expand("../../../lib/demo_web/live/demo_live.ex", __DIR__))

    assert source =~ "tenant_id = socket.assigns.tenant_id"
    refute source =~ ~r/"oauth_connected", %\{[^}]*tenant_id:/
  end
end

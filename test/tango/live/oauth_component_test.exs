defmodule Tango.Live.OAuthComponentTest do
  use Tango.DatabaseCase, async: false

  alias Tango.Factory
  alias Tango.Live.OAuthComponent
  alias Tango.Schemas.OAuthSession

  @origin "https://app.example.test"
  @callback_url "https://api.example.test/api/oauth/callback"

  setup do
    previous = Application.get_env(:tango, :allowed_completion_origins)
    Application.put_env(:tango, :allowed_completion_origins, [@origin])

    on_exit(fn ->
      if previous,
        do: Application.put_env(:tango, :allowed_completion_origins, previous),
        else: Application.delete_env(:tango, :allowed_completion_origins)
    end)

    provider =
      Factory.create_provider(%{
        default_scopes: ["records.read"],
        config: %{
          "display_name" => "Component Test",
          "client_id" => "component-client",
          "auth_url" => "https://provider.example.test/oauth/authorize",
          "token_url" => "https://provider.example.test/oauth/token"
        }
      })

    %{provider: provider, tenant: Factory.tenant_id("component")}
  end

  describe "connect" do
    test "browser event parameters cannot override the server completion policy", ctx do
      {:ok, socket} = mount_component(ctx)

      assert {:noreply, _socket} =
               OAuthComponent.handle_event(
                 "connect",
                 %{"completion_mode" => "consume", "expected_subject" => "browser-subject"},
                 socket
               )

      session = Repo.one!(OAuthSession)
      assert session.completion_mode == :connection
      assert session.expected_subject == nil
      assert session.expected_connection_id == nil
    end

    test "binds an authorization session to the origin, callback, and a fresh intent", ctx do
      {:ok, socket} = mount_component(ctx)

      {:noreply, socket} = OAuthComponent.handle_event("connect", %{}, socket)

      assert socket.assigns.connecting
      intent = socket.assigns.pending_intent
      assert is_binary(intent) and byte_size(intent) >= 16

      session = Repo.one!(OAuthSession)
      assert session.completion_origin == @origin
      assert session.intent_reference == intent
      assert session.redirect_uri == @callback_url
      assert session.tenant_id == ctx.tenant

      assert [["open_popup", payload]] = pushed_events(socket)
      assert payload.intent_reference == intent
      assert payload.callback_origin == "https://api.example.test"
      assert payload.url =~ "state="
      refute inspect(payload) =~ "token"
    end

    test "each click uses a new intent reference", ctx do
      {:ok, socket} = mount_component(ctx)
      {:noreply, first} = OAuthComponent.handle_event("connect", %{}, socket)
      {:noreply, second} = OAuthComponent.handle_event("connect", %{}, socket)

      refute first.assigns.pending_intent == second.assigns.pending_intent
    end

    test "reports an error when the completion origin is not allowed", ctx do
      {:ok, socket} = mount_component(ctx, completion_origin: "https://evil.example.test")

      {:noreply, socket} = OAuthComponent.handle_event("connect", %{}, socket)

      refute socket.assigns.connecting
      assert_received {"oauth_error", %{error: :invalid_completion_origin}}
      assert Repo.aggregate(OAuthSession, :count) == 0
    end
  end

  describe "oauth_complete" do
    test "hands only the opaque handle to the parent", ctx do
      {:ok, socket} = mount_component(ctx)
      {:noreply, socket} = OAuthComponent.handle_event("connect", %{}, socket)
      intent = socket.assigns.pending_intent

      {:noreply, socket} =
        OAuthComponent.handle_event(
          "oauth_complete",
          %{"completion_handle" => "opaque-handle", "intent_reference" => intent},
          socket
        )

      refute socket.assigns.connecting
      assert socket.assigns.pending_intent == nil

      assert_received {"oauth_connected", message}

      assert message == %{
               provider: ctx.provider.slug,
               tenant_id: ctx.tenant,
               completion_handle: "opaque-handle",
               intent_reference: intent
             }
    end

    test "ignores a stale completion without cancelling the in-flight flow", ctx do
      {:ok, socket} = mount_component(ctx)
      {:noreply, socket} = OAuthComponent.handle_event("connect", %{}, socket)
      intent = socket.assigns.pending_intent

      {:noreply, socket} =
        OAuthComponent.handle_event(
          "oauth_complete",
          %{"completion_handle" => "stale-handle", "intent_reference" => "other"},
          socket
        )

      assert socket.assigns.connecting
      assert socket.assigns.pending_intent == intent
      refute_received {"oauth_error", _}
      refute_received {"oauth_connected", _}

      {:noreply, socket} =
        OAuthComponent.handle_event(
          "oauth_complete",
          %{"completion_handle" => "opaque-handle", "intent_reference" => intent},
          socket
        )

      refute socket.assigns.connecting
      assert_received {"oauth_connected", %{completion_handle: "opaque-handle"}}
    end

    test "ignores a completion when no connect is pending", ctx do
      {:ok, socket} = mount_component(ctx)

      {:noreply, socket} =
        OAuthComponent.handle_event(
          "oauth_complete",
          %{"completion_handle" => "opaque-handle", "intent_reference" => "intent"},
          socket
        )

      refute socket.assigns.connecting
      refute_received {"oauth_error", _}
      refute_received {"oauth_connected", _}
    end

    test "never forwards legacy connection or token payloads", ctx do
      {:ok, socket} = mount_component(ctx)
      {:noreply, socket} = OAuthComponent.handle_event("connect", %{}, socket)

      for params <- [
            %{"connection" => %{"token" => "legacy-token", "provider" => "github"}},
            %{
              "completion_handle" => "h",
              "intent_reference" => socket.assigns.pending_intent,
              "token" => "legacy-token"
            },
            %{"completion_handle" => 1, "intent_reference" => socket.assigns.pending_intent}
          ] do
        {:noreply, _socket} = OAuthComponent.handle_event("oauth_complete", params, socket)

        assert_received {"oauth_error", %{error: :invalid_completion}}
        refute_received {"oauth_connected", _}
      end

      refute_received {:tango_log, %{message: "legacy-token"}}
    end
  end

  describe "oauth_error" do
    test "forwards only a stable category", ctx do
      {:ok, socket} = mount_component(ctx)
      {:noreply, socket} = OAuthComponent.handle_event("connect", %{}, socket)
      intent = socket.assigns.pending_intent

      {:noreply, finished} =
        OAuthComponent.handle_event(
          "oauth_error",
          %{"error" => "invalid_grant", "intent_reference" => intent},
          socket
        )

      refute finished.assigns.connecting
      assert finished.assigns.pending_intent == nil
      assert_received {"oauth_error", %{error: "invalid_grant"}}

      {:noreply, _socket} =
        OAuthComponent.handle_event(
          "oauth_error",
          %{
            "error" => "<b>free text with candidate-access-secret</b>",
            "intent_reference" => intent
          },
          socket
        )

      assert_received {"oauth_error", %{error: "oauth_failed"}}
    end

    test "ignores an error for another intent without cancelling the in-flight flow", ctx do
      {:ok, socket} = mount_component(ctx)
      {:noreply, socket} = OAuthComponent.handle_event("connect", %{}, socket)
      intent = socket.assigns.pending_intent

      for params <- [
            %{"error" => "access_denied", "intent_reference" => "other"},
            %{"error" => "access_denied"}
          ] do
        {:noreply, unchanged} = OAuthComponent.handle_event("oauth_error", params, socket)

        assert unchanged.assigns.connecting
        assert unchanged.assigns.pending_intent == intent
        refute_received {"oauth_error", _}
      end
    end

    test "ignores an error when no connect is pending", ctx do
      {:ok, socket} = mount_component(ctx)

      {:noreply, _socket} =
        OAuthComponent.handle_event(
          "oauth_error",
          %{"error" => "access_denied", "intent_reference" => "intent"},
          socket
        )

      refute_received {"oauth_error", _}
    end
  end

  defp mount_component(ctx, overrides \\ []) do
    assigns =
      Map.merge(
        %{
          id: "oauth",
          provider: ctx.provider.slug,
          tenant_id: ctx.tenant,
          callback_url: @callback_url,
          completion_origin: @origin
        },
        Map.new(overrides)
      )

    OAuthComponent.update(assigns, %Phoenix.LiveView.Socket{assigns: %{__changed__: %{}}})
  end

  defp pushed_events(socket) do
    socket.private.live_temp.push_events |> Enum.reverse()
  end
end

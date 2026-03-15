defmodule Tango.Live.OAuthComponent do
  @moduledoc """
  LiveComponent that encapsulates the OAuth connect flow.

  Handles session creation, authorization URL generation, and popup-based
  OAuth completion via JS hooks and postMessage.

  ## Usage

      <.live_component
        module={Tango.Live.OAuthComponent}
        id="github-oauth"
        provider="github"
        tenant_id="user-123"
        callback_url="http://localhost:4000/api/oauth/callback"
        on_connect="oauth_connected"
        on_error="oauth_error"
      />

  ## Required Assigns

  - `provider` — provider slug string (e.g. `"github"`)
  - `tenant_id` — tenant identifier string
  - `callback_url` — the URL where Tango's API Router handles callbacks

  ## Optional Assigns

  - `scopes` — list of scope strings (defaults to provider's default scopes)
  - `button_class` — CSS classes for the connect button
  - `button_label` — override button text (default: "Connect {Provider}")
  - `on_connect` — event name sent to parent on success (default: `"oauth_connected"`)
  - `on_error` — event name sent to parent on failure (default: `"oauth_error"`)

  ## Events Sent to Parent

  On success, sends `{on_connect, %{provider: ..., token: ..., scopes: ..., ...}}` via `send/2`.
  On error, sends `{on_error, %{error: reason}}` via `send/2`.
  """
  use Phoenix.LiveComponent

  require Logger

  @impl true
  def update(assigns, socket) do
    socket =
      socket
      |> assign(assigns)
      |> assign_new(:connecting, fn -> false end)
      |> assign_new(:scopes, fn -> [] end)
      |> assign_new(:button_class, fn -> "" end)
      |> assign_new(:button_label, fn -> nil end)
      |> assign_new(:on_connect, fn -> "oauth_connected" end)
      |> assign_new(:on_error, fn -> "oauth_error" end)

    {:ok, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id={@id} phx-hook="TangoOAuth" data-component-id={@id}>
      <button
        type="button"
        class={@button_class}
        phx-click="connect"
        phx-target={@myself}
        disabled={@connecting}
      >
        <%= if @connecting do %>
          Connecting...
        <% else %>
          <%= if assigns[:inner_block] && @inner_block != [] do %>
            {render_slot(@inner_block)}
          <% else %>
            {@button_label || "Connect #{String.capitalize(@provider)}"}
          <% end %>
        <% end %>
      </button>
    </div>
    """
  end

  @impl true
  def handle_event("connect", _params, socket) do
    %{provider: provider, tenant_id: tenant_id, callback_url: callback_url, scopes: scopes} =
      socket.assigns

    notify_parent(socket, :log, %{level: :info, message: "Starting OAuth flow for #{provider}..."})

    case Tango.create_session(provider, tenant_id) do
      {:ok, session} ->
        notify_parent(socket, :log, %{
          level: :info,
          message: "Session created, generating authorization URL..."
        })

        auth_opts =
          [redirect_uri: callback_url]
          |> maybe_add_scopes(scopes)

        case Tango.authorize_url(session.session_token, auth_opts) do
          {:ok, auth_url} ->
            notify_parent(socket, :log, %{
              level: :info,
              message: "Authorization URL ready, opening popup..."
            })

            socket =
              socket
              |> assign(:connecting, true)
              |> push_event("open_popup", %{url: auth_url})

            {:noreply, socket}

          {:error, reason} ->
            Logger.error("Tango OAuth authorize_url failed: #{inspect(reason)}")

            notify_parent(socket, :log, %{
              level: :error,
              message: "Failed to generate auth URL: #{inspect(reason)}"
            })

            send(self(), {socket.assigns.on_error, %{error: reason}})
            {:noreply, socket}
        end

      {:error, reason} ->
        Logger.error("Tango OAuth create_session failed: #{inspect(reason)}")

        notify_parent(socket, :log, %{
          level: :error,
          message: "Failed to create session: #{inspect(reason)}"
        })

        send(self(), {socket.assigns.on_error, %{error: reason}})
        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("oauth_complete", %{"connection" => connection_data}, socket) do
    notify_parent(socket, :log, %{level: :success, message: "OAuth flow completed successfully!"})

    send(self(), {socket.assigns.on_connect, normalize_connection(connection_data)})

    {:noreply, assign(socket, :connecting, false)}
  end

  @impl true
  def handle_event("oauth_error", %{"error" => error}, socket) do
    notify_parent(socket, :log, %{level: :error, message: "OAuth error: #{error}"})
    send(self(), {socket.assigns.on_error, %{error: error}})
    {:noreply, assign(socket, :connecting, false)}
  end

  @impl true
  def handle_event("popup_closed", _params, socket) do
    if socket.assigns.connecting do
      notify_parent(socket, :log, %{
        level: :warning,
        message: "Popup was closed before completing OAuth flow"
      })
    end

    {:noreply, assign(socket, :connecting, false)}
  end

  defp maybe_add_scopes(opts, []), do: opts
  defp maybe_add_scopes(opts, scopes) when is_list(scopes), do: Keyword.put(opts, :scopes, scopes)

  defp normalize_connection(data) when is_map(data) do
    %{
      provider: data["provider"],
      token: data["token"],
      status: data["status"],
      scopes: data["scopes"] || [],
      expires_at: data["expires_at"]
    }
  end

  defp notify_parent(socket, :log, log_data) do
    send(self(), {:tango_log, Map.put(log_data, :component_id, socket.assigns.id)})
  end
end

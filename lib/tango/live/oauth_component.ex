defmodule Tango.Live.OAuthComponent do
  @moduledoc """
  LiveComponent that encapsulates the OAuth connect flow.

  Creates an authorization session bound to a completion origin and a fresh
  intent reference, opens the provider's consent page in a popup, and receives
  the callback result via a JS hook and postMessage.

  The browser only ever sees an opaque, short-lived completion handle. The
  component never receives, forwards, or displays an access or refresh token.
  On success it hands the handle to the parent LiveView, which finishes the flow
  on the server with `Tango.verify_authorization/4` and
  `Tango.multi_finalize_authorization/5`, using the tenant from its own
  authenticated assigns.

  ## Usage

      <.live_component
        module={Tango.Live.OAuthComponent}
        id="github-oauth"
        provider="github"
        tenant_id="user-123"
        callback_url="http://localhost:4000/api/oauth/callback"
        completion_origin="http://localhost:4000"
        on_connect="oauth_connected"
        on_error="oauth_error"
      />

  ## Required Assigns

  - `provider` — provider slug string (e.g. `"github"`)
  - `tenant_id` — tenant identifier string
  - `callback_url` — the URL where Tango's API Router handles callbacks
  - `completion_origin` — exact origin of the page hosting this component
    (e.g. `"https://app.example.com"`). It must be listed in
    `config :tango, :allowed_completion_origins`; the callback page posts to
    this origin only.

  ## Optional Assigns

  - `scopes` — list of scope strings (defaults to provider's default scopes)
  - `intent_reference` — opaque reference that ties the completion to the
    action that started it (defaults to a random value per click)
  - `expected_connection_id` / `expected_subject` — set when reauthorizing an
    existing connection
  - `auth_params` — extra provider authorization parameters
  - `button_class` — CSS classes for the connect button
  - `button_label` — override button text (default: "Connect {Provider}")
  - `on_connect` — event name sent to parent on success (default: `"oauth_connected"`)
  - `on_error` — event name sent to parent on failure (default: `"oauth_error"`)

  ## Events Sent to Parent

  On success, sends `{on_connect, %{provider: ..., tenant_id: ..., completion_handle: ...,
  intent_reference: ...}}` via `send/2`. The handle is not a credential, but it is
  single-use and must be completed by trusted server code.

  On error, sends `{on_error, %{error: reason}}` via `send/2`, where `reason` is
  a stable category and never a provider response.

  Completion and error messages for any intent other than the pending one are
  ignored, so a stale or replayed message cannot cancel the flow in flight.
  """
  use Phoenix.LiveComponent

  require Logger

  @impl true
  def update(assigns, socket) do
    socket =
      socket
      |> assign(assigns)
      |> assign_new(:connecting, fn -> false end)
      |> assign_new(:pending_intent, fn -> nil end)
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
    %{provider: provider} = socket.assigns

    notify_parent(socket, :log, %{level: :info, message: "Starting OAuth flow for #{provider}..."})

    intent_reference = socket.assigns[:intent_reference] || generate_intent_reference()

    with {:ok, session} <-
           Tango.create_authorization_session(
             provider,
             socket.assigns.tenant_id,
             session_options(socket.assigns, intent_reference)
           ),
         {:ok, auth_url} <- Tango.Auth.authorization_url(session) do
      notify_parent(socket, :log, %{
        level: :info,
        message: "Authorization URL ready, opening popup..."
      })

      socket =
        socket
        |> assign(:connecting, true)
        |> assign(:pending_intent, intent_reference)
        |> push_event("open_popup", %{
          url: auth_url,
          intent_reference: intent_reference,
          callback_origin: Tango.Validation.origin(socket.assigns.callback_url)
        })

      {:noreply, socket}
    else
      {:error, reason} ->
        Logger.error("Tango OAuth connect failed: #{inspect(reason)}")

        notify_parent(socket, :log, %{
          level: :error,
          message: "Failed to start OAuth flow: #{inspect(reason)}"
        })

        send(self(), {socket.assigns.on_error, %{error: reason}})
        {:noreply, assign(socket, :connecting, false)}
    end
  end

  @impl true
  def handle_event(
        "oauth_complete",
        %{"completion_handle" => handle, "intent_reference" => reference} = params,
        socket
      )
      when is_binary(handle) and handle != "" and is_binary(reference) and
             map_size(params) == 2 do
    case socket.assigns.pending_intent do
      ^reference ->
        notify_parent(socket, :log, %{
          level: :success,
          message: "OAuth consent completed, awaiting server verification."
        })

        send(self(), {socket.assigns.on_connect, completion_message(socket, handle, reference)})

        {:noreply, finish(socket)}

      _other ->
        ignore_stale_message(socket, "oauth_complete")
    end
  end

  @impl true
  def handle_event("oauth_complete", _params, socket),
    do: reject_completion(socket, :invalid_completion)

  @impl true
  def handle_event("oauth_error", params, socket) do
    if pending_intent?(socket, params["intent_reference"]) do
      category = error_category(params)
      notify_parent(socket, :log, %{level: :error, message: "OAuth error: #{category}"})
      send(self(), {socket.assigns.on_error, %{error: category}})
      {:noreply, finish(socket)}
    else
      ignore_stale_message(socket, "oauth_error")
    end
  end

  @impl true
  def handle_event("popup_closed", _params, socket) do
    if socket.assigns.connecting do
      notify_parent(socket, :log, %{
        level: :warning,
        message: "Popup was closed before completing OAuth flow"
      })
    end

    {:noreply, finish(socket)}
  end

  defp session_options(assigns, intent_reference) do
    [
      redirect_uri: assigns.callback_url,
      completion_origin: assigns[:completion_origin],
      intent_reference: intent_reference
    ]
    |> maybe_put(:scopes, assigns.scopes, &(&1 != []))
    |> maybe_put(:expected_connection_id, assigns[:expected_connection_id])
    |> maybe_put(:expected_subject, assigns[:expected_subject])
    |> maybe_put(:auth_params, assigns[:auth_params])
  end

  defp maybe_put(opts, key, value, keep? \\ &(!is_nil(&1))) do
    if keep?.(value), do: Keyword.put(opts, key, value), else: opts
  end

  defp completion_message(socket, handle, reference) do
    %{
      provider: socket.assigns.provider,
      tenant_id: socket.assigns.tenant_id,
      completion_handle: handle,
      intent_reference: reference
    }
  end

  defp reject_completion(socket, reason) do
    notify_parent(socket, :log, %{
      level: :error,
      message: "Rejected OAuth completion: #{reason}"
    })

    send(self(), {socket.assigns.on_error, %{error: reason}})
    {:noreply, finish(socket)}
  end

  defp pending_intent?(socket, reference) do
    pending = socket.assigns.pending_intent
    is_binary(pending) and pending == reference
  end

  # A message for another intent is stale, replayed, or from a flow this
  # component no longer tracks. It must not cancel the flow in flight, so it is
  # dropped without touching pending state or notifying the parent.
  defp ignore_stale_message(socket, event) do
    Logger.debug("Tango OAuth ignored #{event} for a non-pending intent")
    {:noreply, socket}
  end

  defp finish(socket) do
    socket
    |> assign(:connecting, false)
    |> assign(:pending_intent, nil)
  end

  # Browser-supplied categories are shown only when they look like a stable
  # snake_case code; anything else collapses to a generic category.
  defp error_category(%{"error" => error}) when is_binary(error) do
    if Regex.match?(~r/\A[a-z][a-z0-9_]{0,63}\z/, error), do: error, else: "oauth_failed"
  end

  defp error_category(_params), do: "oauth_failed"

  defp generate_intent_reference do
    :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
  end

  defp notify_parent(socket, :log, log_data) do
    send(self(), {:tango_log, Map.put(log_data, :component_id, socket.assigns.id)})
  end
end

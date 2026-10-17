defmodule DemoWeb.DemoLive do
  use DemoWeb, :live_view

  use Tango.Live.Components

  import DemoWeb.TangoLogsComponent
  require Ecto.Query

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:tenant_id, "demo-user-1")
      |> assign(:github_user, nil)
      |> assign(:github_repos, [])
      |> assign(:connected_provider, nil)
      |> assign(:audit_logs, [])
      |> assign(:connection_details, nil)
      |> assign(:expected_connection_id, nil)
      |> assign(:expected_subject, nil)
      |> assign(:loading_profile, false)
      |> assign(:page_title, "Tango Demo")
      |> assign_expected_connection()

    {:ok, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-base-200 p-6 lg:p-10">
      <div class="max-w-6xl mx-auto">
        <div class="text-center mb-8">
          <h1 class="text-4xl font-bold tracking-tight">💃 Tango OAuth Demo</h1>
          <p class="text-base-content/60 mt-2">
            <a
              href="https://github.com/agoodway/tango"
              target="_blank"
              class="link link-primary font-medium"
            >
              Tango
            </a>
            handles the OAuth dance between third-party services and Phoenix.
          </p>
        </div>

        <%= if error = Phoenix.Flash.get(@flash, :error) do %>
          <div role="alert" class="alert alert-error mb-6">
            <span>{error}</span>
          </div>
        <% end %>

        <div class="grid lg:grid-cols-3 gap-6">
          <%!-- Left Panel: Connect --%>
          <div class="space-y-6">
            <div class="card bg-base-100 shadow-md">
              <div class="card-body">
                <div>
                  <%= if @connected_provider do %>
                    <button
                      type="button"
                      class="btn btn-lg w-full gap-3 border-none text-base font-medium btn-success text-white"
                      disabled
                    >
                      <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 16 16">
                        <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
                      </svg>
                      Connected to GitHub
                    </button>
                  <% else %>
                    <.live_component
                      module={OAuthComponent}
                      id="github-oauth"
                      provider="github"
                      tenant_id={@tenant_id}
                      scopes={Demo.GithubConnect.scopes()}
                      callback_url={callback_url()}
                      completion_origin={completion_origin()}
                      expected_connection_id={@expected_connection_id}
                      expected_subject={@expected_subject}
                      on_connect="oauth_connected"
                      on_error="oauth_error"
                      button_class="btn btn-lg w-full gap-3 text-white border-none text-base font-medium [background-color:#24292e] hover:[background-color:#1b1f23]"
                    >
                      <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 16 16">
                        <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
                      </svg>
                      Connect GitHub
                    </.live_component>
                  <% end %>
                </div>
              </div>
            </div>
          </div>

          <%!-- Right Panel: Tango Logs + Profile + Repos --%>
          <div class="lg:col-span-2 space-y-6">
            <.tango_logs
              audit_logs={@audit_logs}
              connection={@connection_details}
            />

            <%!-- GitHub Profile Card --%>
            <div :if={@github_user} class="card bg-base-100 shadow-md">
              <div class="card-body items-center text-center">
                <div class="avatar">
                  <div class="w-20 rounded-full ring ring-primary ring-offset-base-100 ring-offset-2">
                    <img src={@github_user["avatar_url"]} alt={@github_user["login"]} />
                  </div>
                </div>
                <h3 class="card-title mt-3">{@github_user["name"] || @github_user["login"]}</h3>
                <p class="text-base-content/60">@{@github_user["login"]}</p>
                <p :if={@github_user["bio"]} class="text-sm mt-1">{@github_user["bio"]}</p>

                <div class="stats stats-horizontal shadow mt-4 text-center">
                  <div class="stat px-4 py-2">
                    <div class="stat-value text-lg">{@github_user["public_repos"]}</div>
                    <div class="stat-desc">Repos</div>
                  </div>
                  <div class="stat px-4 py-2">
                    <div class="stat-value text-lg">{@github_user["followers"]}</div>
                    <div class="stat-desc">Followers</div>
                  </div>
                  <div class="stat px-4 py-2">
                    <div class="stat-value text-lg">{@github_user["following"]}</div>
                    <div class="stat-desc">Following</div>
                  </div>
                </div>
              </div>
            </div>

            <%!-- Recent Repos --%>
            <div :if={@github_repos != []} class="card bg-base-100 shadow-md">
              <div class="card-body">
                <h2 class="card-title text-lg">Recent Repositories</h2>
                <div class="divide-y divide-base-200">
                  <div :for={repo <- @github_repos} class="py-3 first:pt-0 last:pb-0">
                    <div class="flex items-start justify-between">
                      <div>
                        <a
                          href={repo["html_url"]}
                          target="_blank"
                          class="font-medium link link-primary"
                        >
                          {repo["name"]}
                        </a>
                        <p :if={repo["description"]} class="text-sm text-base-content/60 mt-0.5">
                          {repo["description"]}
                        </p>
                      </div>
                      <div class="flex items-center gap-3 text-sm text-base-content/50 shrink-0 ml-4">
                        <span :if={repo["language"]} class="badge badge-sm badge-outline">
                          {repo["language"]}
                        </span>
                        <span class="flex items-center gap-1">
                          <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 16 16">
                            <path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.75.75 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25z" />
                          </svg>
                          {repo["stargazers_count"]}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div :if={@loading_profile} class="flex justify-center py-8">
              <span class="loading loading-spinner loading-lg text-primary"></span>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # The component hands over an opaque completion handle. Verification and
  # finalization happen here on the server, scoped to this socket's tenant.
  # Both call GitHub, so they run in a task rather than blocking the LiveView.
  @impl true
  def handle_info({"oauth_connected", message}, socket) do
    case completion_params(message) do
      {:ok, handle, intent_reference} ->
        tenant_id = socket.assigns.tenant_id
        expected_connection_id = socket.assigns.expected_connection_id

        {:noreply,
         start_async(socket, :complete_connection, fn ->
           Demo.GithubConnect.complete(
             handle,
             intent_reference,
             tenant_id,
             expected_connection_id
           )
         end)}

      :error ->
        {:noreply, connection_not_verified(socket)}
    end
  end

  @impl true
  def handle_info({"oauth_error", %{error: _error}}, socket) do
    socket =
      socket
      |> load_tango_data()
      |> put_flash(:error, "OAuth connection failed")

    {:noreply, socket}
  end

  # OAuthComponent sends real-time log messages; we display DB audit logs instead
  @impl true
  def handle_info({:tango_log, _}, socket), do: {:noreply, socket}

  @impl true
  def handle_async(:complete_connection, {:ok, {:ok, connection}}, socket) do
    tenant_id = socket.assigns.tenant_id

    socket =
      socket
      |> assign(:connected_provider, Demo.GithubConnect.provider())
      |> assign(:loading_profile, true)
      |> load_tango_data()
      |> start_async(:fetch_github_profile, fn ->
        fetch_github_profile(connection.id, tenant_id)
      end)

    {:noreply, socket}
  end

  def handle_async(:complete_connection, _failed, socket),
    do: {:noreply, connection_not_verified(socket)}

  def handle_async(:fetch_github_profile, {:ok, {:ok, %{user: user, repos: repos}}}, socket) do
    socket =
      socket
      |> assign(:github_user, user)
      |> assign(:github_repos, repos)
      |> assign(:loading_profile, false)

    {:noreply, socket}
  end

  def handle_async(
        :fetch_github_profile,
        {:ok, {:error, {:refresh_failed, reason}}},
        socket
      ) do
    message = "GitHub token refresh failed (#{Tango.RefreshError.to_storage(reason)})"
    {:noreply, profile_connection_failed(socket, message)}
  end

  def handle_async(:fetch_github_profile, {:ok, {:error, :not_found}}, socket) do
    {:noreply, profile_connection_failed(socket, "GitHub connection is no longer active")}
  end

  def handle_async(:fetch_github_profile, _failed, socket) do
    socket =
      socket
      |> assign(:loading_profile, false)
      |> put_flash(:error, "Failed to fetch GitHub profile")

    {:noreply, socket}
  end

  defp connection_not_verified(socket) do
    socket
    |> load_tango_data()
    |> put_flash(:error, "OAuth connection could not be verified")
  end

  defp profile_connection_failed(socket, message) do
    socket
    |> load_tango_data()
    |> assign_expected_connection_info()
    |> assign_profile_connection_state()
    |> assign(:loading_profile, false)
    |> put_flash(:error, message)
  end

  defp assign_profile_connection_state(%{assigns: %{connection_details: nil}} = socket) do
    socket
    |> assign(:connected_provider, nil)
    |> assign(:github_user, nil)
    |> assign(:github_repos, [])
  end

  defp assign_profile_connection_state(socket) do
    assign(socket, :connected_provider, socket.assigns.connection_details.provider_slug)
  end

  defp fetch_github_profile(connection_id, tenant_id) do
    with {:ok, connection} <-
           Tango.get_active_connection(connection_id, tenant_id, auto_refresh: true) do
      Demo.GithubClient.fetch_profile(connection.access_token)
    end
  end

  @completion_keys [:provider, :tenant_id, :completion_handle, :intent_reference]

  # Accepts only the component's credential-free completion shape. A message
  # with any other key (such as access_token) is rejected before verification.
  defp completion_params(
         %{completion_handle: handle, intent_reference: intent_reference} = message
       )
       when is_binary(handle) and is_binary(intent_reference) do
    if Enum.all?(Map.keys(message), &(&1 in @completion_keys)),
      do: {:ok, handle, intent_reference},
      else: :error
  end

  defp completion_params(_message), do: :error

  defp load_tango_data(socket) do
    tenant_id = socket.assigns.tenant_id

    audit_logs =
      Ecto.Query.from(a in Tango.Schemas.AuditLog,
        where: a.tenant_id == ^tenant_id,
        order_by: [asc: a.occurred_at],
        limit: 20
      )
      |> Demo.Repo.all()
      |> deduplicate_logs()

    connection = active_connection_info(tenant_id)

    socket
    |> assign(:audit_logs, audit_logs)
    |> assign(:connection_details, connection)
  end

  defp deduplicate_logs(logs) do
    logs
    |> Enum.reject(&(&1.event_type == :token_refresh_failed))
    |> Enum.reduce(%{}, fn log, acc -> Map.put(acc, log.event_type, log) end)
    |> Map.values()
    |> Enum.sort_by(& &1.occurred_at)
  end

  defp assign_expected_connection(socket) do
    socket
    |> assign(:connection_details, active_connection_info(socket.assigns.tenant_id))
    |> assign_expected_connection_info()
  end

  defp assign_expected_connection_info(socket) do
    case socket.assigns.connection_details do
      %Tango.ConnectionInfo{} = connection ->
        socket
        |> assign(:expected_connection_id, connection.id)
        |> assign(:expected_subject, connection.account_subject)

      nil ->
        socket
        |> assign(:expected_connection_id, nil)
        |> assign(:expected_subject, nil)
    end
  end

  defp active_connection_info(tenant_id) do
    tenant_id
    |> Tango.list_connection_infos(provider_slug: Demo.GithubConnect.provider())
    |> List.first()
  end

  defp callback_url do
    DemoWeb.Endpoint.url() <> "/api/oauth/callback"
  end

  # Exact origin of this page; the callback page posts the completion here only.
  defp completion_origin, do: Tango.Validation.origin(DemoWeb.Endpoint.url())
end

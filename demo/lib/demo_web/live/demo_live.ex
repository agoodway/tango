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
      |> assign(:loading_profile, false)
      |> assign(:page_title, "Tango Demo")

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
            <a href="https://github.com/agoodway/tango" target="_blank" class="link link-primary font-medium">Tango</a>
            handles the OAuth dance between third-party services and Phoenix.
          </p>
        </div>

        <div class="grid lg:grid-cols-3 gap-6">
          <%!-- Left Panel: Connect --%>
          <div class="space-y-6">
            <div class="card bg-base-100 shadow-md">
              <div class="card-body">
                <div>
                  <%= if @connected_provider do %>
                    <button type="button" class="btn btn-lg w-full gap-3 border-none text-base font-medium btn-success text-white" disabled>
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
                      scopes={["user:email", "repo"]}
                      callback_url={callback_url()}
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

  @impl true
  def handle_info({"oauth_connected", %{token: token, provider: provider}}, socket) do
    socket =
      socket
      |> assign(:connected_provider, provider)
      |> assign(:loading_profile, true)
      |> load_tango_data()

    send(self(), {:fetch_github_profile, token})
    {:noreply, socket}
  end

  @impl true
  def handle_info({:fetch_github_profile, token}, socket) do
    case Demo.GithubClient.fetch_profile(token) do
      {:ok, %{user: user, repos: repos}} ->
        socket =
          socket
          |> assign(:github_user, user)
          |> assign(:github_repos, repos)
          |> assign(:loading_profile, false)

        {:noreply, socket}

      {:error, _reason} ->
        socket =
          socket
          |> assign(:loading_profile, false)
          |> put_flash(:error, "Failed to fetch GitHub profile")

        {:noreply, socket}
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

    connection =
      case Tango.get_connection_for_provider("github", tenant_id) do
        {:ok, conn} -> conn
        _ -> nil
      end

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

  defp callback_url do
    DemoWeb.Endpoint.url() <> "/api/oauth/callback"
  end
end

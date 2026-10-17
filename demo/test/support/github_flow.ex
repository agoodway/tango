defmodule Demo.GithubFlow do
  @moduledoc """
  Test support that drives the real Tango staging path against a local token
  endpoint, so demo tests exercise genuine candidates and completion handles.
  """

  @origin "http://localhost:4002"
  @redirect_uri "http://localhost:4002/api/oauth/callback"
  @access_token "gho_candidate_access_secret"
  @refresh_token "ghr_candidate_refresh_secret"

  def access_token, do: @access_token
  def refresh_token, do: @refresh_token

  @doc "Creates the GitHub provider with its token endpoint pointed at `bypass`."
  def create_provider(bypass) do
    Tango.Testing.insert_provider!(%{
      slug: Demo.GithubConnect.provider(),
      name: "GitHub",
      client_secret: "github-client-secret",
      default_scopes: Demo.GithubConnect.scopes(),
      config: %{
        "client_id" => "github-client-id",
        "auth_url" => "http://localhost:#{bypass.port}/login/oauth/authorize",
        "token_url" => "http://localhost:#{bypass.port}/login/oauth/access_token"
      }
    })
  end

  @doc """
  Authorizes through the token endpoint and returns the staged completion
  handle and its intent reference.
  """
  def stage(bypass, tenant_id, opts \\ []) do
    scope = Keyword.get(opts, :scope, "user:email,repo")

    intent_reference =
      Keyword.get(opts, :intent_reference, "intent-#{System.unique_integer([:positive])}")

    Bypass.expect_once(bypass, "POST", "/login/oauth/access_token", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(
        200,
        Jason.encode!(%{
          "access_token" => @access_token,
          "refresh_token" => @refresh_token,
          "token_type" => "bearer",
          "expires_in" => 3600,
          "scope" => scope
        })
      )
    end)

    session_opts =
      [
        scopes: Demo.GithubConnect.scopes(),
        redirect_uri: @redirect_uri,
        completion_origin: @origin,
        intent_reference: intent_reference
      ] ++ Keyword.take(opts, [:expected_connection_id, :expected_subject])

    {:ok, session} =
      Tango.create_authorization_session(Demo.GithubConnect.provider(), tenant_id, session_opts)

    {:ok, url} = Tango.Auth.authorization_url(session)
    state = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("state")

    {:ok, completion} =
      Tango.stage_authorization(state, "github-code-0123456789", tenant_id,
        redirect_uri: @redirect_uri
      )

    %{handle: completion.completion_handle, intent_reference: intent_reference}
  end

  @doc "Stubs the GitHub API with a fixed account."
  def stub_github(id \\ 42, login \\ "octocat") do
    Req.Test.stub(Demo.GithubClient, fn conn ->
      case conn.request_path do
        "/user" -> Req.Test.json(conn, %{"id" => id, "login" => login, "name" => "Octo Cat"})
        "/user/repos" -> Req.Test.json(conn, [])
      end
    end)
  end

  @doc "Routes `Demo.GithubClient` requests through `Req.Test` for the test run."
  def use_req_test do
    previous = Application.get_env(:demo, :github_req_options)
    Application.put_env(:demo, :github_req_options, plug: {Req.Test, Demo.GithubClient})

    ExUnit.Callbacks.on_exit(fn ->
      if previous,
        do: Application.put_env(:demo, :github_req_options, previous),
        else: Application.delete_env(:demo, :github_req_options)
    end)
  end
end

defmodule Demo.GithubClient do
  @moduledoc """
  Simple GitHub API client using Req.
  """

  @base_url "https://api.github.com"

  def fetch_profile(access_token) do
    headers = headers(access_token)

    with {:ok, user} <- fetch_user_with_headers(headers),
         {:ok, repos} <- fetch_repos(headers) do
      {:ok, %{user: user, repos: repos}}
    end
  end

  @doc """
  Fetches the authenticated GitHub user.

  Errors keep HTTP and transport failures distinct so callers can tell a
  rejected token from a GitHub outage: `{:error, {:http_status, status}}` or
  `{:error, {:transport, reason}}`.
  """
  def fetch_user(access_token), do: access_token |> headers() |> fetch_user_with_headers()

  # Extra Req options, e.g. `plug: {Req.Test, Demo.GithubClient}` in tests.
  defp req_options, do: Application.get_env(:demo, :github_req_options, [])

  defp headers(access_token) do
    [
      {"authorization", "Bearer #{access_token}"},
      {"accept", "application/vnd.github+json"},
      {"user-agent", "tango-demo"}
    ]
  end

  defp fetch_user_with_headers(headers) do
    case Req.get("#{@base_url}/user", [headers: headers] ++ req_options()) do
      {:ok, %{status: 200, body: body}} -> {:ok, body}
      {:ok, %{status: status}} -> {:error, {:http_status, status}}
      {:error, %Req.TransportError{reason: reason}} -> {:error, {:transport, reason}}
      {:error, exception} -> {:error, {:transport, exception}}
    end
  end

  defp fetch_repos(headers) do
    case Req.get(
           "#{@base_url}/user/repos",
           [headers: headers, params: [sort: "updated", per_page: 5]] ++ req_options()
         ) do
      {:ok, %{status: 200, body: body}} -> {:ok, body}
      {:ok, %{status: _status}} -> {:ok, []}
      {:error, _reason} -> {:ok, []}
    end
  end
end

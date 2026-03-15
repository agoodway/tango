defmodule Demo.GithubClient do
  @moduledoc """
  Simple GitHub API client using Req.
  """

  @base_url "https://api.github.com"

  def fetch_profile(access_token) do
    headers = [
      {"authorization", "Bearer #{access_token}"},
      {"accept", "application/vnd.github+json"},
      {"user-agent", "tango-demo"}
    ]

    with {:ok, user} <- fetch_user(headers),
         {:ok, repos} <- fetch_repos(headers) do
      {:ok, %{user: user, repos: repos}}
    end
  end

  defp fetch_user(headers) do
    case Req.get("#{@base_url}/user", headers: headers) do
      {:ok, %{status: 200, body: body}} -> {:ok, body}
      {:ok, %{status: status}} -> {:error, "GitHub API returned #{status}"}
      {:error, reason} -> {:error, "GitHub API request failed: #{inspect(reason)}"}
    end
  end

  defp fetch_repos(headers) do
    case Req.get("#{@base_url}/user/repos",
           headers: headers,
           params: [sort: "updated", per_page: 5]
         ) do
      {:ok, %{status: 200, body: body}} -> {:ok, body}
      {:ok, %{status: _status}} -> {:ok, []}
      {:error, _reason} -> {:ok, []}
    end
  end
end

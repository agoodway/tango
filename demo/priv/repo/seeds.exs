alias Demo.Repo

github_client_id = System.get_env("GITHUB_CLIENT_ID")
github_client_secret = System.get_env("GITHUB_CLIENT_SECRET")

if github_client_id && github_client_secret do
  case Tango.get_provider("github") do
    {:ok, _provider} ->
      IO.puts("GitHub provider already exists, skipping seed.")

    {:error, :not_found} ->
      {:ok, provider} =
        Tango.create_provider(%{
          slug: "github",
          name: "GitHub",
          config: %{
            "client_id" => github_client_id,
            "auth_url" => "https://github.com/login/oauth/authorize",
            "token_url" => "https://github.com/login/oauth/access_token",
            "auth_mode" => "OAUTH2"
          },
          client_secret: github_client_secret,
          default_scopes: ["user:email", "repo"]
        })

      IO.puts("Created GitHub provider: #{provider.slug}")
  end
else
  IO.puts("""
  Skipping GitHub provider seed.
  Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET env vars to create one.

  You can also create a provider manually:

      Tango.create_provider(%{
        slug: "github",
        name: "GitHub",
        config: %{
          "client_id" => "your_client_id",
          "auth_url" => "https://github.com/login/oauth/authorize",
          "token_url" => "https://github.com/login/oauth/access_token",
          "auth_mode" => "OAUTH2"
        },
        client_secret: "your_client_secret",
        default_scopes: ["user:email", "repo"]
      })
  """)
end

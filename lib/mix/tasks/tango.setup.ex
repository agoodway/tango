defmodule Mix.Tasks.Tango.Setup do
  @shortdoc "Generates an Ecto migration that installs Tango tables"

  @moduledoc """
  Generates an Ecto migration that installs Tango's schema (providers,
  connections, OAuth sessions, audit log) by calling `Tango.Migration.up/0`.

  ## Usage

      mix tango.setup
      mix tango.setup --repo MyApp.OtherRepo

  ## Options

    * `--repo` - Ecto repo module to install against. Defaults to the first
      entry in `config :my_app, ecto_repos: [...]`.

  The migration is written to the repo's configured priv dir (defaults to
  `priv/repo/migrations`), not a library-specific path.

  Then run:

      mix ecto.migrate
  """

  use Mix.Task

  @impl Mix.Task
  def run(args) do
    {opts, _, _} = OptionParser.parse(args, switches: [repo: :string])

    repo = resolve_repo(opts[:repo])
    migrations_path = Path.join(priv_path(repo), "migrations")
    File.mkdir_p!(migrations_path)

    timestamp = timestamp()
    filename = "#{timestamp}_install_tango.exs"
    full_path = Path.join(migrations_path, filename)

    File.write!(full_path, migration_content(repo))

    Mix.shell().info("Created migration: #{full_path}")
    Mix.shell().info("Run `mix ecto.migrate` to apply.")
  end

  defp resolve_repo(nil) do
    app = Mix.Project.config()[:app]

    case Application.get_env(app, :ecto_repos, []) do
      [repo] ->
        repo

      [repo | _] = repos ->
        Mix.shell().info(
          "Multiple repos configured (#{inspect(repos)}); using #{inspect(repo)}. " <>
            "Pass `--repo` to choose a specific one."
        )

        repo

      [] ->
        Mix.raise("No Ecto repos configured. Add `:ecto_repos` to your app config.")
    end
  end

  defp resolve_repo(repo_string) do
    Module.concat([repo_string])
  end

  defp priv_path(repo) do
    # Respect the repo's configured :priv option; fall back to "priv/repo".
    case repo.config()[:priv] do
      nil -> "priv/repo"
      priv when is_binary(priv) -> priv
    end
  rescue
    # Repo may not be loaded yet (rare) — fall back to the Phoenix default.
    _ -> "priv/repo"
  end

  defp timestamp do
    {{y, m, d}, {hh, mm, ss}} = :calendar.universal_time()

    :io_lib.format("~4..0B~2..0B~2..0B~2..0B~2..0B~2..0B", [y, m, d, hh, mm, ss])
    |> IO.iodata_to_binary()
  end

  defp migration_content(repo) do
    """
    defmodule #{inspect(repo)}.Migrations.InstallTango do
      @moduledoc "Installs Tango OAuth schema via `Tango.Migration`."
      use Ecto.Migration

      def up, do: Tango.Migration.up()
      def down, do: Tango.Migration.down()
    end
    """
  end
end

defmodule Mix.Tasks.Helpers.TaskHelper do
  @moduledoc """
  Helper functions for Tango Mix tasks.

  Provides utilities for starting required applications and dependencies
  in Mix task contexts.
  """

  @doc """
  Ensures all required applications and dependencies are started for Tango Mix tasks.

  This includes:
  - HTTP client dependencies (:req and its dependencies)
  - Tango application (for vault and other services)
  - Database repository (if configured)
  """
  def ensure_started do
    # Start required applications for HTTP requests
    Application.ensure_all_started(:req)
    Application.ensure_all_started(:tango)

    # Start the repo if configured and not already started
    ensure_repo_started()
  end

  @doc """
  Ensures HTTP-only dependencies are started for catalog operations.

  This includes:
  - HTTP client dependencies (:req and its dependencies)
  - Tango application (for vault and other services)

  Does not start database dependencies, making it safe for HTTP-only operations.
  """
  def ensure_http_started do
    # Start required applications for HTTP requests only
    Application.ensure_all_started(:req)
    # Start tango app but don't force repo startup
    Application.ensure_all_started(:tango)
  end

  @doc """
  Ensures the configured Ecto repository is started.

  Safe to call multiple times - handles already started repos gracefully.
  """
  def ensure_repo_started do
    repo = Application.get_env(:tango, :repo, Tango.Repo)

    case repo.start_link() do
      {:ok, _} -> :ok
      {:error, {:already_started, _}} -> :ok
      error -> error
    end
  end
end

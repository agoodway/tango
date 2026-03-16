defmodule Tango.MixProject do
  use Mix.Project

  @version "0.1.1"
  @source_url "https://github.com/agoodway/tango"

  def project do
    [
      app: :tango,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      aliases: aliases(),
      description: description(),
      package: package(),
      docs: docs(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_coverages: ["coveralls", "coveralls.detail", "coveralls.html"],
      dialyzer: [
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
      ]
    ]
  end

  def cli do
    [preferred_envs: [quality: :test]]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :ssl],
      mod: {Tango.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # Database and encryption
      {:postgrex, "~> 0.19", optional: true},
      {:ecto, "~> 3.13"},
      {:ecto_sql, "~> 3.13"},
      {:cloak_ecto, "~> 1.3"},
      {:plug, "~> 1.19"},

      # Optional Phoenix/LiveView for component library
      {:phoenix, "~> 1.7", optional: true},
      {:phoenix_live_view, "~> 1.1", optional: true},

      # Migration system
      {:ecto_evolver, "~> 0.1.0"},

      # JSON, YAML, and UUID
      {:jason, "~> 1.4"},
      {:yaml_elixir, "~> 2.12"},
      {:uuid, "~> 1.1"},

      # Clients and HTTP
      {:oauth2, "~> 2.1"},
      {:req, "~> 0.5"},

      # Utility libraries
      {:nimble_options, "~> 1.0"},
      {:telemetry, "~> 1.0"},

      # Development and testing dependencies
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:credo, "~> 1.7.17", only: [:dev, :test], runtime: false},
      {:ex_slop, "~> 0.2", only: [:dev, :test], runtime: false},
      {:ex_dna, "~> 1.2", only: [:dev, :test], runtime: false},
      {:doctor, "~> 0.22.0", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:bypass, "~> 2.1", only: :test}
    ]
  end

  # Compilation paths
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Aliases for common tasks
  defp aliases do
    [
      setup: ["deps.get"],
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"],
      "test.coverage": ["coveralls"],
      "test.coverage.html": ["coveralls.html"],
      quality: ["format --check-formatted", "credo --strict", "ex_dna", "doctor", "test"]
    ]
  end

  defp description do
    """
    OAuth integrations library for Phoenix applications.
    Drop-in OAuth support with PKCE, multi-tenant isolation, encrypted token storage,
    audit logging, and optional LiveView components. Compatible with Nango's provider catalog.
    """
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib assets priv .formatter.exs mix.exs README.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md"],
      source_url: @source_url
    ]
  end
end

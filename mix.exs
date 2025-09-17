defmodule Tango.MixProject do
  use Mix.Project

  def project do
    [
      app: :tango,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      aliases: aliases(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_coverages: [
        "coveralls",
        "coveralls.detail",
        "coveralls.html",
        "coveralls.github"
      ],
      dialyzer: [
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
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
      {:postgrex, "~> 0.17", optional: true},
      {:ecto, "~> 3.10"},
      {:ecto_sql, "~> 3.10"},
      {:cloak_ecto, "~> 1.3"},
      {:plug, "~> 1.15"},

      # JSON, YAML, and UUID
      {:jason, "~> 1.4"},
      {:yaml_elixir, "~> 2.11"},
      {:uuid, "~> 1.1"},

      # Clients and HTTP
      {:oauth2, "~> 2.1"},
      {:req, "~> 0.4"},

      # Utility libraries
      {:nimble_options, "~> 1.0"},
      {:telemetry, "~> 1.0"},

      # Development and testing dependencies
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
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
      quality: ["format --check-formatted", "credo --strict", "test"]
    ]
  end
end

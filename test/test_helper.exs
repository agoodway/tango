# Start the application
{:ok, _} = Application.ensure_all_started(:tango)

# Configure Ecto sandbox for test isolation
Ecto.Adapters.SQL.Sandbox.mode(Tango.TestRepo, :manual)

# Start ExUnit
ExUnit.start()

# Configure test settings
ExUnit.configure(
  exclude: [skip: true],
  timeout: 60_000,
  capture_log: true,
  max_failures: :infinity
)

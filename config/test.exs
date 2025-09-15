import Config

# Test-specific configuration for Tango library
config :tango,
  # Use a deterministic test encryption key (32 bytes)
  encryption_key: Base.decode64!("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU="),
  # API key for client authentication
  api_key: "lets-dance-the-tango",
  # Use test repo for library testing
  repo: Tango.TestRepo,
  ecto_repos: [Tango.TestRepo]

# Test database configuration
config :tango, Tango.TestRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "tango_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10,
  log: false,
  priv: "priv/ecto_migrations"

# Cloak configuration for encryption in tests
config :cloak, Tango.Vault,
  ciphers: [
    default:
      {Cloak.Ciphers.AES.GCM,
       tag: "AES.GCM.V1", key: Base.decode64!("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=")}
  ]

# Suppress ExUnit async warnings
config :ex_unit,
  capture_log: true

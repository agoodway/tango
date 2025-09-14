import Config

# Basic configuration for Tango library testing
config :tango,
  # Use a test encryption key (32 bytes)
  encryption_key: :crypto.strong_rand_bytes(32),
  # Suppress Ecto repo warnings in library context
  ecto_repos: []

# Import environment specific config
import_config "#{config_env()}.exs"

import Config

# Development configuration for Tango library
config :tango,
  # Use a dev encryption key (32 bytes)
  encryption_key: :crypto.strong_rand_bytes(32),
  # API key for client authentication
  api_key: "lets-dance-the-tango",
  # Development doesn't need repos configured
  ecto_repos: []

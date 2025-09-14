defmodule Tango.Factory do
  @moduledoc """
  Test data factory for creating test fixtures.

  Eliminates code duplication across test files and provides
  consistent test data patterns.
  """

  alias Tango.TestRepo, as: Repo
  alias Tango.Schemas.{AuditLog, Connection, OAuthSession, Provider}

  @doc """
  Creates a test provider with optional attributes override.

  ## Examples

      provider = Factory.create_provider()
      github_provider = Factory.create_provider(%{name: "github_custom"})
      
  """
  def create_provider(attrs \\ %{}) do
    default_suffix = System.unique_integer([:positive])

    default_attrs = %{
      name: "test_provider_#{default_suffix}",
      slug: "test_provider_#{default_suffix}",
      auth_mode: "oauth2",
      client_secret: "test_client_secret_#{default_suffix}",
      config: %{
        "display_name" => "Test Provider #{default_suffix}",
        "client_id" => "test_client_id_#{default_suffix}",
        "auth_url" => "https://example.com/oauth/authorize",
        "token_url" => "https://example.com/oauth/token"
      }
    }

    merged_attrs = Map.merge(default_attrs, attrs)
    changeset = Provider.changeset(%Provider{}, merged_attrs)
    {:ok, provider} = Repo.insert(changeset)
    provider
  end

  @doc """
  Creates a GitHub test provider.

  Options:
  - `:urls` - Map with "auth_url" and "token_url" keys to override default URLs
  """
  def create_github_provider(suffix \\ "", opts \\ []) do
    urls =
      Keyword.get(opts, :urls, %{
        "auth_url" => "https://github.com/login/oauth/authorize",
        "token_url" => "https://github.com/login/oauth/access_token"
      })

    create_provider(%{
      name: "github_test#{suffix}",
      slug: "github_test#{suffix}",
      auth_mode: "oauth2",
      client_secret: "github_client_secret#{suffix}",
      config: %{
        "display_name" => "GitHub Test#{suffix}",
        "client_id" => "github_client_id#{suffix}",
        "auth_url" => urls["auth_url"],
        "token_url" => urls["token_url"]
      }
    })
  end

  @doc """
  Creates a Google test provider.

  Options:
  - `:urls` - Map with "auth_url" and "token_url" keys to override default URLs
  """
  def create_google_provider(suffix \\ "", opts \\ []) do
    urls =
      Keyword.get(opts, :urls, %{
        "auth_url" => "https://accounts.google.com/o/oauth2/auth",
        "token_url" => "https://oauth2.googleapis.com/token"
      })

    create_provider(%{
      name: "google_test#{suffix}",
      slug: "google_test#{suffix}",
      auth_mode: "oauth2",
      client_secret: "google_client_secret#{suffix}",
      config: %{
        "display_name" => "Google Test#{suffix}",
        "client_id" => "google_client_id#{suffix}",
        "auth_url" => urls["auth_url"],
        "token_url" => urls["token_url"]
      }
    })
  end

  @doc """
  Creates an API key test provider.
  """
  def create_api_key_provider(suffix \\ "") do
    create_provider(%{
      name: "apikey_provider#{suffix}",
      slug: "apikey_provider#{suffix}",
      auth_mode: "api_key",
      client_secret: "api_key_secret#{suffix}",
      config: %{
        "display_name" => "API Key Provider#{suffix}",
        "client_id" => "api_key_client_id#{suffix}",
        "auth_url" => "https://api.example.com/auth",
        "token_url" => "https://api.example.com/token",
        "api_endpoint" => "https://api.example.com"
      }
    })
  end

  @doc """
  Creates an OAuth session with optional attributes override.

  ## Examples

      session = Factory.create_oauth_session(provider, "tenant_123")
      expired_session = Factory.create_oauth_session(provider, "tenant_123", %{
        expires_at: DateTime.add(DateTime.utc_now(), -3600)
      })
      
  """
  def create_oauth_session(provider, tenant_id, attrs \\ %{}) do
    default_attrs = %{
      provider_id: provider.id,
      tenant_id: tenant_id,
      session_token: secure_token(32),
      state: secure_token(32),
      expires_at: DateTime.add(DateTime.utc_now(), 3600, :second) |> DateTime.truncate(:second)
    }

    merged_attrs = Map.merge(default_attrs, attrs)
    changeset = OAuthSession.changeset(%OAuthSession{}, merged_attrs)
    {:ok, session} = Repo.insert(changeset)
    session
  end

  @doc """
  Creates an OAuth session with PKCE enabled.
  """
  def create_oauth_session_with_pkce(provider, tenant_id, attrs \\ %{}) do
    unique_id = System.unique_integer([:positive])

    pkce_attrs = %{
      code_verifier: "code_verifier_#{unique_id}_" <> String.duplicate("a", 50),
      code_challenge: "code_challenge_#{unique_id}",
      code_challenge_method: "S256"
    }

    create_oauth_session(provider, tenant_id, Map.merge(pkce_attrs, attrs))
  end

  @doc """
  Creates an expired OAuth session.

  Note: Creates the session with a future expiry first, then updates it to be expired
  to bypass validation that requires future timestamps.
  """
  def create_expired_oauth_session(provider, tenant_id, attrs \\ %{}) do
    # First create a valid session
    session = create_oauth_session(provider, tenant_id, attrs)

    # Then update it to be expired using a manual changeset that skips validation
    # Make it 25 hours old to ensure cleanup catches it (cleanup threshold is 24h)
    past_time =
      DateTime.add(DateTime.utc_now(), -25 * 60 * 60, :second)
      |> DateTime.truncate(:second)

    # Use force_change to bypass validation
    changeset =
      session
      |> Ecto.Changeset.change()
      |> Ecto.Changeset.force_change(:expires_at, past_time)

    {:ok, expired_session} = Repo.update(changeset)
    expired_session
  end

  @doc """
  Creates a connection from token response.

  ## Examples

      connection = Factory.create_connection(provider, "tenant_123")
      github_connection = Factory.create_connection(provider, "tenant_123", %{
        access_token: "gho_custom_token"
      })
      
  """
  def create_connection(provider, tenant_id, token_attrs \\ %{}) do
    unique_id = System.unique_integer([:positive])

    default_token_response = %{
      "access_token" => "access_token_#{unique_id}",
      "refresh_token" => "refresh_token_#{unique_id}",
      "token_type" => :bearer,
      "expires_in" => 3600,
      "scope" => "default:scope"
    }

    token_response = Map.merge(default_token_response, token_attrs)
    changeset = Connection.from_token_response(provider.id, tenant_id, token_response)
    {:ok, connection} = Repo.insert(changeset)
    connection
  end

  @doc """
  Creates a GitHub-style connection.
  """
  def create_github_connection(provider, tenant_id, suffix \\ "") do
    token_response = %{
      "access_token" => "gho_access_token#{suffix}",
      "refresh_token" => "gho_refresh_token#{suffix}",
      "token_type" => :bearer,
      "expires_in" => 3600,
      "scope" => "user:email repo"
    }

    changeset = Connection.from_token_response(provider.id, tenant_id, token_response)
    {:ok, connection} = Repo.insert(changeset)
    connection
  end

  @doc """
  Creates a connection without last_used_at timestamp (for testing usage tracking).
  """
  def create_unused_connection(provider, tenant_id, token_attrs \\ %{}) do
    connection = create_connection(provider, tenant_id, token_attrs)

    # Force last_used_at to nil
    changeset =
      connection
      |> Ecto.Changeset.change()
      |> Ecto.Changeset.force_change(:last_used_at, nil)

    {:ok, unused_connection} = Repo.update(changeset)
    unused_connection
  end

  @doc """
  Creates an expired connection.

  Note: Creates connection that's old enough for cleanup (35 days old, status expired)
  """
  def create_expired_connection(provider, tenant_id) do
    # Make it 35 days old to ensure cleanup catches it (cleanup threshold is 30 days)
    past_time =
      DateTime.add(DateTime.utc_now(), -35 * 24 * 60 * 60, :second)
      |> DateTime.truncate(:second)

    connection = create_connection(provider, tenant_id)

    # Set status to expired and old updated_at timestamp
    changeset =
      connection
      |> Ecto.Changeset.change()
      |> Ecto.Changeset.force_change(:expires_at, past_time)
      |> Ecto.Changeset.force_change(:status, :expired)
      |> Ecto.Changeset.force_change(:updated_at, DateTime.to_naive(past_time))

    {:ok, expired_connection} = Repo.update(changeset)
    expired_connection
  end

  @doc """
  Creates a revoked connection.
  """
  def create_revoked_connection(provider, tenant_id) do
    connection = create_connection(provider, tenant_id)

    changeset =
      Connection.changeset(connection, %{
        revoked_at: DateTime.utc_now(),
        status: :revoked
      })

    {:ok, revoked_connection} = Repo.update(changeset)
    revoked_connection
  end

  @doc """
  Creates an audit log entry with optional attributes override.

  ## Examples

      log = Factory.create_audit_log("tenant_123", "user_456")
      connection_log = Factory.create_audit_log("tenant_123", "user_456", %{
        action: "connection_created",
        resource_type: "connection"
      })
      
  """
  def create_audit_log(tenant_id, user_id, attrs \\ %{}) do
    unique_id = System.unique_integer([:positive])

    default_attrs = %{
      tenant_id: tenant_id,
      user_id: user_id,
      action: "test_action_#{unique_id}",
      resource_type: "test_resource",
      resource_id: Ecto.UUID.generate(),
      metadata: %{"test" => "data"}
    }

    merged_attrs = Map.merge(default_attrs, attrs)
    changeset = AuditLog.changeset(%AuditLog{}, merged_attrs)
    {:ok, log} = Repo.insert(changeset)
    log
  end

  @doc """
  Creates multiple test entities at once for complex test scenarios.

  ## Examples

      %{provider: provider, session: session, connection: connection} = 
        Factory.create_oauth_flow("tenant_123")
        
  """
  def create_oauth_flow(tenant_id, opts \\ []) do
    provider_attrs = Keyword.get(opts, :provider_attrs, %{})
    session_attrs = Keyword.get(opts, :session_attrs, %{})
    connection_attrs = Keyword.get(opts, :connection_attrs, %{})

    provider = create_provider(provider_attrs)
    session = create_oauth_session(provider, tenant_id, session_attrs)
    connection = create_connection(provider, tenant_id, connection_attrs)

    %{
      provider: provider,
      session: session,
      connection: connection
    }
  end

  @doc """
  Utility function to generate secure test tokens.
  """
  def secure_token(length \\ 32) do
    :crypto.strong_rand_bytes(length)
    |> Base.url_encode64(padding: false)
    |> String.slice(0, length)
  end

  @doc """
  Utility function to generate test tenant IDs.
  """
  def tenant_id(prefix \\ "tenant") do
    "#{prefix}_#{System.unique_integer([:positive])}"
  end

  @doc """
  Utility function to generate test user IDs.
  """
  def user_id(prefix \\ "user") do
    "#{prefix}_#{System.unique_integer([:positive])}"
  end
end

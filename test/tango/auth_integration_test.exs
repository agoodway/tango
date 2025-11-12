defmodule Tango.AuthIntegrationTest do
  use Tango.DatabaseCase, async: true

  alias Tango.{Auth, Provider}

  describe "Auth database operations" do
    test "creates OAuth session with database provider" do
      # Create provider in database first
      {:ok, provider} =
        Provider.create_provider(%{
          name: "github",
          slug: "github",
          client_secret: "test_secret",
          config: %{
            "display_name" => "GitHub",
            "client_id" => "github_client_id",
            "auth_url" => "https://github.com/login/oauth/authorize",
            "token_url" => "https://github.com/login/oauth/access_token",
            "auth_mode" => "OAUTH2"
          }
        })

      # Test session creation
      tenant_id = "user-123"
      assert {:ok, session} = Auth.create_session("github", tenant_id)

      assert session.provider_id == provider.id
      assert session.tenant_id == tenant_id
      assert session.session_token != nil
      assert session.state != nil
    end

    test "cleanup_expired_sessions with real database" do
      # Should work even with empty database
      assert {:ok, 0} = Auth.cleanup_expired_sessions()
    end

    test "authorization URL includes provider metadata auth_params" do
      # Create provider with metadata containing auth_params
      {:ok, _provider} =
        Provider.create_provider(%{
          name: "google_with_metadata",
          slug: "google_with_metadata",
          client_secret: "test_secret",
          config: %{
            "display_name" => "Google",
            "client_id" => "google_client_id",
            "auth_url" => "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url" => "https://oauth2.googleapis.com/token",
            "auth_mode" => "OAUTH2"
          },
          metadata: %{
            "auth_params" => %{
              "access_type" => "offline",
              "prompt" => "consent"
            }
          }
        })

      tenant_id = "user-123"
      {:ok, session} = Auth.create_session("google_with_metadata", tenant_id)

      {:ok, auth_url} =
        Auth.authorize_url(session.session_token, redirect_uri: "https://app.com/callback")

      # Metadata params should be in URL
      assert String.contains?(auth_url, "access_type=offline")
      assert String.contains?(auth_url, "prompt=consent")

      # Standard params should also be present
      assert String.contains?(auth_url, "client_id=google_client_id")
      assert String.contains?(auth_url, "response_type=code")
    end
  end
end

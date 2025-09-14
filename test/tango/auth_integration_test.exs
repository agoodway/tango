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
  end
end

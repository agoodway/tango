defmodule Tango.AuthTest do
  use ExUnit.Case

  # Simple unit tests for Auth module functions
  # Note: Database tests would be in the host application

  describe "create_session/3" do
    test "validates parameters" do
      assert_raise FunctionClauseError, fn ->
        Tango.Auth.create_session(nil, "user-123")
      end

      assert_raise FunctionClauseError, fn ->
        Tango.Auth.create_session("github", nil)
      end
    end
  end

  describe "authorize_url/2" do
    test "validates parameters" do
      assert_raise FunctionClauseError, fn ->
        Tango.Auth.authorize_url(nil, redirect_uri: "https://app.com/callback")
      end
    end
  end

  describe "exchange_code/4" do
    test "validates parameters" do
      assert {:error, :invalid_state_parameter} =
               Tango.Auth.exchange_code(nil, "code", "tenant-123",
                 redirect_uri: "https://app.com/callback"
               )

      assert {:error, :invalid_authorization_code} =
               Tango.Auth.exchange_code("state", nil, "tenant-123",
                 redirect_uri: "https://app.com/callback"
               )

      assert {:error, :invalid_tenant_id} =
               Tango.Auth.exchange_code("state", "code", nil,
                 redirect_uri: "https://app.com/callback"
               )
    end
  end

  describe "token extraction" do
    test "extract_access_token handles JSON-encoded OAuth2 responses" do
      # Test the JSON-encoded token scenario that was causing production issues
      json_token =
        Jason.encode!(%{
          "access_token" => "gho_real_token_123",
          "token_type" => "bearer",
          "scope" => "repo,user:email"
        })

      # This simulates what OAuth2 library sometimes returns
      oauth2_token = %OAuth2.AccessToken{
        access_token: json_token,
        token_type: "Bearer",
        expires_at: nil,
        refresh_token: nil,
        other_params: %{}
      }

      # Convert using our function
      result = Tango.Auth.convert_token_to_response(oauth2_token)

      # Should extract the real token, not the JSON string
      assert result["access_token"] == "gho_real_token_123"
      assert result["token_type"] == "Bearer"
    end

    test "extract_access_token handles plain string tokens" do
      # Test normal token response
      oauth2_token = %OAuth2.AccessToken{
        access_token: "plain_token_abc123",
        token_type: "bearer",
        expires_at: nil,
        refresh_token: nil,
        other_params: %{"scope" => "read"}
      }

      result = Tango.Auth.convert_token_to_response(oauth2_token)

      # Should pass through plain tokens unchanged
      assert result["access_token"] == "plain_token_abc123"
      assert result["token_type"] == "bearer"
    end

    test "extract_access_token handles malformed JSON gracefully" do
      # Test invalid JSON input
      oauth2_token = %OAuth2.AccessToken{
        access_token: "not-valid-json{",
        token_type: "bearer",
        expires_at: nil,
        refresh_token: nil,
        other_params: %{}
      }

      result = Tango.Auth.convert_token_to_response(oauth2_token)

      # Should return the original string when JSON parsing fails
      assert result["access_token"] == "not-valid-json{"
    end

    test "extract_access_token handles empty access_token in JSON" do
      # Test JSON without access_token field
      json_without_token =
        Jason.encode!(%{
          "token_type" => "bearer",
          "scope" => "read"
        })

      oauth2_token = %OAuth2.AccessToken{
        access_token: json_without_token,
        token_type: "bearer",
        expires_at: nil,
        refresh_token: nil,
        other_params: %{}
      }

      result = Tango.Auth.convert_token_to_response(oauth2_token)

      # Should return the original JSON when no access_token field found
      assert result["access_token"] == json_without_token
    end
  end
end

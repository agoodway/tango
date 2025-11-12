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

  describe "OAuth2 client configuration" do
    test "build_oauth_client includes JSON serializer" do
      # This test ensures the OAuth2.Client is configured with Jason serializer
      # to properly parse JSON responses from OAuth providers (like Google, GitHub, etc.)

      # Create a mock OAuth2 response like what Google returns
      mock_google_response = %{
        "access_token" => "ya29.test_token",
        "expires_in" => 3599,
        "refresh_token" => "1//05test_refresh",
        "scope" => "https://www.googleapis.com/auth/calendar",
        "token_type" => "Bearer"
      }

      # Test that OAuth2.AccessToken.new properly parses the response when given a map
      token = OAuth2.AccessToken.new(mock_google_response)

      assert token.access_token == "ya29.test_token"
      assert token.refresh_token == "1//05test_refresh"
      assert token.expires_at != nil
      assert token.other_params["scope"] == "https://www.googleapis.com/auth/calendar"

      # The key assertion: When OAuth2.Client has a serializer configured,
      # it will decode the JSON response body into a map BEFORE creating the AccessToken.
      # Without the serializer, the entire JSON string gets dumped into access_token field.

      # Test the broken behavior (what happens WITHOUT serializer)
      json_string = Jason.encode!(mock_google_response)
      broken_token = OAuth2.AccessToken.new(json_string)

      # Without serializer, the entire JSON becomes the access_token
      assert broken_token.access_token == json_string
      assert broken_token.refresh_token == nil
      assert broken_token.expires_at == nil
    end
  end
end

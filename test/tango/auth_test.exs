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
end

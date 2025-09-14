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

  describe "exchange_code/3" do
    test "validates parameters" do
      assert_raise FunctionClauseError, fn ->
        Tango.Auth.exchange_code(nil, "code", redirect_uri: "https://app.com/callback")
      end

      assert_raise FunctionClauseError, fn ->
        Tango.Auth.exchange_code("state", nil, redirect_uri: "https://app.com/callback")
      end
    end
  end
end

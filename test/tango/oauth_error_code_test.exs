defmodule Tango.OAuthErrorCodeTest do
  use ExUnit.Case, async: true

  alias Tango.OAuthErrorCode

  doctest OAuthErrorCode

  describe "leading_code/1" do
    test "returns the leading token before a colon or whitespace" do
      cases = [
        {"invalid_grant", "invalid_grant"},
        {"invalid_client: Invalid client_id or client_secret", "invalid_client"},
        {"invalid_client:reason", "invalid_client"},
        {"invalid_grant Token has been revoked", "invalid_grant"},
        {"invalid_scope\tbad scope", "invalid_scope"},
        {"server_error\nretry later", "server_error"},
        {"  invalid_request: missing code", "invalid_request"},
        {"not_a_real_code: invalid_grant", "not_a_real_code"}
      ]

      for {error, code} <- cases do
        assert OAuthErrorCode.leading_code(error) == code
      end
    end

    test "returns nil when there is no leading token" do
      for error <- ["", "   ", ":", ": invalid_grant", nil, 400, %{"code" => "invalid_grant"}] do
        assert OAuthErrorCode.leading_code(error) == nil
      end
    end
  end
end

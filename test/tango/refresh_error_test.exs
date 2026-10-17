defmodule Tango.RefreshErrorTest do
  use ExUnit.Case, async: true

  alias Tango.RefreshError

  @sentinel "LEAKED_PROVIDER_BODY"
  @oauth_codes ~w(
    invalid_grant
    invalid_client
    unauthorized_client
    invalid_request
    invalid_scope
    unsupported_grant_type
    temporarily_unavailable
    server_error
  )

  describe "from_response/3" do
    test "maps only allowlisted 4xx OAuth codes" do
      for code <- @oauth_codes do
        body = %{"error" => code, "error_description" => @sentinel}
        json = Jason.encode!(body)

        atom = String.to_existing_atom(code)
        reason = RefreshError.from_response(400, [], body)
        assert reason == {:oauth_error, atom}
        assert RefreshError.from_response(400, [], json) == {:oauth_error, atom}

        stored = RefreshError.to_storage(reason)
        assert stored == "oauth_error:#{code}"
        refute String.contains?(stored, @sentinel)
      end

      leaked_bodies = [
        %{"error" => "not_a_real_code", "error_description" => @sentinel},
        Jason.encode!(%{"error" => "not_a_real_code", "hint" => @sentinel}),
        [%{"error" => "invalid_grant"}],
        "invalid_grant",
        @sentinel,
        "",
        "<html>#{@sentinel}</html>",
        Jason.encode!(Jason.encode!(%{"error" => "invalid_grant"})),
        Jason.encode!("invalid_grant"),
        400,
        true,
        nil
      ]

      for body <- leaked_bodies do
        reason = RefreshError.from_response(400, [], body)
        assert reason == {:http_error, 400}
        refute String.contains?(RefreshError.to_storage(reason), @sentinel)
      end
    end

    test "HTTP outage status wins over OAuth body" do
      body = %{"error" => "invalid_grant", "error_description" => @sentinel}

      cases = [
        {429, [], {:rate_limited, nil}},
        {503, [], {:http_error, 503}},
        {408, [], {:http_error, 408}}
      ]

      for {status, headers, expected} <- cases do
        reason = RefreshError.from_response(status, headers, body)
        assert reason == expected
        assert RefreshError.classify(reason) == :transient
        refute String.contains?(RefreshError.to_storage(reason), @sentinel)
        refute String.contains?(RefreshError.to_storage(reason), "invalid_grant")
      end
    end

    test "OAuth codes outside 4xx do not prove invalid credentials" do
      for status <- [200, 302, 600],
          body <- [%{"error" => "invalid_grant"}, ~s({"error":"invalid_grant"})] do
        assert RefreshError.from_response(status, [], body) == {:http_error, status}
      end
    end

    test "Retry-After uses the first complete nonnegative integer" do
      http_date = "Wed, 21 Oct 2015 07:28:00 GMT"

      cases = [
        {[{"retry-after", "30"}], 30, 30},
        {[{"ReTrY-AfTeR", "30"}], 30, 30},
        {[{"retry-after", "30"}, {"retry-after", "90"}], 30, 30},
        {[{"RETRY-AFTER", "0"}], 0, 0},
        {[{"retry-after", "7200"}], 7200, 3600},
        {[{"retry-after", "-1"}], nil, 300},
        {[{"retry-after", "-0"}], nil, 300},
        {[{"retry-after", "+30"}], nil, 300},
        {[{"retry-after", "1.5"}], nil, 300},
        {[{"retry-after", "30x"}], nil, 300},
        {[{"retry-after", http_date}], nil, 300},
        {[], nil, 300}
      ]

      for {headers, seconds, delay} <- cases do
        reason = RefreshError.from_response(429, headers, %{"error" => "invalid_grant"})
        assert reason == {:rate_limited, seconds}
        assert RefreshError.backoff_seconds(reason) == delay
      end
    end
  end

  describe "classification and storage" do
    test "unknown tagged terms stay local and redact their payload" do
      for reason <- [
            {:rate_limited, -1},
            {:rate_limited, "30"},
            {:rate_limited, %{secret: @sentinel}},
            {:transport_error, :unknown},
            {:transport_error, %{secret: @sentinel}}
          ] do
        assert RefreshError.classify(reason) == :local
        assert RefreshError.to_storage(reason) == "unknown_refresh_error"
      end
    end

    test "transport details are bounded" do
      assert RefreshError.from_transport(:timeout) == {:transport_error, :timeout}
      assert RefreshError.from_transport(:etimedout) == {:transport_error, :timeout}

      for reason <- [:econnrefused, :closed, "timeout", %{reason: :timeout}, {:timeout, :extra}] do
        assert RefreshError.from_transport(reason) == {:transport_error, :network_error}
      end

      classified = [
        {{:rate_limited, 30}, :transient},
        {{:rate_limited, nil}, :transient},
        {{:http_error, 500}, :transient},
        {{:http_error, 503}, :transient},
        {{:http_error, 599}, :transient},
        {{:http_error, 600}, :request},
        {{:http_error, 408}, :transient},
        {{:oauth_error, :invalid_grant}, :credential},
        {{:oauth_error, :invalid_client}, :client},
        {{:oauth_error, :unauthorized_client}, :client},
        {{:oauth_error, :invalid_request}, :request},
        {{:oauth_error, :invalid_scope}, :request},
        {{:oauth_error, :unsupported_grant_type}, :request},
        {{:oauth_error, :temporarily_unavailable}, :transient},
        {{:oauth_error, :server_error}, :transient},
        {{:http_error, 400}, :request},
        {{:http_error, 401}, :request},
        {{:transport_error, :timeout}, :transient},
        {{:transport_error, :network_error}, :transient},
        {:no_refresh_token, :local},
        {:refresh_not_allowed, :local},
        {:provider_not_found, :local},
        {:invalid_config, :local},
        {:persistence_failed, :local},
        {:transaction_failed, :local}
      ]

      for {reason, class} <- classified do
        assert RefreshError.classify(reason) == class
      end

      assert RefreshError.classify(:not_a_refresh_reason) == :local
      assert RefreshError.classify(%{error: "invalid_grant"}) == :local
      assert RefreshError.classify("oauth_error:invalid_grant") == :local
      assert RefreshError.to_storage(:not_a_refresh_reason) == "unknown_refresh_error"
      assert RefreshError.to_storage(%{error: @sentinel}) == "unknown_refresh_error"
      assert RefreshError.to_storage({:oauth_error, :made_up}) == "unknown_refresh_error"
    end

    test "storage strings are stable JSON scalars" do
      stored = %{
        {:oauth_error, :invalid_grant} => "oauth_error:invalid_grant",
        {:oauth_error, :invalid_client} => "oauth_error:invalid_client",
        {:oauth_error, :unauthorized_client} => "oauth_error:unauthorized_client",
        {:oauth_error, :invalid_request} => "oauth_error:invalid_request",
        {:oauth_error, :invalid_scope} => "oauth_error:invalid_scope",
        {:oauth_error, :unsupported_grant_type} => "oauth_error:unsupported_grant_type",
        {:oauth_error, :temporarily_unavailable} => "oauth_error:temporarily_unavailable",
        {:oauth_error, :server_error} => "oauth_error:server_error",
        {:rate_limited, 30} => "rate_limited:30",
        {:rate_limited, 0} => "rate_limited:0",
        {:rate_limited, nil} => "rate_limited",
        {:http_error, 503} => "http_error:503",
        {:http_error, 408} => "http_error:408",
        {:http_error, 400} => "http_error:400",
        {:transport_error, :timeout} => "transport_error:timeout",
        {:transport_error, :network_error} => "transport_error:network_error",
        :no_refresh_token => "no_refresh_token",
        :refresh_not_allowed => "refresh_not_allowed",
        :provider_not_found => "provider_not_found",
        :invalid_config => "invalid_config",
        :persistence_failed => "persistence_failed",
        :transaction_failed => "transaction_failed"
      }

      for {reason, expected} <- stored do
        assert RefreshError.to_storage(reason) == expected
        assert is_binary(Jason.encode!(expected))
      end
    end
  end
end

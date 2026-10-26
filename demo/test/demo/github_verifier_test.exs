defmodule Demo.GithubVerifierTest do
  use ExUnit.Case, async: false

  setup do
    previous = Application.get_env(:demo, :github_req_options)
    # retry: false keeps transient-failure cases from sleeping through Req's backoff.
    Application.put_env(:demo, :github_req_options,
      plug: {Req.Test, Demo.GithubClient},
      retry: false
    )

    on_exit(fn ->
      if previous,
        do: Application.put_env(:demo, :github_req_options, previous),
        else: Application.delete_env(:demo, :github_req_options)
    end)

    :ok
  end

  defp credential,
    do: %{
      access_token: "gho_candidate_secret_token",
      granted_scopes: ["repo"],
      provider_data: %{}
    }

  test "returns the account id and login without any credential" do
    Req.Test.stub(Demo.GithubClient, fn conn ->
      assert ["Bearer gho_candidate_secret_token"] =
               Plug.Conn.get_req_header(conn, "authorization")

      Req.Test.json(conn, %{
        "id" => 42,
        "login" => "octocat",
        "email" => "private@example.test",
        "access_token" => "must-not-be-copied"
      })
    end)

    assert {:ok, verification} = Demo.GithubVerifier.verify(nil, credential(), [])

    assert verification == %{
             subject: "42",
             claims: %{"login" => "octocat"},
             continuity: :initial
           }

    refute inspect(verification) =~ "gho_candidate_secret_token"
    refute inspect(verification) =~ "must-not-be-copied"
  end

  test "proves continuity with the connection being reauthorized" do
    Req.Test.stub(Demo.GithubClient, &Req.Test.json(&1, %{"id" => 42, "login" => "octocat"}))

    assert {:ok, %{continuity: {:connection, 7}}} =
             Demo.GithubVerifier.verify(nil, credential(), connection_id: 7)
  end

  test "rejects an unusable identity response" do
    Req.Test.stub(Demo.GithubClient, &Req.Test.json(&1, %{"message" => "Bad credentials"}))

    assert {:error, :invalid_identity} = Demo.GithubVerifier.verify(nil, credential(), [])
  end

  test "rejects a failed identity request" do
    Req.Test.stub(Demo.GithubClient, &Plug.Conn.send_resp(&1, 401, ""))

    assert {:error, :invalid_identity} = Demo.GithubVerifier.verify(nil, credential(), [])
  end

  # Transient failures must map to Tango's retryable verifier errors so the
  # candidate survives a GitHub outage and the user can retry verification.
  test "reports GitHub server errors as provider_unavailable" do
    for status <- [500, 502, 503] do
      Req.Test.stub(Demo.GithubClient, &Plug.Conn.send_resp(&1, status, ""))

      assert {:error, :provider_unavailable} =
               Demo.GithubVerifier.verify(nil, credential(), [])
    end
  end

  test "reports rate limiting as temporarily_unavailable" do
    Req.Test.stub(Demo.GithubClient, &Plug.Conn.send_resp(&1, 429, ""))

    assert {:error, :temporarily_unavailable} =
             Demo.GithubVerifier.verify(nil, credential(), [])
  end

  test "reports timeouts and connection failures as transient" do
    Req.Test.stub(Demo.GithubClient, &Req.Test.transport_error(&1, :timeout))
    assert {:error, :timeout} = Demo.GithubVerifier.verify(nil, credential(), [])

    Req.Test.stub(Demo.GithubClient, &Req.Test.transport_error(&1, :econnrefused))
    assert {:error, :network_error} = Demo.GithubVerifier.verify(nil, credential(), [])
  end
end

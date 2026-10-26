defmodule Tango.ProviderRedactionTest do
  use Tango.DatabaseCase, async: false

  alias Tango.Provider
  alias Tango.Schemas.Provider, as: ProviderSchema

  @created "synthetic-provider-create-sentinel"
  @rotated "synthetic-provider-rotate-sentinel"
  @catalog "synthetic-provider-catalog-sentinel"

  test "provider creation and rotation keep secrets out of SQL metadata and preserve schema fields" do
    capture_credentials(fn ->
      assert {:ok, provider} = Provider.create_provider(attrs(@created))
      assert_provider(provider, @created)
      assert {:ok, rotated} = Provider.update_provider(provider, %{client_secret: @rotated})
      assert_provider(rotated, @rotated)
      assert_provider(Repo.get!(ProviderSchema, provider.id), @rotated)
    end)
  end

  test "catalog creation uses the same credential boundary" do
    capture_credentials(fn ->
      assert {:ok, provider} =
               Provider.create_provider_from_nango(
                 "synthetic-catalog",
                 %{
                   "display_name" => "Synthetic catalog",
                   "auth_mode" => "OAUTH2",
                   "authorization_url" => "https://example.test/authorize",
                   "token_url" => "https://example.test/token"
                 },
                 client_id: "synthetic-client",
                 client_secret: @catalog
               )

      assert_provider(provider, @catalog)
      assert_provider(Repo.get!(ProviderSchema, provider.id), @catalog)
    end)
  end

  test "failed writes restore changesets and clear process-local secrets" do
    capture_credentials(fn ->
      assert {:ok, _provider} = Provider.create_provider(attrs(@created))
      assert {:error, changeset} = Provider.create_provider(attrs(@rotated))
      assert Ecto.Changeset.get_field(changeset, :client_secret) == @rotated
      assert Enum.filter(Process.get_keys(), &match?({Tango.RedactedParams, _}, &1)) == []
    end)
  end

  defp attrs(secret),
    do: %{
      name: "Synthetic provider",
      slug: "synthetic-provider",
      client_secret: secret,
      config: %{
        "client_id" => "synthetic-client",
        "auth_url" => "https://example.test/authorize",
        "token_url" => "https://example.test/token"
      }
    }

  defp assert_provider(provider, secret) do
    assert provider.client_secret == secret
    assert Map.keys(provider) |> Enum.sort() == Map.keys(%ProviderSchema{}) |> Enum.sort()
  end

  defp capture_credentials(fun) do
    handler = "provider-redaction-#{System.unique_integer([:positive])}"
    pid = self()

    :telemetry.attach(
      handler,
      [:tango, :test_repo, :query],
      fn _, _, metadata, _ ->
        send(pid, {:provider_query, Map.take(metadata, [:params, :cast_params])})
      end,
      nil
    )

    log =
      try do
        ExUnit.CaptureLog.capture_log(fun)
      after
        :telemetry.detach(handler)
      end

    queries = drain_queries([])
    refute queries == []

    for secret <- [@created, @rotated, @catalog] do
      refute inspect(queries, limit: :infinity) =~ secret
      refute log =~ secret
    end

    for query <- queries,
        value <- query[:cast_params] || [],
        match?(%Tango.RedactedParams.Secret{}, value) do
      assert :error = Tango.RedactedParams.fetch(value)
    end
  end

  defp drain_queries(queries) do
    receive do
      {:provider_query, query} -> drain_queries([query | queries])
    after
      0 -> queries
    end
  end
end

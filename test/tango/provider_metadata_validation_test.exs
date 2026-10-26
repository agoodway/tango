defmodule Tango.ProviderMetadataValidationTest do
  use ExUnit.Case, async: true

  alias Tango.Schemas.Provider

  describe "token_response_metadata" do
    test "accepts nil and lists of non-blank field names, including secret-like catalog names" do
      for fields <- [nil, [], ["instance_url"], ["team.id", "bot_user_id"], ["id_token"]] do
        assert changeset(%{"token_response_metadata" => fields}).valid?
      end
    end

    test "rejects non-list values and blank or non-string field names" do
      for fields <- ["instance_url", %{"field" => "instance_url"}, true, [42], [" "], [""], [nil]] do
        changeset = changeset(%{"token_response_metadata" => fields})
        refute changeset.valid?

        assert {"token_response_metadata must be a list of non-blank field names", _} =
                 changeset.errors[:metadata]
      end
    end
  end

  describe "authorization_method" do
    test "accepts nil, header, and body" do
      for method <- [nil, "header", "body"] do
        assert changeset(%{"authorization_method" => method}).valid?
      end
    end

    test "accepts body combined with a basic token request auth method" do
      assert changeset(%{
               "authorization_method" => "body",
               "token_request_auth_method" => "basic"
             }).valid?
    end

    test "rejects any other value" do
      for method <- ["basic", "Body", "", 1, true] do
        changeset = changeset(%{"authorization_method" => method})
        refute changeset.valid?

        assert {~s(authorization_method must be "header" or "body"), _} =
                 changeset.errors[:metadata]
      end
    end
  end

  test "ordinary provider configuration retains its existing defaults" do
    for metadata <- [
          %{},
          %{"token_request_auth_method" => "basic", "authorization_method" => "header"}
        ] do
      assert changeset(metadata).valid?
    end
  end

  describe "catalog import" do
    test "copies token_response_metadata from the catalog entry" do
      assert Provider.catalog_metadata(%{
               "token_response_metadata" => ["instance_url", "team.id"]
             })[
               "token_response_metadata"
             ] == ["instance_url", "team.id"]

      changeset =
        Provider.from_nango_config(
          "synthetic-catalog",
          %{
            "display_name" => "Synthetic catalog",
            "auth_mode" => "OAUTH2",
            "authorization_url" => "https://provider.example.test/authorize",
            "token_url" => "https://provider.example.test/token",
            "authorization_method" => "body",
            "token_response_metadata" => ["instance_url", "id_token"]
          },
          client_id: "synthetic-client",
          client_secret: "synthetic-secret"
        )

      assert changeset.valid?
      metadata = Ecto.Changeset.get_field(changeset, :metadata)
      assert metadata["token_response_metadata"] == ["instance_url", "id_token"]
      assert metadata["authorization_method"] == "body"
    end

    test "records nil when the catalog omits token_response_metadata" do
      metadata = Provider.catalog_metadata(%{})
      assert Map.has_key?(metadata, "token_response_metadata")
      assert metadata["token_response_metadata"] == nil
    end
  end

  test "client_secret is redacted from inspect output" do
    refute inspect(%Provider{client_secret: "synthetic-inspect-secret"}) =~
             "synthetic-inspect-secret"
  end

  defp changeset(metadata) do
    Provider.changeset(%Provider{}, %{
      name: "Generic authorization provider",
      slug: "generic-authorization-provider",
      client_secret: "synthetic-secret",
      config: %{
        "client_id" => "synthetic-client",
        "auth_url" => "https://provider.example.test/authorize",
        "token_url" => "https://provider.example.test/token"
      },
      metadata: metadata
    })
  end
end

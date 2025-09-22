defmodule Mix.Tasks.Helpers.ProviderHelperValidationTest do
  @moduledoc """
  Tests for ProviderHelper validation and utility functions.

  Focuses on testing the validation logic and display functions
  without complex provider creation or network dependencies.
  """

  use ExUnit.Case, async: true

  alias Mix.Tasks.Helpers.ProviderHelper
  alias Tango.Schemas.Provider, as: ProviderSchema

  import ExUnit.CaptureIO

  describe "validate_oauth2_credentials/1" do
    test "validates correct OAuth2 credentials" do
      opts = [client_id: "test_client_id", client_secret: "test_secret"]

      assert {:ok, credentials} = ProviderHelper.validate_oauth2_credentials(opts)
      assert credentials.client_id == "test_client_id"
      assert credentials.client_secret == "test_secret"
    end

    test "returns error when client_id is missing" do
      opts = [client_secret: "test_secret"]

      assert {:error, message} = ProviderHelper.validate_oauth2_credentials(opts)
      assert message == "OAuth2 client ID required (--client-id)"
    end

    test "returns error when client_secret is missing" do
      opts = [client_id: "test_client_id"]

      assert {:error, message} = ProviderHelper.validate_oauth2_credentials(opts)
      assert message == "OAuth2 client secret required (--client-secret)"
    end

    test "returns error when both credentials are missing" do
      opts = []

      assert {:error, message} = ProviderHelper.validate_oauth2_credentials(opts)
      assert message == "OAuth2 client ID required (--client-id)"
    end

    test "handles nil values in credentials" do
      opts = [client_id: nil, client_secret: "test_secret"]

      assert {:error, message} = ProviderHelper.validate_oauth2_credentials(opts)
      assert message == "OAuth2 client ID required (--client-id)"
    end
  end

  describe "validate_api_key_credentials/1" do
    test "validates correct API key credentials" do
      opts = [api_key: "sk_test_12345"]

      assert {:ok, credentials} = ProviderHelper.validate_api_key_credentials(opts)
      assert credentials.api_key == "sk_test_12345"
    end

    test "returns error when api_key is missing" do
      opts = []

      assert {:error, message} = ProviderHelper.validate_api_key_credentials(opts)
      assert message == "API key required (--api-key)"
    end

    test "returns error when api_key is nil" do
      opts = [api_key: nil]

      assert {:error, message} = ProviderHelper.validate_api_key_credentials(opts)
      assert message == "API key required (--api-key)"
    end

    test "accepts empty string as valid api key" do
      opts = [api_key: ""]

      assert {:ok, credentials} = ProviderHelper.validate_api_key_credentials(opts)
      assert credentials.api_key == ""
    end

    test "validation functions handle edge cases" do
      # Test validation with unusual but valid inputs
      assert {:ok, _} =
               ProviderHelper.validate_oauth2_credentials(
                 client_id: "very_long_client_id_" <> String.duplicate("x", 100),
                 client_secret: "very_long_secret_" <> String.duplicate("y", 100)
               )

      assert {:ok, _} =
               ProviderHelper.validate_api_key_credentials(
                 api_key: "special_chars_!@#$%^&*()_+-="
               )
    end
  end

  describe "display functions" do
    test "print_changeset_errors/1 formats errors correctly" do
      # Create a changeset with errors using the schema module
      changeset = ProviderSchema.changeset(%ProviderSchema{}, %{name: ""})

      output =
        capture_io(fn ->
          ProviderHelper.print_changeset_errors(changeset)
        end)

      assert output =~ "name:"
    end

    test "display_create_usage/1 shows provider-specific usage" do
      output =
        capture_io(fn ->
          ProviderHelper.display_create_usage("github")
        end)

      assert output =~ "For OAuth2 providers:"
      assert output =~ "mix tango.providers.create github --client-id=xxx --client-secret=yyy"
      assert output =~ "For API key providers:"
      assert output =~ "mix tango.providers.create github --api-key=xxx"
    end

    test "display_general_usage/0 shows general usage information" do
      output =
        capture_io(fn ->
          ProviderHelper.display_general_usage()
        end)

      assert output =~ "Usage:"
      assert output =~ "Examples:"
      assert output =~ "mix tango.providers.create github --client-id=xxx --client-secret=yyy"
      assert output =~ "mix tango.providers.create stripe --api-key=sk_live_xxx"
    end
  end

  describe "parse_scopes/2" do
    test "parses multiple individual scopes correctly" do
      nango_config = %{"default_scopes" => ["offline_access", ".default"]}

      # Simulate OptionParser output with :keep for multiple --scope arguments
      opts = [
        scope: "Calendars.Read",
        scope: "Calendars.ReadWrite",
        scope: "User.Read",
        client_id: "test",
        client_secret: "test"
      ]

      result = ProviderHelper.parse_scopes(nango_config, opts)

      assert result == ["Calendars.Read", "Calendars.ReadWrite", "User.Read"]
    end

    test "parses comma-separated scopes correctly" do
      nango_config = %{"default_scopes" => ["offline_access"]}
      opts = [scopes: "Calendars.Read,Calendars.ReadWrite,User.Read"]

      result = ProviderHelper.parse_scopes(nango_config, opts)

      assert result == ["Calendars.Read", "Calendars.ReadWrite", "User.Read"]
    end

    test "combines individual and comma-separated scopes" do
      nango_config = %{}

      opts = [
        scope: "Calendars.Read",
        scope: "User.Read",
        scopes: "offline_access,Calendars.ReadWrite"
      ]

      result = ProviderHelper.parse_scopes(nango_config, opts)

      assert result == ["Calendars.Read", "User.Read", "offline_access", "Calendars.ReadWrite"]
    end

    test "uses catalog scopes when no user scopes provided" do
      nango_config = %{"default_scopes" => ["offline_access", ".default"]}
      opts = []

      result = ProviderHelper.parse_scopes(nango_config, opts)

      assert result == ["offline_access", ".default"]
    end

    test "user scopes override catalog scopes when provided" do
      nango_config = %{"default_scopes" => ["offline_access", ".default"]}
      opts = [scope: "Calendars.ReadWrite", scope: "User.Read"]

      result = ProviderHelper.parse_scopes(nango_config, opts)

      assert result == ["Calendars.ReadWrite", "User.Read"]
    end

    test "handles empty and whitespace-only scopes in comma-separated list" do
      nango_config = %{}
      opts = [scopes: "Calendars.Read, , User.Read,  ,offline_access"]

      result = ProviderHelper.parse_scopes(nango_config, opts)

      assert result == ["Calendars.Read", "User.Read", "offline_access"]
    end

    test "handles missing scopes gracefully" do
      nango_config = %{}
      opts = [client_id: "test", client_secret: "test"]

      result = ProviderHelper.parse_scopes(nango_config, opts)

      assert result == []
    end

    test "handles catalog config without default_scopes" do
      nango_config = %{"auth_mode" => "OAUTH2"}
      opts = [scope: "User.Read"]

      result = ProviderHelper.parse_scopes(nango_config, opts)

      assert result == ["User.Read"]
    end
  end
end

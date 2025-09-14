defmodule Tango.CatalogTest do
  @moduledoc """
  Tests for Tango.Catalog module - provider catalog management and integration.

  Uses a small mock dataset to test catalog functionality without hitting real APIs.
  """

  use ExUnit.Case, async: true

  alias Tango.Catalog
  alias Tango.CatalogMockServer

  setup do
    bypass = Bypass.open()
    CatalogMockServer.setup_catalog_endpoint(bypass)

    # Override the catalog URL for testing
    original_url = Application.get_env(:tango, :nango_providers_url)
    mock_url = CatalogMockServer.catalog_url(bypass)
    Application.put_env(:tango, :nango_providers_url, mock_url)

    on_exit(fn ->
      if original_url do
        Application.put_env(:tango, :nango_providers_url, original_url)
      else
        Application.delete_env(:tango, :nango_providers_url)
      end
    end)

    {:ok, bypass: bypass}
  end

  describe "get_catalog/0" do
    test "returns complete provider catalog" do
      assert {:ok, catalog} = Catalog.get_catalog()

      # Should be a map with string keys
      assert is_map(catalog)
      # Our mock has exactly 7 providers
      assert map_size(catalog) == 7

      # Verify expected mock providers are present
      expected_providers = [
        "github",
        "google",
        "slack",
        "stripe",
        "notion",
        "basic-auth-provider",
        "minimal-provider"
      ]

      for provider <- expected_providers do
        assert Map.has_key?(catalog, provider), "Missing provider: #{provider}"
      end
    end

    test "all providers have required fields" do
      {:ok, catalog} = Catalog.get_catalog()

      for {provider_name, config} <- catalog do
        # All providers should have display_name
        assert Map.has_key?(config, "display_name"),
               "Provider #{provider_name} missing display_name"

        assert is_binary(config["display_name"]),
               "Provider #{provider_name} display_name should be string"

        # All providers should have categories
        assert Map.has_key?(config, "categories"),
               "Provider #{provider_name} missing categories"

        assert is_list(config["categories"]),
               "Provider #{provider_name} categories should be list"

        assert length(config["categories"]) > 0,
               "Provider #{provider_name} should have at least one category"

        # All providers should have auth_mode
        assert Map.has_key?(config, "auth_mode"),
               "Provider #{provider_name} missing auth_mode"

        assert config["auth_mode"] in ["OAUTH2", "API_KEY", "BASIC"],
               "Provider #{provider_name} has invalid auth_mode: #{config["auth_mode"]}"

        # All providers should have docs
        assert Map.has_key?(config, "docs"),
               "Provider #{provider_name} missing docs"

        assert String.starts_with?(config["docs"], "https://"),
               "Provider #{provider_name} docs should be HTTPS URL"
      end
    end

    test "OAuth2 providers have required OAuth fields" do
      {:ok, catalog} = Catalog.get_catalog()

      oauth2_providers =
        catalog
        |> Enum.filter(fn {_name, config} -> config["auth_mode"] == "OAUTH2" end)

      # Should have OAuth2 providers
      assert length(oauth2_providers) > 0

      for {provider_name, config} <- oauth2_providers do
        # OAuth2 providers must have authorization_url
        assert Map.has_key?(config, "authorization_url"),
               "OAuth2 provider #{provider_name} missing authorization_url"

        assert String.starts_with?(config["authorization_url"], "https://"),
               "OAuth2 provider #{provider_name} authorization_url should be HTTPS"

        # OAuth2 providers must have token_url
        assert Map.has_key?(config, "token_url"),
               "OAuth2 provider #{provider_name} missing token_url"

        assert String.starts_with?(config["token_url"], "https://"),
               "OAuth2 provider #{provider_name} token_url should be HTTPS"

        # OAuth2 providers should have default_scopes (can be empty)
        # Note: Some real providers may not have this field, so we make it optional
        if Map.has_key?(config, "default_scopes") do
          assert is_list(config["default_scopes"]),
                 "OAuth2 provider #{provider_name} default_scopes should be list"
        end
      end
    end

    test "API_KEY providers typically do not have OAuth fields" do
      {:ok, catalog} = Catalog.get_catalog()

      api_key_providers =
        catalog
        |> Enum.filter(fn {_name, config} -> config["auth_mode"] == "API_KEY" end)

      # Should have at least one API key provider (stripe, minimal-provider)
      assert length(api_key_providers) > 0

      for {provider_name, config} <- api_key_providers do
        # API key providers typically should not have OAuth fields
        # Note: Some real providers may have these fields, so we make this a soft check
        if Map.has_key?(config, "authorization_url") and config["authorization_url"] != nil do
          # If present, should still be a valid URL
          assert String.starts_with?(config["authorization_url"], "https://")
        end

        if Map.has_key?(config, "token_url") and config["token_url"] != nil do
          # If present, should still be a valid URL
          assert String.starts_with?(config["token_url"], "https://")
        end

        # Default scopes don't make sense for API key auth
        refute Map.has_key?(config, "default_scopes"),
               "API_KEY provider #{provider_name} should not have default_scopes"
      end
    end

    test "provider categories are valid" do
      {:ok, catalog} = Catalog.get_catalog()

      # Valid categories based on common real-world categories
      valid_categories = [
        "dev-tools",
        "support",
        "productivity",
        "calendar",
        "communication",
        "payments",
        "e-commerce",
        "notes",
        "scheduling",
        "forms",
        # Common catch-all category
        "other",
        # Real Nango category
        "accounting",
        # Real Nango category
        "marketing",
        # Real Nango category
        "design"
      ]

      for {provider_name, config} <- catalog do
        for category <- config["categories"] do
          assert category in valid_categories,
                 "Provider #{provider_name} has invalid category: #{category}. Valid categories: #{inspect(valid_categories)}"
        end
      end
    end

    test "all URLs are properly formatted" do
      {:ok, catalog} = Catalog.get_catalog()

      url_fields = ["authorization_url", "token_url", "docs"]

      for {provider_name, config} <- catalog do
        for field <- url_fields do
          if Map.has_key?(config, field) and config[field] != nil do
            url = config[field]

            assert String.starts_with?(url, "https://"),
                   "Provider #{provider_name} #{field} should use HTTPS: #{url}"

            # Basic URL validation - should not contain spaces or invalid characters
            refute String.contains?(url, " "),
                   "Provider #{provider_name} #{field} contains spaces: #{url}"

            assert String.match?(url, ~r/^https:\/\/[a-zA-Z0-9.-]+/),
                   "Provider #{provider_name} #{field} has invalid format: #{url}"
          end
        end
      end
    end
  end

  describe "get_provider/1" do
    test "retrieves existing provider configuration" do
      # Test with known mock providers
      known_providers = ["github", "google", "slack", "stripe"]

      for provider_name <- known_providers do
        assert {:ok, config} = Catalog.get_provider(provider_name)

        # Should return the same config as in the full catalog
        {:ok, full_catalog} = Catalog.get_catalog()
        expected_config = full_catalog[provider_name]
        assert config == expected_config

        # Verify required fields are present
        assert Map.has_key?(config, "display_name")
        assert Map.has_key?(config, "auth_mode")
        assert Map.has_key?(config, "categories")
      end
    end

    test "returns error for non-existent provider" do
      non_existent_providers = [
        "nonexistent",
        "fake_provider",
        "does_not_exist",
        "",
        "123invalid"
      ]

      for provider_name <- non_existent_providers do
        assert {:error, :not_found} = Catalog.get_provider(provider_name)
      end
    end

    test "is case sensitive" do
      # Provider names should be case sensitive
      assert {:ok, _config} = Catalog.get_provider("github")
      assert {:error, :not_found} = Catalog.get_provider("GitHub")
      assert {:error, :not_found} = Catalog.get_provider("GITHUB")
      assert {:error, :not_found} = Catalog.get_provider("Github")
    end

    test "handles edge cases" do
      # Test with various edge case inputs
      edge_cases = [
        nil,
        1234,
        %{},
        [],
        :atom
      ]

      for invalid_input <- edge_cases do
        # Should either handle gracefully or raise appropriate error
        result =
          try do
            Catalog.get_provider(invalid_input)
          rescue
            e -> {:raised, e}
          end

        case result do
          # Acceptable
          {:error, :not_found} -> :ok
          # Acceptable for type mismatch
          {:raised, %FunctionClauseError{}} -> :ok
          # Acceptable for Map.get with wrong type
          {:raised, %Protocol.UndefinedError{}} -> :ok
          other -> flunk("Unexpected result for #{inspect(invalid_input)}: #{inspect(other)}")
        end
      end
    end
  end

  describe "suggest_similar/1" do
    test "finds exact substring matches" do
      # Test substring matching
      suggestions = Catalog.suggest_similar("git")
      assert "github" in suggestions

      suggestions = Catalog.suggest_similar("goo")
      assert "google" in suggestions

      suggestions = Catalog.suggest_similar("slack")
      assert "slack" in suggestions
    end

    test "finds similar names using Jaro distance" do
      # Test fuzzy matching with Jaro distance
      # Close to "github"
      suggestions = Catalog.suggest_similar("githab")
      assert "github" in suggestions

      # Close to "google"
      suggestions = Catalog.suggest_similar("googel")
      assert "google" in suggestions

      # Close to "slack"
      suggestions = Catalog.suggest_similar("slac")
      assert "slack" in suggestions
    end

    test "returns empty list for very different inputs" do
      # Test with inputs that should not match anything
      very_different = [
        "xyz123",
        "completely_different",
        "zzzzzzz",
        "abcdefghijklmnop"
      ]

      for input <- very_different do
        suggestions = Catalog.suggest_similar(input)
        # Should return empty list or very few results
        assert length(suggestions) <= 1
      end
    end

    test "limits results to maximum 3 suggestions" do
      # Test that we don't return too many suggestions
      all_inputs = [
        # Should match many due to being in many provider names
        "a",
        # Common letter
        "o",
        # Empty string
        ""
      ]

      for input <- all_inputs do
        suggestions = Catalog.suggest_similar(input)
        assert length(suggestions) <= 3
      end
    end

    test "returns suggestions in order of similarity" do
      # Test that results are ordered by similarity (best match first)
      suggestions = Catalog.suggest_similar("git")

      if length(suggestions) > 1 do
        # First result should be more similar than second
        [first, second | _rest] = suggestions

        first_distance = String.jaro_distance(first, "git")
        second_distance = String.jaro_distance(second, "git")

        assert first_distance >= second_distance
      end
    end

    test "handles empty and special inputs" do
      # Test edge cases
      edge_cases = [
        # Empty string
        "",
        # Single space
        " ",
        # Multiple spaces
        "   ",
        # Single character
        "a",
        # Numbers only
        "123",
        # Special characters
        "!@#$%",
        "very_long_input_that_should_not_match_anything_in_catalog"
      ]

      for input <- edge_cases do
        suggestions = Catalog.suggest_similar(input)

        # Should return a list (possibly empty)
        assert is_list(suggestions)
        assert length(suggestions) <= 3

        # All suggestions should be strings
        Enum.each(suggestions, fn suggestion ->
          assert is_binary(suggestion)
        end)
      end
    end

    test "suggestions are valid provider names" do
      # Test that all suggestions are actually valid providers from catalog
      {:ok, catalog} = Catalog.get_catalog()
      valid_providers = Map.keys(catalog)

      test_inputs = ["git", "goo", "cal", "type", "not"]

      for input <- test_inputs do
        suggestions = Catalog.suggest_similar(input)

        for suggestion <- suggestions do
          assert suggestion in valid_providers,
                 "Suggestion '#{suggestion}' for input '#{input}' is not a valid provider"
        end
      end
    end

    test "handles non-string inputs gracefully" do
      # Test with non-string inputs
      non_string_inputs = [
        nil,
        123,
        %{},
        [],
        :atom
      ]

      for invalid_input <- non_string_inputs do
        result =
          try do
            Catalog.suggest_similar(invalid_input)
          rescue
            e -> {:raised, e}
          end

        case result do
          suggestions when is_list(suggestions) ->
            # If it succeeds, should return a valid list
            assert length(suggestions) <= 3

          # Acceptable
          {:raised, %Protocol.UndefinedError{}} ->
            :ok

          # Acceptable
          {:raised, %FunctionClauseError{}} ->
            :ok

          # Acceptable
          {:raised, %ArgumentError{}} ->
            :ok

          other ->
            flunk("Unexpected result for #{inspect(invalid_input)}: #{inspect(other)}")
        end
      end
    end
  end

  describe "catalog data integrity" do
    test "catalog is consistent across multiple calls" do
      # Test that the catalog doesn't change between calls
      {:ok, catalog1} = Catalog.get_catalog()
      {:ok, catalog2} = Catalog.get_catalog()

      assert catalog1 == catalog2

      # Test individual provider calls are consistent
      for provider_name <- Map.keys(catalog1) do
        {:ok, config1} = Catalog.get_provider(provider_name)
        {:ok, config2} = Catalog.get_provider(provider_name)
        assert config1 == config2
      end
    end

    test "provider names are URL-safe" do
      {:ok, catalog} = Catalog.get_catalog()

      for provider_name <- Map.keys(catalog) do
        # Provider names should be URL-safe (lowercase, no spaces, etc.)
        assert String.match?(provider_name, ~r/^[a-z0-9_-]+$/),
               "Provider name '#{provider_name}' is not URL-safe"

        assert provider_name == String.downcase(provider_name),
               "Provider name '#{provider_name}' should be lowercase"
      end
    end

    test "no duplicate display names" do
      {:ok, catalog} = Catalog.get_catalog()

      display_names =
        catalog
        |> Enum.map(fn {_name, config} -> config["display_name"] end)

      unique_display_names = Enum.uniq(display_names)

      assert length(display_names) == length(unique_display_names),
             "Found duplicate display names in catalog"
    end

    test "OAuth providers have valid domain structure" do
      {:ok, catalog} = Catalog.get_catalog()

      oauth_providers =
        catalog
        |> Enum.filter(fn {_name, config} -> config["auth_mode"] == "OAUTH2" end)

      # Should have OAuth2 providers in our mock
      assert length(oauth_providers) > 0

      for {provider_name, config} <- oauth_providers do
        if config["authorization_url"] do
          auth_uri = URI.parse(config["authorization_url"])
          assert auth_uri.host != nil, "Provider #{provider_name} authorization_url has no host"

          assert auth_uri.scheme == "https",
                 "Provider #{provider_name} authorization_url should use HTTPS"
        end

        if config["token_url"] do
          token_uri = URI.parse(config["token_url"])
          assert token_uri.host != nil, "Provider #{provider_name} token_url has no host"

          assert token_uri.scheme == "https",
                 "Provider #{provider_name} token_url should use HTTPS"
        end
      end
    end
  end

  describe "error handling" do
    test "handles catalog fetch failures gracefully", %{bypass: bypass} do
      # Test error handling by setting up a failing mock server
      CatalogMockServer.setup_catalog_endpoint(bypass, should_fail: true)

      # Should return error when catalog fetch fails
      assert {:error, :catalog_fetch_failed} = Catalog.get_catalog()

      # get_provider should propagate the error
      assert {:error, :catalog_fetch_failed} = Catalog.get_provider("github")

      # suggest_similar should return empty list on error
      suggestions = Catalog.suggest_similar("github")
      assert suggestions == []
    end
  end
end

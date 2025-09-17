defmodule Tango.ValidationTest do
  @moduledoc """
  Unit tests for input validation functions.

  Tests tenant ID validation, OAuth parameter validation,
  URL validation, and security input sanitization.
  """

  use ExUnit.Case, async: true

  alias Tango.Validation

  describe "validate_tenant_id/1" do
    test "accepts valid tenant IDs" do
      valid_ids = [
        "user-123",
        "tenant_456",
        "org789",
        "user-with-dashes-123",
        "tenant_with_underscores_456",
        "UPPERCASE-TENANT",
        "MixedCase_123-abc",
        # Single character
        "a",
        # Maximum length
        String.duplicate("a", 255)
      ]

      Enum.each(valid_ids, fn id ->
        assert :ok = Validation.validate_tenant_id(id), "Failed for: #{id}"
      end)
    end

    test "rejects invalid tenant IDs" do
      invalid_ids = [
        # Empty
        "",
        # Whitespace only
        " ",
        "tenant with spaces",
        # Email-like
        "tenant@email.com",
        # SQL injection attempt
        "tenant;DROP TABLE users;",
        # XSS attempt
        "tenant<script>",
        # Newline
        "tenant\n123",
        # Tab
        "tenant\t123",
        # Slash
        "tenant/123",
        # Backslash
        "tenant\\123",
        # Dot
        "tenant.123",
        # Comma
        "tenant,123",
        # Colon
        "tenant:123",
        # Pipe
        "tenant|123",
        # Too long
        String.duplicate("a", 256)
      ]

      Enum.each(invalid_ids, fn id ->
        assert {:error, _reason} = Validation.validate_tenant_id(id),
               "Should have failed for: #{id}"
      end)
    end

    test "rejects non-string inputs" do
      invalid_types = [nil, 123, :atom, %{}, [], true]

      Enum.each(invalid_types, fn input ->
        assert {:error, :invalid_tenant_id} = Validation.validate_tenant_id(input)
      end)
    end

    test "returns specific error for too long tenant ID" do
      too_long = String.duplicate("a", 256)
      assert {:error, :tenant_id_too_long} = Validation.validate_tenant_id(too_long)
    end
  end

  describe "validate_state/1" do
    test "accepts valid OAuth state parameters" do
      valid_states = [
        :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false),
        :crypto.strong_rand_bytes(24) |> Base.url_encode64(padding: false),
        # States need to be longer than 16 bytes
        "abcdef123456789012345",
        # With allowed special chars
        "abc-def_123456789012",
        # Mixed case
        "ABC123def456789012345"
      ]

      Enum.each(valid_states, fn state ->
        assert :ok = Validation.validate_state(state), "Failed for: #{state}"
      end)
    end

    test "rejects invalid OAuth state parameters" do
      invalid_states = [
        # Empty
        "",
        # Whitespace
        " ",
        "state with spaces",
        # XSS attempt
        "state<script>",
        # SQL injection attempt
        "state;DROP TABLE",
        # Newline
        "state\n123",
        # Tab
        "state\t123",
        # Slash
        "state/path",
        # Backslash
        "state\\path",
        # @ symbol
        "state@email",
        # Hash
        "state#hash",
        # Percent encoding
        "state%encoded",
        # Extremely long
        String.duplicate("a", 1000)
      ]

      Enum.each(invalid_states, fn state ->
        assert {:error, _reason} = Validation.validate_state(state),
               "Should have failed for: #{state}"
      end)
    end

    test "rejects non-string state parameters" do
      invalid_types = [nil, 123, :atom, %{}, [], true]

      Enum.each(invalid_types, fn input ->
        assert {:error, :invalid_state} = Validation.validate_state(input)
      end)
    end
  end

  describe "validate_authorization_code/1" do
    test "accepts valid authorization codes including provider-specific formats" do
      valid_codes = [
        "abc123def456",
        :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false),
        "code-with-dashes",
        "code_with_underscores",
        "UPPERCASE-CODE",
        "MixedCase123",
        # Google-style codes with forward slashes and special chars
        "4/0AX4XfWh_abc123_def456-xyz789",
        "4/abc-def/ghi_jkl.mno",
        # GitHub-style codes
        "ghu_1234567890abcdef",
        # URL-safe characters
        "code.with.dots",
        "code/with/slashes",
        # Long but reasonable
        String.duplicate("a", 512)
      ]

      Enum.each(valid_codes, fn code ->
        assert :ok = Validation.validate_authorization_code(code), "Failed for: #{code}"
      end)
    end

    test "rejects invalid authorization codes for security reasons" do
      invalid_codes = [
        # Empty/whitespace only
        "",
        "   ",
        "\t",
        "\n",
        # Too long
        String.duplicate("a", 2000)
      ]

      Enum.each(invalid_codes, fn code ->
        assert {:error, _reason} = Validation.validate_authorization_code(code),
               "Should have failed for: #{code}"
      end)
    end
  end

  describe "validate_redirect_uri/1" do
    test "accepts valid redirect URIs" do
      valid_uris = [
        "https://example.com/callback",
        "https://app.com:8080/oauth/callback",
        "https://sub.domain.com/auth/callback?param=value",
        # Localhost HTTP allowed
        "http://localhost:3000/callback",
        # Localhost IP
        "http://127.0.0.1:4000/callback",
        "https://app.com/callback#fragment"
      ]

      Enum.each(valid_uris, fn uri ->
        assert :ok = Validation.validate_redirect_uri(uri), "Failed for: #{uri}"
      end)
    end

    test "rejects dangerous redirect URIs" do
      dangerous_uris = [
        "javascript:alert('xss')",
        "data:text/html,<script>alert('xss')</script>",
        "file:///etc/passwd",
        "ftp://malicious.com/file",
        "",
        " ",
        "not-a-url",
        # Custom schemes not allowed
        "app://oauth/callback",
        "com.myapp://oauth"
      ]

      Enum.each(dangerous_uris, fn uri ->
        assert {:error, _reason} = Validation.validate_redirect_uri(uri),
               "Should have failed for: #{uri}"
      end)
    end

    test "validates URI format" do
      assert {:error, :invalid_redirect_uri} = Validation.validate_redirect_uri("not a uri")
      # https:// is actually valid - it parses as a URI
      assert :ok = Validation.validate_redirect_uri("https://")

      assert {:error, :invalid_redirect_uri} =
               Validation.validate_redirect_uri("://missing-scheme")
    end
  end

  describe "validate_scopes/1" do
    test "accepts valid scope arrays including URL-based scopes" do
      valid_scope_lists = [
        [],
        ["read"],
        ["read", "write"],
        ["user", "repo", "gist"],
        ["user:email", "repo:status"],
        ["read_user", "write_repo"],
        ["openid", "profile", "email"],
        # Google Calendar API scopes (URL-based)
        ["https://www.googleapis.com/auth/calendar"],
        ["https://www.googleapis.com/auth/calendar.readonly"],
        # Microsoft Graph API scopes
        ["https://graph.microsoft.com/User.Read"],
        ["https://graph.microsoft.com/Calendars.ReadWrite"],
        # Mixed formats
        ["read", "https://api.example.com/auth/scope", "user:profile"],
        # Complex URL scopes with query params
        ["https://api.example.com/auth?scope=read&version=v1"],
        # Scopes with spaces and special characters (modern OAuth providers)
        ["scope with spaces"],
        ["scope.with.dots"],
        ["scope/with/slashes"],
        ["scope:with:colons"],
        ["scope-with-dashes"],
        ["scope_with_underscores"]
      ]

      Enum.each(valid_scope_lists, fn scopes ->
        assert :ok = Validation.validate_scopes(scopes), "Failed for: #{inspect(scopes)}"
      end)
    end

    test "rejects invalid scope formats" do
      invalid_scopes = [
        # Non-string in array
        [123],
        # Atom in array
        [:atom],
        # String instead of array
        "not-an-array",
        nil,
        %{},
        # Empty strings in array
        ["valid", ""],
        ["", "also-valid"],
        # Very long scopes
        [String.duplicate("a", 1000)]
      ]

      Enum.each(invalid_scopes, fn scopes ->
        assert {:error, _reason} = Validation.validate_scopes(scopes),
               "Should have failed for: #{inspect(scopes)}"
      end)
    end
  end

  describe "validate_provider_slug/1" do
    test "accepts valid provider slugs" do
      valid_slugs = [
        "github",
        "google-oauth",
        "stripe-api",
        "custom_provider",
        "provider-123",
        "lowercase-slug",
        "slug_with_underscores",
        # Single character
        "a",
        # Shorter to avoid length limit
        String.duplicate("a", 50)
      ]

      Enum.each(valid_slugs, fn slug ->
        assert :ok = Validation.validate_provider_slug(slug), "Failed for: #{slug}"
      end)
    end

    test "rejects invalid provider slugs" do
      invalid_slugs = [
        # Empty
        "",
        # Whitespace
        " ",
        "slug with spaces",
        "slug@email",
        "slug<script>",
        "slug;DROP",
        "slug\n123",
        "slug/path",
        "slug\\path",
        "slug:port",
        # Should reject uppercase
        "UPPERCASE",
        # Too long
        String.duplicate("a", 300)
      ]

      Enum.each(invalid_slugs, fn slug ->
        assert {:error, _reason} = Validation.validate_provider_slug(slug),
               "Should have failed for: #{slug}"
      end)
    end
  end

  describe "validate_oauth_url/1" do
    test "accepts valid OAuth URLs" do
      valid_urls = [
        "https://example.com",
        "https://api.example.com/v1/oauth",
        "https://example.com:8080/path",
        "https://sub.domain.example.com/path?query=value",
        # HTTPS URLs
        "https://localhost:3000",
        "https://127.0.0.1:4000/path"
      ]

      Enum.each(valid_urls, fn url ->
        assert :ok = Validation.validate_oauth_url(url), "Failed for: #{url}"
      end)
    end

    test "rejects invalid OAuth URLs" do
      invalid_urls = [
        "",
        " ",
        "not-a-url",
        # Non-HTTP/HTTPS
        "ftp://example.com",
        "javascript:alert(1)",
        "data:text/html,<script>",
        "file:///etc/passwd",
        # Missing scheme
        "://example.com"
      ]

      Enum.each(invalid_urls, fn url ->
        assert {:error, _reason} = Validation.validate_oauth_url(url),
               "Should have failed for: #{url}"
      end)
    end

    test "handles HTTP localhost URLs" do
      # localhost returns ok
      assert :ok = Validation.validate_oauth_url("http://localhost:3000/path")

      # IP address returns warning
      assert {:warning, :insecure_oauth_url} =
               Validation.validate_oauth_url("http://127.0.0.1:4000")

      # These return warnings for HTTP (not errors)
      assert {:warning, :insecure_oauth_url} = Validation.validate_oauth_url("http://example.com")

      assert {:warning, :insecure_oauth_url} =
               Validation.validate_oauth_url("http://api.github.com/oauth")
    end
  end

  describe "edge cases and security" do
    test "handles extremely long inputs gracefully" do
      very_long_input = String.duplicate("a", 10_000)

      # Should not crash, should return appropriate errors
      assert {:error, _} = Validation.validate_tenant_id(very_long_input)
      assert {:error, _} = Validation.validate_state(very_long_input)
      assert {:error, _} = Validation.validate_authorization_code(very_long_input)
    end

    test "handles unicode characters appropriately" do
      unicode_inputs = [
        # Greek letters
        "tenant-αβγ",
        # Emoji
        "tenant-🚀",
        # Chinese characters
        "tenant-中文",
        # Arabic
        "tenant-العربية"
      ]

      # Should reject unicode in tenant IDs for security
      Enum.each(unicode_inputs, fn input ->
        assert {:error, :invalid_tenant_id} = Validation.validate_tenant_id(input)
      end)
    end

    test "validates against injection patterns for tenant_id and state only" do
      injection_attempts = [
        "'; DROP TABLE users; --",
        "<script>alert('xss')</script>",
        "../../../etc/passwd",
        # URL encoded script tag
        "%3Cscript%3E",
        # Null byte
        "\u0000",
        # Command injection
        "$(rm -rf /)"
      ]

      Enum.each(injection_attempts, fn attempt ->
        # These fields require strict validation for security
        assert {:error, _} = Validation.validate_tenant_id(attempt)
        assert {:error, _} = Validation.validate_state(attempt)
        assert {:error, _} = Validation.validate_provider_slug(attempt)

        # Authorization codes are provider-generated, so we don't validate format
        # (only length and non-empty)
      end)
    end
  end
end

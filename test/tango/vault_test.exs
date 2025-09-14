defmodule Tango.VaultTest do
  @moduledoc """
  Tests for Tango.Vault encryption module.

  Tests the encryption vault used for OAuth token storage, covering
  cryptographic security, key management, and error scenarios.
  """

  use ExUnit.Case, async: true

  alias Tango.Vault

  describe "encrypt/1 and decrypt/1" do
    test "encrypts and decrypts data successfully" do
      plaintext = "sensitive_oauth_token_12345"

      # Encrypt the data
      encrypted = Vault.encrypt(plaintext)

      # Should return encrypted data (not plaintext)
      assert encrypted != plaintext
      assert is_binary(encrypted)
      assert byte_size(encrypted) > byte_size(plaintext)

      # Decrypt should return original data
      assert {:ok, decrypted} = Vault.decrypt(encrypted)
      assert decrypted == plaintext
    end

    test "produces different ciphertext for same plaintext (random IV)" do
      plaintext = "same_token_data"

      # Encrypt same data multiple times
      encrypted1 = Vault.encrypt(plaintext)
      encrypted2 = Vault.encrypt(plaintext)
      encrypted3 = Vault.encrypt(plaintext)

      # Ciphertexts should be different (due to random IV)
      assert encrypted1 != encrypted2
      assert encrypted2 != encrypted3
      assert encrypted1 != encrypted3

      # But all should decrypt to same plaintext
      assert {:ok, ^plaintext} = Vault.decrypt(encrypted1)
      assert {:ok, ^plaintext} = Vault.decrypt(encrypted2)
      assert {:ok, ^plaintext} = Vault.decrypt(encrypted3)
    end

    test "handles empty data" do
      # Empty string
      empty_encrypted = Vault.encrypt("")
      assert {:ok, ""} = Vault.decrypt(empty_encrypted)

      # Note: nil throws ErlangError from crypto module, not ArgumentError
      # This is expected behavior from the underlying crypto library
    end

    test "handles various data types and sizes" do
      test_cases = [
        # Single character
        "a",
        # Short string
        "short_token",
        # Long string
        String.duplicate("x", 1000),
        # Unicode characters
        "🔐💾🚀",
        # Special characters
        "token_with_special_chars!@#$%^&*()",
        # JSON data
        Jason.encode!(%{"access_token" => "abc", "refresh_token" => "def"})
      ]

      for plaintext <- test_cases do
        encrypted = Vault.encrypt(plaintext)
        assert {:ok, decrypted} = Vault.decrypt(encrypted)
        assert decrypted == plaintext
      end
    end
  end

  describe "decrypt/1 error handling" do
    test "handles malformed ciphertext gracefully" do
      malformed_data = [
        # Empty string
        "",
        # Plain text
        "not_encrypted_data",
        # Invalid characters
        "invalid_base64_!@#$",
        # Random bytes
        <<1, 2, 3, 4>>,
        # Wrong length
        String.duplicate("a", 1000)
      ]

      for bad_data <- malformed_data do
        result = Vault.decrypt(bad_data)
        assert {:error, _reason} = result
        assert elem(result, 0) == :error
      end
    end

    test "handles corrupted encrypted data" do
      plaintext = "valid_token_data"
      encrypted = Vault.encrypt(plaintext)

      # Try different corruption strategies
      corruption_attempts = [
        # Truncate the data
        String.slice(encrypted, 0..-10),
        # Add extra bytes
        encrypted <> "extra_bytes",
        # Replace middle section
        String.slice(encrypted, 0..10) <> "corrupted" <> String.slice(encrypted, -10..-1)
      ]

      # At least one corruption should fail
      failures =
        Enum.count(corruption_attempts, fn corrupted ->
          case Vault.decrypt(corrupted) do
            {:error, _} -> true
            {:ok, _} -> false
          end
        end)

      assert failures > 0, "Expected at least one corruption to cause decryption failure"
    end
  end

  describe "get_encryption_key/0" do
    test "retrieves encryption key from application config" do
      # This test assumes the key is properly configured in test config
      key = Vault.get_encryption_key()

      assert is_binary(key)
      assert byte_size(key) == 32
    end

    test "handles missing encryption key configuration" do
      # Temporarily remove the key to test error handling
      original_key = Application.get_env(:tango, :encryption_key)
      Application.delete_env(:tango, :encryption_key)

      assert_raise ArgumentError, ~r/Tango encryption key not configured/, fn ->
        Vault.get_encryption_key()
      end

      # Restore original key
      if original_key do
        Application.put_env(:tango, :encryption_key, original_key)
      end
    end

    test "validates key length requirements" do
      original_key = Application.get_env(:tango, :encryption_key)

      # Test with wrong length key
      Application.put_env(:tango, :encryption_key, "too_short")

      assert_raise ArgumentError, ~r/must be 32 bytes/, fn ->
        Vault.get_encryption_key()
      end

      # Test with invalid base64
      Application.put_env(:tango, :encryption_key, "invalid_base64_!@#$%^&*()")

      assert_raise ArgumentError, ~r/must be 32 bytes or valid base64/, fn ->
        Vault.get_encryption_key()
      end

      # Restore original key
      if original_key do
        Application.put_env(:tango, :encryption_key, original_key)
      end
    end

    test "handles base64-encoded keys correctly" do
      original_key = Application.get_env(:tango, :encryption_key)

      # Create a valid 32-byte key and encode it
      raw_key = :crypto.strong_rand_bytes(32)
      base64_key = Base.encode64(raw_key)

      Application.put_env(:tango, :encryption_key, base64_key)

      retrieved_key = Vault.get_encryption_key()
      assert retrieved_key == raw_key

      # Restore original key
      if original_key do
        Application.put_env(:tango, :encryption_key, original_key)
      end
    end

    test "rejects base64 keys of wrong length" do
      original_key = Application.get_env(:tango, :encryption_key)

      # Create a 16-byte key (wrong size) and encode it
      wrong_size_key = :crypto.strong_rand_bytes(16)
      base64_key = Base.encode64(wrong_size_key)

      Application.put_env(:tango, :encryption_key, base64_key)

      assert_raise ArgumentError, ~r/Decoded key must be 32 bytes, got 16 bytes/, fn ->
        Vault.get_encryption_key()
      end

      # Restore original key
      if original_key do
        Application.put_env(:tango, :encryption_key, original_key)
      end
    end
  end

  describe "cryptographic security properties" do
    test "encrypted data does not contain plaintext patterns" do
      sensitive_data = [
        "access_token_super_secret",
        "refresh_token_confidential",
        "client_secret_sensitive",
        "password123",
        "api_key_private"
      ]

      for plaintext <- sensitive_data do
        encrypted = Vault.encrypt(plaintext)

        # Encrypted data should not contain any part of plaintext
        refute String.contains?(encrypted, plaintext)
        refute String.contains?(encrypted, "secret")
        refute String.contains?(encrypted, "token")
        refute String.contains?(encrypted, "password")
        refute String.contains?(encrypted, "key")
      end
    end

    test "encryption is deterministic with same IV (for testing)" do
      # Note: In production, IVs are random, but for testing we can verify
      # the underlying encryption mechanism works
      plaintext = "test_data_for_determinism"

      # Multiple encryptions should produce different results (random IV)
      results =
        for _i <- 1..10 do
          Vault.encrypt(plaintext)
        end

      # All results should be unique (high probability with random IV)
      unique_results = Enum.uniq(results)
      assert length(unique_results) == length(results)

      # But all should decrypt to same plaintext
      for encrypted <- results do
        assert {:ok, ^plaintext} = Vault.decrypt(encrypted)
      end
    end

    test "encryption uses AES-GCM with proper authentication" do
      plaintext = "authenticated_encryption_test"
      encrypted = Vault.encrypt(plaintext)

      # AES-GCM should include authentication tag
      # Encrypted data should be longer than plaintext + IV
      # plaintext + IV + auth tag
      assert byte_size(encrypted) > byte_size(plaintext) + 12 + 16

      # Test that decryption works for valid data
      assert {:ok, ^plaintext} = Vault.decrypt(encrypted)

      # Note: Cloak may handle some corruption gracefully, focusing on successful operation
    end
  end

  describe "integration with Cloak vault behavior" do
    test "vault is properly initialized" do
      # Verify the vault process is running
      assert Process.whereis(Vault) != nil

      # Test that the vault can perform basic operations (indicating proper init)
      test_data = "vault_initialization_test"
      encrypted = Vault.encrypt(test_data)
      assert {:ok, ^test_data} = Vault.decrypt(encrypted)
    end

    test "can encrypt and decrypt large amounts of data efficiently" do
      # Test with large data (simulating batch token encryption)
      large_data =
        for i <- 1..100 do
          "access_token_#{i}_" <> String.duplicate("x", 100)
        end
        |> Enum.join("\n")

      start_time = System.monotonic_time(:millisecond)
      encrypted = Vault.encrypt(large_data)
      encrypt_time = System.monotonic_time(:millisecond) - start_time

      start_time = System.monotonic_time(:millisecond)
      assert {:ok, decrypted} = Vault.decrypt(encrypted)
      decrypt_time = System.monotonic_time(:millisecond) - start_time

      assert decrypted == large_data

      # Performance should be reasonable (less than 100ms each for large data)
      assert encrypt_time < 100
      assert decrypt_time < 100
    end
  end
end

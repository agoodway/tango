defmodule Tango.Types.EncryptedBinaryTest do
  use ExUnit.Case, async: true

  alias Tango.Types.EncryptedBinary

  describe "cast/1" do
    test "casts nil to nil" do
      assert {:ok, nil} = EncryptedBinary.cast(nil)
    end

    test "casts binary strings" do
      assert {:ok, "secret_token"} = EncryptedBinary.cast("secret_token")
      assert {:ok, ""} = EncryptedBinary.cast("")

      assert {:ok, "long_binary_string_with_special_chars_!@#$%"} =
               EncryptedBinary.cast("long_binary_string_with_special_chars_!@#$%")
    end

    test "rejects non-binary values" do
      assert :error = EncryptedBinary.cast(123)
      assert :error = EncryptedBinary.cast(:atom)
      assert :error = EncryptedBinary.cast(%{})
      assert :error = EncryptedBinary.cast([])
      assert :error = EncryptedBinary.cast(true)
    end
  end

  describe "load/1" do
    test "loads nil to nil" do
      assert {:ok, nil} = EncryptedBinary.load(nil)
    end

    test "loads encrypted binary and decrypts it" do
      # First encrypt some data
      plaintext = "sensitive_access_token"
      encrypted = Tango.Vault.encrypt(plaintext)

      # Now test loading it
      assert {:ok, ^plaintext} = EncryptedBinary.load(encrypted)
    end

    test "handles decryption errors" do
      # Invalid encrypted data should return :error
      assert :error = EncryptedBinary.load("invalid_encrypted_data")
      assert :error = EncryptedBinary.load("corrupted_ciphertext_xyz")
    end

    test "rejects non-binary values" do
      assert :error = EncryptedBinary.load(123)
      assert :error = EncryptedBinary.load(:atom)
      assert :error = EncryptedBinary.load(%{})
      assert :error = EncryptedBinary.load([])
    end
  end

  describe "dump/1" do
    test "dumps nil to nil" do
      assert {:ok, nil} = EncryptedBinary.dump(nil)
    end

    test "dumps plaintext by encrypting it" do
      plaintext = "refresh_token_abc123"

      assert {:ok, encrypted} = EncryptedBinary.dump(plaintext)
      assert is_binary(encrypted)
      # Should be encrypted, not plaintext
      assert encrypted != plaintext

      # Verify we can decrypt it back
      assert {:ok, ^plaintext} = Tango.Vault.decrypt(encrypted)
    end

    test "handles empty strings" do
      assert {:ok, encrypted} = EncryptedBinary.dump("")
      assert is_binary(encrypted)

      # Verify we can decrypt it back to empty string
      assert {:ok, ""} = Tango.Vault.decrypt(encrypted)
    end

    test "rejects non-binary values" do
      assert :error = EncryptedBinary.dump(123)
      assert :error = EncryptedBinary.dump(:atom)
      assert :error = EncryptedBinary.dump(%{})
      assert :error = EncryptedBinary.dump([])
      assert :error = EncryptedBinary.dump(true)
    end
  end

  describe "type/0" do
    test "returns binary type" do
      assert EncryptedBinary.type() == :binary
    end
  end

  describe "round-trip encryption/decryption" do
    test "encrypts and decrypts data correctly" do
      test_cases = [
        "simple_token",
        "complex_token_with_symbols_!@#$%^&*()",
        "very_long_token_" <> String.duplicate("a", 500),
        "unicode_token_🔒🔑",
        # Empty string
        "",
        "token\nwith\nnewlines",
        "token\twith\ttabs"
      ]

      for plaintext <- test_cases do
        # Cast -> Dump -> Load -> should get original back
        assert {:ok, ^plaintext} = EncryptedBinary.cast(plaintext)
        assert {:ok, encrypted} = EncryptedBinary.dump(plaintext)
        assert {:ok, ^plaintext} = EncryptedBinary.load(encrypted)
      end
    end

    test "different plaintexts produce different ciphertexts" do
      token1 = "access_token_1"
      token2 = "access_token_2"

      assert {:ok, encrypted1} = EncryptedBinary.dump(token1)
      assert {:ok, encrypted2} = EncryptedBinary.dump(token2)

      # Different plaintexts should produce different ciphertexts
      assert encrypted1 != encrypted2
    end

    test "same plaintext produces different ciphertexts (due to random IV)" do
      token = "access_token"

      assert {:ok, encrypted1} = EncryptedBinary.dump(token)
      assert {:ok, encrypted2} = EncryptedBinary.dump(token)

      # Due to random IV, same plaintext should produce different ciphertexts
      assert encrypted1 != encrypted2

      # But both should decrypt to the same plaintext
      assert {:ok, ^token} = EncryptedBinary.load(encrypted1)
      assert {:ok, ^token} = EncryptedBinary.load(encrypted2)
    end
  end

  describe "integration with Ecto" do
    test "behaves correctly in Ecto changeset context" do
      # Simulate what Ecto does during casting and validation
      value = "oauth_access_token"

      # Cast (user input validation)
      assert {:ok, cast_value} = EncryptedBinary.cast(value)
      assert cast_value == value

      # Dump (before saving to database)
      assert {:ok, dumped_value} = EncryptedBinary.dump(cast_value)
      assert is_binary(dumped_value)
      # Should be encrypted
      assert dumped_value != value

      # Load (when reading from database)
      assert {:ok, loaded_value} = EncryptedBinary.load(dumped_value)
      # Should be decrypted back to original
      assert loaded_value == value
    end

    test "handles nil values throughout Ecto lifecycle" do
      # Cast nil
      assert {:ok, nil} = EncryptedBinary.cast(nil)

      # Dump nil
      assert {:ok, nil} = EncryptedBinary.dump(nil)

      # Load nil
      assert {:ok, nil} = EncryptedBinary.load(nil)
    end
  end

  describe "error handling" do
    test "gracefully handles corrupt encrypted data" do
      # Simulate corrupted database data
      corrupted_data = "corrupted_binary_data"

      assert :error = EncryptedBinary.load(corrupted_data)
    end

    test "validates input types at each stage" do
      # Cast should only accept binary or nil
      assert :error = EncryptedBinary.cast(123)

      # Dump should only accept binary or nil
      assert :error = EncryptedBinary.dump(123)

      # Load should only accept binary or nil
      assert :error = EncryptedBinary.load(123)
    end
  end

  describe "security properties" do
    test "encrypted data does not contain plaintext" do
      sensitive_data = "super_secret_oauth_token_12345"

      assert {:ok, encrypted} = EncryptedBinary.dump(sensitive_data)

      # Encrypted data should not contain the plaintext
      refute String.contains?(encrypted, sensitive_data)
      refute String.contains?(encrypted, "super_secret")
      refute String.contains?(encrypted, "oauth_token")
      refute String.contains?(encrypted, "12345")
    end

    test "encrypted data is sufficiently long (includes IV, tag, etc.)" do
      short_data = "hi"

      assert {:ok, encrypted} = EncryptedBinary.dump(short_data)

      # Encrypted data should be longer than plaintext due to IV, tag, etc.
      # AES-GCM typically adds at least 16 bytes (IV) + 16 bytes (tag) + overhead
      assert byte_size(encrypted) > byte_size(short_data) + 30
    end

    test "encryption uses proper random IVs" do
      data = "same_data"

      # Encrypt the same data multiple times
      encryptions =
        for _ <- 1..10 do
          {:ok, encrypted} = EncryptedBinary.dump(data)
          encrypted
        end

      # All encryptions should be unique (due to random IVs)
      unique_encryptions = Enum.uniq(encryptions)
      assert length(unique_encryptions) == 10
    end
  end
end

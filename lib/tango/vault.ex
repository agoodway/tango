defmodule Tango.Vault do
  @moduledoc """
  Encryption vault for OAuth token storage.
  """

  use Cloak.Vault, otp_app: :tango

  @impl GenServer
  def init(config) do
    config =
      Keyword.put(config, :ciphers,
        default: {
          Cloak.Ciphers.AES.GCM,
          tag: "AES.GCM.V1", key: get_encryption_key(), iv_length: 12
        }
      )

    {:ok, config}
  end

  @doc """
  Encrypts data using the default cipher.

  ## Examples

      encrypted = Tango.Vault.encrypt("sensitive_token")
      decrypted = Tango.Vault.decrypt(encrypted)
  """
  def encrypt(plaintext), do: encrypt!(plaintext)

  @doc """
  Decrypts data using the appropriate cipher.

  Returns `{:ok, plaintext}` or `{:error, reason}`.
  """
  def decrypt(ciphertext) do
    {:ok, decrypt!(ciphertext)}
  rescue
    error -> {:error, Exception.message(error)}
  end

  @doc """
  Gets the encryption key from application configuration.

  This function is called by Cloak to get the encryption key at runtime.
  """
  def get_encryption_key do
    key = Application.get_env(:tango, :encryption_key)

    case key do
      nil ->
        raise ArgumentError, "Tango encryption key not configured. Set :encryption_key in config."

      key when byte_size(key) == 32 ->
        key

      key ->
        case Base.decode64(key) do
          {:ok, decoded} when byte_size(decoded) == 32 ->
            decoded

          {:ok, decoded} ->
            raise ArgumentError,
                  "Decoded key must be 32 bytes, got #{byte_size(decoded)} bytes"

          :error ->
            raise ArgumentError,
                  "Key must be 32 bytes or valid base64-encoded 32 bytes, got #{byte_size(key)} bytes"
        end
    end
  end
end

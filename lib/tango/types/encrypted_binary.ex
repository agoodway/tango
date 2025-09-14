defmodule Tango.Types.EncryptedBinary do
  @moduledoc """
  Custom Ecto type for encrypting binary data using Tango.Vault.

  This type automatically encrypts data when storing to database and
  decrypts when loading from database. Used for sensitive OAuth tokens
  and credentials.
  """

  use Cloak.Ecto.Binary, vault: Tango.Vault

  @doc """
  Encrypts a plaintext string for database storage.

  ## Examples

      iex> Tango.Types.EncryptedBinary.cast("sensitive_token")
      {:ok, "sensitive_token"}
      
      iex> Tango.Types.EncryptedBinary.cast(nil)
      {:ok, nil}
  """
  def cast(nil), do: {:ok, nil}
  def cast(value) when is_binary(value), do: {:ok, value}
  def cast(_), do: :error

  @doc """
  Loads encrypted data from database and decrypts it.
  """
  def load(nil), do: {:ok, nil}

  def load(encrypted_value) when is_binary(encrypted_value) do
    case Tango.Vault.decrypt(encrypted_value) do
      {:ok, decrypted} -> {:ok, decrypted}
      {:error, _reason} -> :error
    end
  end

  def load(_), do: :error

  @doc """
  Dumps plaintext data by encrypting it for database storage.
  """
  def dump(nil), do: {:ok, nil}

  def dump(plaintext) when is_binary(plaintext) do
    encrypted = Tango.Vault.encrypt(plaintext)
    {:ok, encrypted}
  end

  def dump(_), do: :error

  @doc """
  Returns the underlying database type.
  """
  def type, do: :binary
end

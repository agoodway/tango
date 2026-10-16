defmodule Tango.Types.EncryptedBinary do
  @moduledoc """
  Custom Ecto type for encrypting binary data using Tango.Vault.

  This type automatically encrypts data when storing to database and
  decrypts when loading from database. Used for sensitive OAuth tokens
  and credentials.
  """

  # `cast/1` comes from `Cloak.Ecto.Binary`: nil and binaries cast as-is,
  # zero-arity closures are unwrapped, and everything else returns `:error`.
  use Cloak.Ecto.Binary, vault: Tango.Vault

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

  def dump(%Tango.RedactedParams.Secret{} = secret) do
    case Tango.RedactedParams.fetch(secret) do
      {:ok, plaintext} -> dump(plaintext)
      :error -> :error
    end
  end

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

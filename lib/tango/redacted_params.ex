defmodule Tango.RedactedParams do
  @moduledoc false
  # Ecto reports the pre-dump values of every written column (`cast_params`) to
  # SQL logging and telemetry handlers, even for encrypted column types. These
  # helpers replace credential values with `Tango.RedactedParams.Secret`, an opaque
  # reference that carries no credential bytes, for the duration of an insert
  # or update. The plaintext lives only in the calling process's private
  # storage under that reference; `Tango.Types.EncryptedBinary.dump/1` resolves
  # it while encrypting, which happens in the same process as the write. Stored
  # data is unchanged, telemetry and log metadata never contain the credential,
  # and returned structs carry plaintext again for the caller.

  defmodule Secret do
    @moduledoc false
    @type t :: %__MODULE__{ref: reference()}

    @enforce_keys [:ref]
    defstruct [:ref]
  end

  @credential_fields [:access_token, :refresh_token, :client_secret]

  @doc "Inserts `changeset` with credential values kept out of query metadata."
  def insert(repo, %Ecto.Changeset{} = changeset), do: write(changeset, &repo.insert/1)

  @doc "Updates `changeset` with credential values kept out of query metadata."
  def update(repo, %Ecto.Changeset{} = changeset), do: write(changeset, &repo.update/1)

  @doc false
  # Resolves a placeholder to its plaintext; only valid in the process that
  # created it.
  def fetch(%Secret{ref: ref}) do
    case Process.get({__MODULE__, ref}) do
      plaintext when is_binary(plaintext) -> {:ok, plaintext}
      _ -> :error
    end
  end

  defp write(%Ecto.Changeset{changes: changes} = changeset, write_fun) do
    {redacted_changes, secrets} =
      Enum.reduce(changes, {%{}, %{}}, fn
        {field, value}, {acc, secrets} when field in @credential_fields and is_binary(value) ->
          secret = %Secret{ref: make_ref()}
          Process.put({__MODULE__, secret.ref}, value)
          {Map.put(acc, field, secret), Map.put(secrets, secret.ref, value)}

        {field, value}, {acc, secrets} ->
          {Map.put(acc, field, value), secrets}
      end)

    try do
      %{changeset | changes: redacted_changes} |> write_fun.() |> restore(secrets)
    after
      Enum.each(secrets, fn {ref, _plaintext} -> Process.delete({__MODULE__, ref}) end)
    end
  end

  defp restore({:ok, struct}, secrets), do: {:ok, unwrap(struct, secrets)}

  defp restore({:error, %Ecto.Changeset{changes: changes} = changeset}, secrets),
    do:
      {:error,
       %{changeset | changes: Map.new(changes, fn {k, v} -> {k, unwrap_value(v, secrets)} end)}}

  defp restore(other, _secrets), do: other

  defp unwrap(struct, secrets) do
    Enum.reduce(@credential_fields, struct, fn field, acc ->
      case Map.fetch(acc, field) do
        {:ok, value} -> Map.put(acc, field, unwrap_value(value, secrets))
        :error -> acc
      end
    end)
  end

  defp unwrap_value(%Secret{ref: ref} = secret, secrets), do: Map.get(secrets, ref, secret)
  defp unwrap_value(value, _secrets), do: value
end

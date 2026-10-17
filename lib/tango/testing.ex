defmodule Tango.Testing do
  @moduledoc """
  Inserts providers and connections for consumer test suites.

  Compiled with the library so a consumer can call it from its own tests.
  Requires the configured Tango repo, encryption key, and the caller's test
  database ownership. Does not check out a sandbox, change application
  config, make HTTP calls, or delete rows. Cleanup stays with the caller.

  Accepts atom-key attribute maps. `provider_id` and `tenant_id` always come
  from the `insert_connection!/3` arguments.
  """

  import Ecto.Changeset, only: [force_change: 3]

  alias Tango.RedactedParams
  alias Tango.Schemas.{Connection, Provider}

  @default_scopes ["records.read"]
  @nullable_fields [:refresh_token, :granted_scopes, :account_subject, :expires_at]

  @doc """
  Inserts a provider with unique example.test endpoints.

  Omitted fields receive a unique slug, name, client secret, `records.read`,
  and a config map containing `client_id`, `auth_url`, and `token_url`.
  Passed attributes replace those defaults. An invalid provider raises
  `Ecto.InvalidChangesetError`.
  """
  @spec insert_provider!(map()) :: Provider.t()
  def insert_provider!(attrs \\ %{}) when is_map(attrs) do
    attrs
    |> provider_attrs()
    |> provider_changeset()
    |> insert!()
  end

  @doc """
  Inserts a connection for `provider` and `tenant_id`.

  An omitted access token or refresh token becomes a random dummy. An
  explicit nil access token is rejected. An explicit nil refresh token,
  scope list, subject, or expiry is stored as NULL, so a database default
  does not replace it. Omitted scopes default to `records.read`, and an
  omitted `oauth_client_id` comes from the provider config. Attributes
  cannot change the provider or tenant. A failed changeset raises
  `Ecto.InvalidChangesetError`. Database constraints still apply.
  """
  @spec insert_connection!(Provider.t(), String.t(), map()) :: Connection.t()
  def insert_connection!(%Provider{} = provider, tenant_id, attrs \\ %{})
      when is_binary(tenant_id) and is_map(attrs) do
    provider
    |> connection_attrs(tenant_id, attrs)
    |> connection_changeset()
    |> insert!()
  end

  defp provider_changeset(attrs), do: Provider.changeset(%Provider{}, attrs)

  defp connection_changeset(attrs) do
    %Connection{}
    |> Connection.changeset(attrs)
    |> force_explicit_nils(attrs)
  end

  defp force_explicit_nils(changeset, attrs) do
    Enum.reduce(@nullable_fields, changeset, &force_explicit_nil(&2, attrs, &1))
  end

  defp force_explicit_nil(changeset, attrs, field) do
    case Map.fetch(attrs, field) do
      {:ok, nil} -> force_change(changeset, field, nil)
      _other -> changeset
    end
  end

  defp insert!(changeset) do
    case RedactedParams.insert(repo(), changeset) do
      {:ok, record} -> record
      {:error, %Ecto.Changeset{} = changeset} -> raise_invalid(changeset)
    end
  end

  defp raise_invalid(changeset) do
    raise Ecto.InvalidChangesetError, action: :insert, changeset: changeset
  end

  defp provider_attrs(attrs) do
    suffix = System.unique_integer([:positive])

    Map.merge(
      %{
        name: "records_#{suffix}",
        slug: "records_#{suffix}",
        client_secret: dummy_token(),
        default_scopes: @default_scopes,
        config: %{
          "client_id" => "records_client_#{suffix}",
          "auth_url" => "https://example.test/#{suffix}/authorize",
          "token_url" => "https://example.test/#{suffix}/token"
        }
      },
      attrs
    )
  end

  defp connection_attrs(provider, tenant_id, attrs) do
    %{
      granted_scopes: @default_scopes,
      oauth_client_id: provider.config["client_id"],
      status: :active
    }
    |> Map.merge(attrs)
    |> put_dummy_token(:access_token)
    |> put_dummy_token(:refresh_token)
    |> Map.merge(%{provider_id: provider.id, tenant_id: tenant_id})
  end

  defp put_dummy_token(attrs, field) do
    attrs
    |> Map.fetch(field)
    |> keep_or_dummy(attrs, field)
  end

  defp keep_or_dummy({:ok, _value}, attrs, _field), do: attrs
  defp keep_or_dummy(:error, attrs, field), do: Map.put(attrs, field, dummy_token())

  defp dummy_token do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  defp repo, do: Application.get_env(:tango, :repo) || raise("Tango :repo not configured")
end

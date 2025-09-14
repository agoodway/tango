defmodule Tango.Schemas.Connection do
  @moduledoc """
  Active OAuth connections with encrypted token storage.

  Stores OAuth connections with multi-tenant isolation, token lifecycle management,
  and automatic refresh capabilities. All sensitive tokens are encrypted at rest.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @schema_prefix Application.compile_env(:tango, :schema_prefix, nil)

  @fields [
    :provider_id,
    :tenant_id,
    :access_token,
    :refresh_token,
    :token_type,
    :expires_at,
    :granted_scopes,
    :raw_payload,
    :metadata,
    :status,
    :last_used_at,
    :refresh_attempts,
    :last_refresh_failure,
    :next_refresh_at,
    :refresh_exhausted,
    :auto_refresh_enabled,
    :connection_config
  ]

  @required_fields [:provider_id, :tenant_id, :access_token, :status]

  schema "tango_connections" do
    belongs_to(:provider, Tango.Schemas.Provider)
    field(:tenant_id, :string)

    # Encrypted token storage
    field(:access_token, Tango.Types.EncryptedBinary)
    field(:refresh_token, Tango.Types.EncryptedBinary)
    field(:token_type, Ecto.Enum, values: [:bearer, :token], default: :bearer)
    field(:expires_at, :utc_datetime)
    field(:granted_scopes, {:array, :string})
    field(:raw_payload, :map, default: %{})
    field(:metadata, :map, default: %{})
    field(:status, Ecto.Enum, values: [:active, :revoked, :expired], default: :active)
    field(:last_used_at, :utc_datetime)

    # Token refresh management
    field(:refresh_attempts, :integer, default: 0)
    field(:last_refresh_failure, :string)
    field(:next_refresh_at, :utc_datetime)
    field(:refresh_exhausted, :boolean, default: false)
    field(:auto_refresh_enabled, :boolean, default: true)

    # Connection configuration overrides
    field(:connection_config, :map, default: %{})

    timestamps()
  end

  @doc "Creates a changeset for connection management"
  def changeset(connection, attrs) do
    connection
    |> cast(attrs, @fields)
    |> validate_required(@required_fields)
    |> validate_number(:refresh_attempts, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:provider_id)
    |> prepare_changes(&normalize_token_type/1)
  end

  @doc "Creates connection from OAuth token response"
  def from_token_response(provider_id, tenant_id, token_response) do
    attrs = %{
      provider_id: provider_id,
      tenant_id: tenant_id,
      access_token: token_response["access_token"],
      refresh_token: token_response["refresh_token"],
      token_type: normalize_token_type_value(token_response["token_type"]),
      expires_at: calculate_expiration(token_response["expires_in"]),
      granted_scopes: parse_scopes(token_response["scope"]),
      raw_payload: token_response,
      status: :active,
      last_used_at: DateTime.utc_now()
    }

    %__MODULE__{}
    |> changeset(attrs)
  end

  @doc "Updates connection after successful token refresh"
  def refresh_changeset(connection, token_response) do
    attrs = %{
      access_token: token_response["access_token"],
      refresh_token: token_response["refresh_token"] || connection.refresh_token,
      expires_at: calculate_expiration(token_response["expires_in"]),
      granted_scopes: parse_scopes(token_response["scope"]) || connection.granted_scopes,
      raw_payload: Map.merge(connection.raw_payload || %{}, token_response),
      refresh_attempts: 0,
      last_refresh_failure: nil,
      refresh_exhausted: false,
      last_used_at: DateTime.utc_now()
    }

    changeset(connection, attrs)
  end

  @doc "Marks connection as expired or failed"
  def mark_expired(connection, reason \\ nil) do
    attrs = %{
      status: :expired,
      refresh_exhausted: true,
      last_refresh_failure: reason
    }

    changeset(connection, attrs)
  end

  @doc "Records a failed refresh attempt"
  def record_refresh_failure(connection, error_reason) do
    attempts = connection.refresh_attempts + 1
    max_attempts = 3

    attrs = %{
      refresh_attempts: attempts,
      last_refresh_failure: to_string(error_reason),
      refresh_exhausted: attempts >= max_attempts,
      status: if(attempts >= max_attempts, do: :expired, else: connection.status)
    }

    changeset(connection, attrs)
  end

  @doc "Checks if token needs refresh"
  def needs_refresh?(%__MODULE__{expires_at: nil}), do: false

  def needs_refresh?(%__MODULE__{expires_at: expires_at}) do
    # Refresh 5 minutes before expiration
    buffer_time = DateTime.add(DateTime.utc_now(), 5 * 60, :second)
    DateTime.compare(buffer_time, expires_at) != :lt
  end

  @doc "Checks if connection can be refreshed"
  def can_refresh?(%__MODULE__{} = connection) do
    connection.refresh_token != nil and
      not connection.refresh_exhausted and
      connection.auto_refresh_enabled and
      connection.status == :active
  end

  # Private helper functions

  defp normalize_token_type(changeset) do
    case get_change(changeset, :token_type) do
      nil -> changeset
      token_type -> put_change(changeset, :token_type, normalize_token_type_value(token_type))
    end
  end

  defp normalize_token_type_value(token_type) when is_binary(token_type) do
    case token_type do
      "Bearer" -> :bearer
      "bearer" -> :bearer
      "token" -> :bearer
      _ -> :bearer
    end
  end

  defp normalize_token_type_value(nil), do: :bearer
  defp normalize_token_type_value(atom) when is_atom(atom), do: atom

  defp calculate_expiration(expires_in) when is_integer(expires_in) and expires_in > 0 do
    DateTime.add(DateTime.utc_now(), expires_in, :second)
  end

  defp calculate_expiration(_), do: nil

  defp parse_scopes(scope) when is_binary(scope) do
    scope
    |> String.split(~r/\s+/)
    |> Enum.reject(&(&1 == ""))
  end

  defp parse_scopes(scopes) when is_list(scopes), do: scopes
  defp parse_scopes(_), do: []
end

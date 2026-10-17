defmodule Tango.Schemas.Connection do
  @moduledoc """
  Active OAuth connections with encrypted token storage.

  Stores OAuth connections with multi-tenant isolation, token lifecycle management,
  and automatic refresh capabilities. All sensitive tokens are encrypted at rest.
  """

  use Ecto.Schema
  import Ecto.Changeset

  # Rejections that expire a connection when the caller passes no
  # `:max_failures`. Callers tune the ceiling per provider to match how often
  # they hit it; refresh keeps its own internal ceiling below.
  @default_max_auth_failures 3
  @max_refresh_attempts 3

  @type t :: %__MODULE__{
          id: integer() | nil,
          provider_id: integer() | nil,
          provider: Tango.Schemas.Provider.t() | Ecto.Association.NotLoaded.t() | nil,
          tenant_id: String.t() | nil,
          access_token: binary() | nil,
          refresh_token: binary() | nil,
          token_type: :bearer | :token | nil,
          expires_at: DateTime.t() | nil,
          granted_scopes: [String.t()] | nil,
          raw_payload: map(),
          metadata: map(),
          status: :active | :revoked | :expired,
          last_used_at: DateTime.t() | nil,
          refresh_attempts: non_neg_integer(),
          last_refresh_failure: String.t() | nil,
          next_refresh_at: DateTime.t() | nil,
          refresh_exhausted: boolean(),
          auth_failures: non_neg_integer(),
          last_auth_failure: String.t() | nil,
          auto_refresh_enabled: boolean(),
          connection_config: map(),
          lock_version: integer(),
          inserted_at: NaiveDateTime.t() | nil,
          updated_at: NaiveDateTime.t() | nil
        }

  @primary_key {:id, :id, autogenerate: true}
  @foreign_key_type :id
  @schema_prefix Application.compile_env(:tango, :schema_prefix, nil)

  @fields [
    :provider_id,
    :tenant_id,
    :account_subject,
    :oauth_client_id,
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
    :auth_failures,
    :last_auth_failure,
    :auto_refresh_enabled,
    :connection_config,
    :lock_version
  ]

  @required_fields [:provider_id, :tenant_id, :access_token, :status]

  schema "tango_connections" do
    belongs_to(:provider, Tango.Schemas.Provider)
    field(:tenant_id, :string)
    field(:account_subject, :string)
    field(:oauth_client_id, :string)

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

    # Rejections of the stored credentials by the provider itself, reported by
    # the consumer rather than observed here. Refreshing a token is a separate
    # failure mode with its own counters above: a connection can hold a token
    # the provider rejects while refresh has never once been attempted.
    field(:auth_failures, :integer, default: 0)
    field(:last_auth_failure, :string)

    field(:auto_refresh_enabled, :boolean, default: true)

    # Connection configuration overrides
    field(:connection_config, :map, default: %{})

    # Optimistic locking for concurrent refresh protection
    field(:lock_version, :integer, default: 1)

    timestamps()
  end

  @doc "Creates a changeset for connection management"
  def changeset(connection, attrs) do
    connection
    |> cast(attrs, @fields)
    |> validate_required(@required_fields)
    |> validate_number(:refresh_attempts, greater_than_or_equal_to: 0)
    |> validate_number(:auth_failures, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:provider_id)
    |> optimistic_lock(:lock_version)
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
      granted_scopes: Tango.Validation.parse_scopes(token_response["scope"]),
      raw_payload: sanitize_raw_payload(token_response),
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
      granted_scopes: refresh_scopes(token_response, connection.granted_scopes),
      raw_payload: Map.merge(connection.raw_payload || %{}, sanitize_raw_payload(token_response)),
      refresh_attempts: 0,
      last_refresh_failure: nil,
      refresh_exhausted: false,
      auth_failures: 0,
      last_auth_failure: nil,
      next_refresh_at: nil,
      last_used_at: DateTime.utc_now()
    }

    changeset(connection, attrs)
  end

  @unrecorded_refresh_reasons [
    :no_refresh_token,
    :refresh_not_allowed,
    :persistence_failed,
    :transaction_failed
  ]

  @doc """
  Records a refresh failure on a locked connection.

  Credential failures expire the connection immediately. Client, request, and
  recorded local failures expire it on the third attempt. Transient failures
  keep the attempt count and set `next_refresh_at`. Eligibility shortcuts and
  persistence failures leave the row unchanged.
  """
  def record_refresh_failure(%__MODULE__{} = connection, reason)
      when reason in @unrecorded_refresh_reasons do
    changeset(connection, %{})
  end

  def record_refresh_failure(%__MODULE__{} = connection, reason) do
    case Tango.RefreshError.classify(reason) do
      :transient -> schedule_refresh_backoff(connection, reason)
      :credential -> record_refresh_attempt(connection, reason, true)
      _class -> record_refresh_attempt(connection, reason, false)
    end
  end

  defp record_refresh_attempt(connection, reason, immediate_expiry?) do
    attempts = connection.refresh_attempts + 1
    expire? = immediate_expiry? or attempts >= @max_refresh_attempts

    changeset(connection, %{
      refresh_attempts: attempts,
      last_refresh_failure: Tango.RefreshError.to_storage(reason),
      refresh_exhausted: expire?,
      status: if(expire?, do: :expired, else: connection.status),
      next_refresh_at: nil
    })
  end

  defp schedule_refresh_backoff(connection, reason) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    changeset(connection, %{
      last_refresh_failure: Tango.RefreshError.to_storage(reason),
      next_refresh_at: DateTime.add(now, Tango.RefreshError.backoff_seconds(reason), :second)
    })
  end

  @doc """
  Records the provider rejecting the stored credentials.

  Consumers report a provider's own rejection — an HTTP 401 or 403 answering an
  API call — which this library cannot observe for itself. The connection is
  expired once the rejections reach `opts[:max_failures]` (default
  #{@default_max_auth_failures}), after which `get_connection_for_provider/2`
  stops handing it out and the consumer can treat the connection as gone.

  The threshold is per call rather than library-wide because a Tango deployment
  serves many providers, each called on its own cadence — and the count is a
  number of rejections, not a duration. A consumer polling a provider every few
  seconds reaches a given ceiling within seconds of a transient outage, while
  one sweeping twice an hour takes days to reach the same count; each caller
  passes the threshold that matches how often it hits that provider.

  A rejection is not a refresh failure and leaves the refresh counters alone.
  The two are independent: a connection carrying no refresh token and no expiry
  is never eligible for refresh, so its credentials can be rejected forever
  while `refresh_attempts` stays at zero.

  Only an `:active` connection is moved to `:expired`; a terminal status is
  kept, since `:revoked` and `:expired` rows age out on different schedules.
  Raises `ArgumentError` when `opts[:max_failures]` is not a positive integer.
  """
  def record_auth_failure(connection, error_reason, opts \\ []) do
    failures = connection.auth_failures + 1
    exhausted = failures >= max_failures!(opts)

    attrs = %{
      auth_failures: failures,
      last_auth_failure: to_string(error_reason),
      status:
        if(exhausted and connection.status == :active, do: :expired, else: connection.status)
    }

    changeset(connection, attrs)
  end

  @doc """
  Clears a rejection streak after the credentials authenticate again.

  Keeps the count consecutive: without this, unrelated rejections spread over
  months would accumulate to the threshold and expire a working connection.
  """
  def clear_auth_failures(connection) do
    changeset(connection, %{auth_failures: 0, last_auth_failure: nil})
  end

  @doc "Whether the provider has rejected these credentials enough times to expire them"
  def auth_failures_exhausted?(%__MODULE__{auth_failures: failures}, opts \\ []),
    do: failures >= max_failures!(opts)

  # A threshold that is not a positive integer is a defect at the call site,
  # not runtime data: zero or a negative expires on the first report, and a
  # non-integer never compares true against the count.
  defp max_failures!(opts) do
    case Keyword.get(opts, :max_failures, @default_max_auth_failures) do
      max when is_integer(max) and max > 0 ->
        max

      other ->
        raise ArgumentError,
              ":max_failures must be a positive integer, got: #{inspect(other)}"
    end
  end

  @doc "Checks if token needs refresh"
  def needs_refresh?(%__MODULE__{expires_at: nil}), do: false

  def needs_refresh?(%__MODULE__{expires_at: expires_at}) do
    buffer_time = refresh_buffer_time()
    DateTime.compare(buffer_time, expires_at) != :lt
  end

  @doc "Checks if connection can be refreshed"
  def can_refresh?(%__MODULE__{
        refresh_token: refresh_token,
        refresh_exhausted: false,
        auto_refresh_enabled: true,
        status: :active
      })
      when not is_nil(refresh_token),
      do: true

  def can_refresh?(%__MODULE__{}), do: false

  @doc "Extracts the raw access token string for API usage"
  def get_raw_access_token(%__MODULE__{access_token: nil}), do: nil

  def get_raw_access_token(%__MODULE__{access_token: encrypted_token})
      when is_binary(encrypted_token) do
    # The access_token field is automatically decrypted by EncryptedBinary type
    # when loaded from the database, so we can return it directly
    encrypted_token
  end

  def get_raw_access_token(%__MODULE__{access_token: token}) do
    # Handle any other token format (should be rare)
    case token do
      token when is_binary(token) -> token
      _ -> nil
    end
  end

  defp normalize_token_type(changeset) do
    case get_change(changeset, :token_type) do
      nil -> changeset
      token_type -> put_change(changeset, :token_type, normalize_token_type_value(token_type))
    end
  end

  defp normalize_token_type_value("Bearer"), do: :bearer
  defp normalize_token_type_value("bearer"), do: :bearer
  defp normalize_token_type_value("token"), do: :bearer
  defp normalize_token_type_value(token_type) when is_binary(token_type), do: :bearer
  defp normalize_token_type_value(nil), do: :bearer
  defp normalize_token_type_value(atom) when is_atom(atom), do: atom

  defp calculate_expiration(expires_in) when is_integer(expires_in) and expires_in > 0 do
    DateTime.add(DateTime.utc_now(), expires_in, :second)
  end

  defp calculate_expiration(_), do: nil

  defp refresh_buffer_time do
    DateTime.add(DateTime.utc_now(), 5 * 60, :second)
  end

  defp refresh_scopes(%{"scope" => scope}, _existing) when is_binary(scope) or is_list(scope),
    do: Tango.Validation.parse_scopes(scope)

  defp refresh_scopes(_response, existing), do: existing

  # Remove sensitive tokens from raw_payload to prevent unencrypted storage
  defp sanitize_raw_payload(token_response) when is_map(token_response) do
    Map.drop(token_response, ["access_token", "refresh_token"])
  end

  defp sanitize_raw_payload(_), do: %{}
end

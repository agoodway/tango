defmodule Tango.Schemas.AuditLog do
  @moduledoc """
  Comprehensive OAuth activity logging for security and compliance.

  Records all OAuth-related events with structured metadata for debugging,
  security monitoring, and compliance auditing.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :id, autogenerate: true}
  @foreign_key_type :id
  @schema_prefix Application.compile_env(:tango, :schema_prefix, nil)

  @fields [
    :event_type,
    :tenant_id,
    :provider_id,
    :connection_id,
    :session_id,
    :success,
    :error_code,
    :ip_address,
    :user_agent,
    :event_data,
    :sensitive_data_hash,
    :occurred_at
  ]

  @required_fields [:event_type, :tenant_id, :success, :occurred_at]

  schema "tango_audit_logs" do
    field(:event_type, Ecto.Enum,
      values: [
        :oauth_start,
        :token_exchange,
        :oauth_denied,
        :oauth_provider_error,
        :oauth_callback_error,
        :token_refreshed,
        :token_refresh_failed,
        :connection_revoked,
        :connection_expired,
        :provider_created,
        :provider_updated,
        :provider_deleted,
        :session_created,
        :session_expired,
        :batch_token_refresh,
        :tenant_connections_revoked,
        :provider_connections_revoked,
        :expired_connections_cleanup
      ]
    )

    field(:tenant_id, :string)
    belongs_to(:provider, Tango.Schemas.Provider)
    belongs_to(:connection, Tango.Schemas.Connection)
    field(:session_id, :string)
    field(:success, :boolean)

    field(:error_code, Ecto.Enum,
      values: [
        :session_not_found,
        :session_expired,
        :invalid_state,
        :invalid_authorization_code,
        :invalid_tenant_id,
        :invalid_options,
        :invalid_state_parameter,
        :token_too_short,
        :suspicious_token_content,
        :invalid_token_format,
        :oauth_error_response,
        :insecure_redirect_uri,
        :unsafe_redirect_uri,
        :invalid_redirect_uri,
        :network_error,
        :timeout,
        :rate_limited,
        :provider_error,
        :access_denied,
        :invalid_request,
        :invalid_client,
        :invalid_grant,
        :unsupported_grant_type,
        :invalid_scope,
        :server_error,
        :temporarily_unavailable,
        :missing_callback_params,
        :unknown_error
      ]
    )

    field(:ip_address, :string)
    field(:user_agent, :string)
    field(:event_data, :map, default: %{})
    field(:sensitive_data_hash, :string)
    field(:occurred_at, :utc_datetime)

    timestamps(updated_at: false)
  end

  @doc "Creates a changeset for audit log entry"
  def changeset(audit_log, attrs) do
    attrs_with_occurred_at = Map.put_new(attrs, :occurred_at, DateTime.utc_now())

    audit_log
    |> cast(attrs_with_occurred_at, @fields)
    |> validate_required(@required_fields)
    |> foreign_key_constraint(:provider_id)
    |> foreign_key_constraint(:connection_id)
    |> generate_sensitive_data_hash()
  end

  @doc "Logs OAuth session start event"
  def log_oauth_start(provider, tenant_id, session, opts \\ %{}) do
    attrs = %{
      event_type: :oauth_start,
      tenant_id: tenant_id,
      provider_id: provider.id,
      session_id: session.session_token,
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      success: true,
      occurred_at: DateTime.utc_now(),
      event_data: %{
        scopes_requested: opts[:scopes] || provider.default_scopes,
        redirect_uri_hash: hash_sensitive_data(opts[:redirect_uri]),
        provider_name: provider.name,
        session_expires_at: session.expires_at
      }
    }

    %__MODULE__{}
    |> changeset(attrs)
  end

  @doc "Logs token exchange completion"
  def log_token_exchange(session, connection, success, error \\ nil) do
    attrs = %{
      event_type: :token_exchange,
      tenant_id: session.tenant_id,
      provider_id: session.provider_id,
      connection_id: connection && connection.id,
      session_id: session.session_token,
      success: success,
      error_code: error,
      occurred_at: DateTime.utc_now(),
      event_data: %{
        scopes_granted: connection && connection.granted_scopes,
        token_expires_at: connection && connection.expires_at,
        token_type: connection && connection.token_type,
        session_duration_ms: calculate_session_duration(session)
      }
    }

    %__MODULE__{}
    |> changeset(attrs)
  end

  @doc "Logs provider configuration changes"
  def log_provider_event(event_type, provider, success, event_data \\ %{})
      when event_type in [:provider_created, :provider_updated, :provider_deleted] do
    attrs = %{
      event_type: event_type,
      # Provider changes are system-level
      tenant_id: "system",
      provider_id: provider.id,
      success: success,
      occurred_at: DateTime.utc_now(),
      event_data:
        Map.merge(
          %{
            provider_name: provider.name,
            provider_active: provider.active
          },
          event_data
        )
    }

    %__MODULE__{}
    |> changeset(attrs)
  end

  @doc "Logs OAuth callback errors (user denial, provider errors, malformed callbacks)"
  def log_oauth_callback_error(
        event_type,
        error_code,
        tenant_id,
        session_id \\ nil,
        event_data \\ %{}
      )
      when event_type in [:oauth_denied, :oauth_provider_error, :oauth_callback_error] do
    attrs = %{
      event_type: event_type,
      tenant_id: tenant_id,
      session_id: session_id,
      success: false,
      error_code: error_code,
      occurred_at: DateTime.utc_now(),
      event_data: event_data
    }

    %__MODULE__{}
    |> changeset(attrs)
  end

  @doc "Logs session expiration cleanup"
  def log_session_cleanup(expired_count, tenant_id \\ "system") do
    attrs = %{
      event_type: :session_expired,
      tenant_id: tenant_id,
      success: true,
      occurred_at: DateTime.utc_now(),
      event_data: %{
        expired_sessions_count: expired_count,
        cleanup_type: "automatic"
      }
    }

    %__MODULE__{}
    |> changeset(attrs)
  end

  @doc "Logs connection-related events"
  def log_connection_event(event_type, connection, success, event_data \\ %{}) do
    attrs = %{
      event_type: event_type,
      tenant_id: connection.tenant_id,
      provider_id: connection.provider_id,
      connection_id: connection.id,
      success: success,
      occurred_at: DateTime.utc_now(),
      event_data: event_data
    }

    %__MODULE__{}
    |> changeset(attrs)
  end

  @doc "Logs system-level events"
  def log_system_event(event_type, success, event_data \\ %{}) do
    attrs = %{
      event_type: event_type,
      tenant_id: "system",
      success: success,
      occurred_at: DateTime.utc_now(),
      event_data: event_data
    }

    %__MODULE__{}
    |> changeset(attrs)
  end

  defp generate_sensitive_data_hash(changeset) do
    case get_change(changeset, :event_data) do
      nil ->
        changeset

      event_data ->
        sensitive_hash = hash_sensitive_metadata(event_data)
        put_change(changeset, :sensitive_data_hash, sensitive_hash)
    end
  end

  defp hash_sensitive_metadata(event_data) when is_map(event_data) do
    # Hash specific sensitive fields for correlation while protecting PII
    sensitive_fields = [:redirect_uri_hash, :scopes_requested, :scopes_granted, :ip_address]

    event_data
    |> Map.take(sensitive_fields)
    |> Jason.encode!()
    |> hash_sensitive_data()
  end

  defp hash_sensitive_data(nil), do: nil

  defp hash_sensitive_data(data) when is_binary(data) do
    :crypto.hash(:sha256, data)
    |> Base.encode16(case: :lower)
  end

  defp calculate_session_duration(%{inserted_at: start_time})
       when is_struct(start_time, NaiveDateTime) do
    start_time
    |> DateTime.from_naive!("Etc/UTC")
    |> then(&DateTime.diff(DateTime.utc_now(), &1, :millisecond))
  end

  defp calculate_session_duration(%{inserted_at: start_time})
       when is_struct(start_time, DateTime) do
    start_time
    |> then(&DateTime.diff(DateTime.utc_now(), &1, :millisecond))
  end

  defp calculate_session_duration(_), do: nil
end

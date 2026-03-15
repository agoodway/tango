defmodule DemoWeb.TangoLogsComponent do
  @moduledoc """
  A macOS-style terminal showing Tango's audit trail and connection details.
  """
  use Phoenix.Component

  attr :audit_logs, :list, required: true
  attr :connection, :any, default: nil
  attr :class, :string, default: ""

  def tango_logs(assigns) do
    ~H"""
    <div class={[
      "rounded-lg overflow-hidden font-mono text-[13px] shadow-[0_4px_24px_rgba(0,0,0,0.15)]",
      @class
    ]}>
      <div class="bg-[#2d2d2d] px-3 py-2 flex items-center gap-2 select-none">
        <div class="flex gap-1.5 items-center">
          <span class="w-3 h-3 rounded-full bg-[#ff5f56]"></span>
          <span class="w-3 h-3 rounded-full bg-[#ffbd2e]"></span>
          <span class="w-3 h-3 rounded-full bg-[#27c93f]"></span>
        </div>
        <span class="flex-1 text-center text-[#9a9a9a] text-xs font-medium">Tango Logs</span>
      </div>

      <div class="bg-[#1a1a1a] p-4 min-h-[200px] max-h-[500px] overflow-y-auto">
        <%= if @audit_logs == [] do %>
          <p class="text-[#555] italic">Connect a provider to see Tango in action...</p>
        <% else %>
          <%!-- Audit Trail --%>
          <div class="space-y-3">
            <div :for={log <- @audit_logs} class="flex gap-3">
              <div class="flex flex-col items-center shrink-0">
                <span class={[
                  "w-2.5 h-2.5 rounded-full mt-1",
                  log.success && "bg-[#98c379]",
                  !log.success && "bg-[#e06c75]"
                ]}>
                </span>
                <div class="w-px flex-1 bg-[#333] mt-1"></div>
              </div>
              <div class="pb-1 min-w-0">
                <div class="flex items-baseline gap-2 flex-wrap">
                  <span class="text-[#61afef] whitespace-nowrap">{format_time(log.occurred_at)}</span>
                  <span class={[
                    "font-medium",
                    log.success && "text-[#98c379]",
                    !log.success && "text-[#e06c75]"
                  ]}>
                    {event_label(log.event_type)}
                  </span>
                </div>
                <div class="text-[#777] text-[12px] mt-0.5 leading-relaxed">
                  {event_details(log)}
                </div>
              </div>
            </div>
          </div>

          <%!-- Connection Details --%>
          <div :if={@connection} class="mt-4 pt-4 border-t border-[#333]">
            <div class="text-[#9a9a9a] text-[11px] uppercase tracking-wider mb-2 font-medium">
              Connection
            </div>
            <div class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[12px]">
              <span class="text-[#777]">Status</span>
              <span class="text-[#98c379] flex items-center gap-1.5">
                <span class="w-1.5 h-1.5 rounded-full bg-[#98c379] inline-block"></span>
                {to_string(@connection.status)}
              </span>

              <span class="text-[#777]">Tenant</span>
              <span class="text-[#abb2bf]">{@connection.tenant_id}</span>

              <span class="text-[#777]">Provider</span>
              <span class="text-[#abb2bf]">{@connection.provider.name}</span>

              <span class="text-[#777]">Scopes</span>
              <span class="text-[#abb2bf]">{Enum.join(@connection.granted_scopes, ", ")}</span>

              <span class="text-[#777]">Token</span>
              <span class="text-[#e5c07b]">encrypted (AES-256-GCM)</span>

              <span class="text-[#777]">Created</span>
              <span class="text-[#abb2bf]">{relative_time(@connection.inserted_at)}</span>

              <span class="text-[#777]">Expires</span>
              <span class="text-[#abb2bf]">{expires_label(@connection.expires_at)}</span>
            </div>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  defp format_time(nil), do: ""

  defp format_time(%DateTime{} = dt) do
    Calendar.strftime(dt, "%H:%M:%S")
  end

  defp event_label(:oauth_start), do: "Tango Session Created"
  defp event_label(:token_exchange), do: "Tango Token Exchanged"
  defp event_label(:token_refreshed), do: "Token Refreshed"

  defp event_label(:connection_revoked), do: "Connection Revoked"
  defp event_label(:connection_expired), do: "Connection Expired"
  defp event_label(:session_created), do: "Session Created"
  defp event_label(:session_expired), do: "Session Expired"
  defp event_label(:oauth_denied), do: "OAuth Denied"
  defp event_label(:oauth_provider_error), do: "Provider Error"
  defp event_label(:oauth_callback_error), do: "Callback Error"
  defp event_label(:provider_created), do: "Provider Created"
  defp event_label(:provider_updated), do: "Provider Updated"
  defp event_label(:provider_deleted), do: "Provider Deleted"
  defp event_label(type), do: type |> to_string() |> String.replace("_", " ") |> String.capitalize()

  defp event_details(%{event_type: :oauth_start, event_data: data}) do
    parts =
      [
        data["provider_name"] && "Provider: #{data["provider_name"]}",
        data["scopes_requested"] && "Scopes: #{Enum.join(data["scopes_requested"], ", ")}",
        "PKCE: S256"
      ]
      |> Enum.filter(& &1)

    Enum.join(parts, " · ")
  end

  defp event_details(%{event_type: :token_exchange, event_data: data}) do
    parts =
      [
        data["session_duration_ms"] && "Completed in #{(data["session_duration_ms"] / 1000) |> Float.round(1)}s",
        data["token_type"] && "Token type: #{data["token_type"]}",
        data["scopes_granted"] && "Scopes: #{Enum.join(data["scopes_granted"], ", ")}",
        "Stored encrypted"
      ]
      |> Enum.filter(& &1)

    Enum.join(parts, " · ")
  end

  defp event_details(%{event_data: data}) when is_map(data) and map_size(data) > 0 do
    data
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.take(3)
    |> Enum.map(fn {k, v} -> "#{k}: #{inspect(v)}" end)
    |> Enum.join(" · ")
  end

  defp event_details(_), do: ""

  defp relative_time(nil), do: "unknown"

  defp relative_time(%NaiveDateTime{} = ndt) do
    diff = NaiveDateTime.diff(NaiveDateTime.utc_now(), ndt, :second)

    cond do
      diff < 5 -> "just now"
      diff < 60 -> "#{diff}s ago"
      diff < 3600 -> "#{div(diff, 60)}m ago"
      diff < 86400 -> "#{div(diff, 3600)}h ago"
      true -> Calendar.strftime(ndt, "%Y-%m-%d %H:%M")
    end
  end

  defp expires_label(nil), do: "never"

  defp expires_label(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M UTC")
  end
end

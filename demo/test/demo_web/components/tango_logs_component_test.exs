defmodule DemoWeb.TangoLogsComponentTest do
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  test "renders credential-free connection info with nullable scopes" do
    connection = %Tango.ConnectionInfo{
      id: 1,
      tenant_id: "demo-user-1",
      provider_slug: "github",
      status: :active,
      granted_scopes: nil,
      expires_at: nil
    }

    html =
      render_component(&DemoWeb.TangoLogsComponent.tango_logs/1,
        connection: connection,
        audit_logs: []
      )

    details = html |> LazyHTML.from_fragment() |> LazyHTML.query("#tango-connection-info")
    text = LazyHTML.text(details)
    assert text =~ "github"
    assert text =~ "demo-user-1"
    assert text =~ "active"
    assert text =~ "never"
    refute text =~ "Created"
  end
end

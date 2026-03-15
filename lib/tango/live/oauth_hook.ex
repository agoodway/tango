defmodule Tango.Live.OAuthHook do
  @moduledoc """
  Provides the JavaScript hook name for the Tango OAuth popup flow.

  Host apps should import the JS hook from `deps/tango/assets/tango_oauth_hook.js`
  and register it with the LiveSocket under the name returned by `hook_name/0`.

  ## Example (app.js)

      import TangoOAuth from "../../deps/tango/assets/tango_oauth_hook.js"

      let Hooks = { TangoOAuth }
      let liveSocket = new LiveSocket("/live", Socket, { hooks: Hooks })
  """

  @doc "Returns the hook module name to register with LiveSocket."
  def hook_name, do: "TangoOAuth"
end

defmodule Tango.Live.Components do
  @moduledoc """
  Convenience module for using Tango LiveView components.

  ## Usage

      use Tango.Live.Components

  This makes `Tango.Live.OAuthComponent` available for use as a LiveComponent:

      <.live_component
        module={Tango.Live.OAuthComponent}
        id="github-oauth"
        provider="github"
        tenant_id="user-123"
        callback_url="http://localhost:4000/api/oauth/callback"
      />
  """

  defmacro __using__(_opts) do
    quote do
      alias Tango.Live.OAuthComponent
    end
  end
end

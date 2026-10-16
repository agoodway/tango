defmodule Demo.GithubConnect do
  @moduledoc """
  Completes a GitHub authorization on the server.

  The browser supplies only an opaque completion handle and the intent
  reference. Verification and finalization run here, in the tenant's
  authenticated LiveView process, so the access and refresh tokens never reach
  the browser.
  """

  alias Demo.Repo

  @provider "github"
  @scopes ["user:email", "repo"]

  def provider, do: @provider
  def scopes, do: @scopes

  @doc """
  Verifies the staged candidate's GitHub identity, then atomically replaces the
  tenant's connection with it.
  """
  def complete(handle, intent_reference, tenant_id, expected_connection_id \\ nil) do
    with {:ok, _summary} <-
           Tango.verify_authorization(handle, tenant_id, {Demo.GithubVerifier, []},
             intent_reference: intent_reference,
             provider: @provider
           ),
         {:ok, %{authorization: %{connection: connection}}} <-
           Ecto.Multi.new()
           |> Tango.multi_finalize_authorization(:authorization, handle, tenant_id,
             required_scopes: @scopes,
             intent_reference: intent_reference,
             provider: @provider,
             expected_connection_id: expected_connection_id
           )
           |> Repo.transaction() do
      {:ok, connection}
    else
      {:error, _step, reason, _changes} -> {:error, reason}
      {:error, _reason} = error -> error
    end
  end
end

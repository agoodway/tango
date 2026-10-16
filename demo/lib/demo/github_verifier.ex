defmodule Demo.GithubVerifier do
  @moduledoc """
  Verifies the GitHub identity behind a staged authorization candidate.

  Runs on the server with the candidate's ephemeral access token. Only the
  stable GitHub account id and login are returned as claims; the token never
  leaves this function.
  """

  @behaviour Tango.AuthorizationVerifier

  @impl true
  def verify(_provider, %{access_token: access_token}, opts) do
    case Demo.GithubClient.fetch_user(access_token) do
      {:ok, %{"id" => id, "login" => login}} when is_integer(id) and is_binary(login) ->
        {:ok,
         %{
           subject: Integer.to_string(id),
           claims: %{"login" => login},
           continuity: continuity(opts)
         }}

      {:error, reason} ->
        {:error, failure_category(reason)}

      _unusable_identity ->
        {:error, :invalid_identity}
    end
  end

  # Outages map to Tango's retryable verifier errors, which keep the candidate
  # open so the user can retry. Anything else (a rejected token, a malformed
  # response) is an identity failure and consumes the candidate.
  defp failure_category({:http_status, 429}), do: :temporarily_unavailable
  defp failure_category({:http_status, status}) when status >= 500, do: :provider_unavailable
  defp failure_category({:transport, :timeout}), do: :timeout
  defp failure_category({:transport, _reason}), do: :network_error
  defp failure_category(_reason), do: :invalid_identity

  defp continuity(opts) do
    case Keyword.get(opts, :connection_id) do
      nil -> :initial
      connection_id -> {:connection, connection_id}
    end
  end
end

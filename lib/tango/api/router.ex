defmodule Tango.API.Router do
  @moduledoc """
  Reusable OAuth API router for Phoenix applications.

  This module provides a complete OAuth API that can be mounted in Phoenix
  applications using the `forward` macro. It handles all OAuth operations
  including session creation, authorization URL generation, token exchange,
  and connection management.

  ## Usage

  In your Phoenix router:

      defmodule MyAppWeb.Router do
        use MyAppWeb, :router

        scope "/api/oauth" do
          pipe_through :api
          forward "/", Tango.API.Router
        end
      end

  ## Configuration

  The API expects tenant ID to be provided via:
  - Request header: `X-Tenant-ID`
  - Connection assigns: `conn.assigns.current_tenant_id`

  Configure CORS if needed:

      config :tango, :api,
        cors_origins: ["http://localhost:3000", "https://myapp.com"]

  ## Routes

  - `POST /sessions` - Create OAuth session
  - `GET /authorize/:session_token` - Get authorization URL
  - `POST /exchange` - Exchange authorization code for connection
  - `GET /callback` - OAuth callback page for popup flows
  - `GET /health` - Health check

  """

  use Plug.Router
  require Logger

  alias Tango.Auth
  alias Tango.Schemas.Connection

  plug(Tango.API.CORSPlug)
  plug(:match)

  plug(Plug.Parsers,
    parsers: [:json],
    pass: ["application/json"],
    json_decoder: Jason
  )

  plug(:authenticate_api_key)
  plug(:dispatch)

  # Create OAuth session
  post "/sessions" do
    with {:ok, params} <- validate_session_params(conn.body_params),
         {:ok, tenant_id} <- extract_tenant_id(conn),
         {:ok, session} <-
           Tango.create_session(
             params["provider"],
             tenant_id,
             redirect_uri: params["redirect_uri"],
             scopes: params["scopes"] || []
           ) do
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(
        201,
        Jason.encode!(%{
          session_token: session.session_token,
          expires_at: session.expires_at
        })
      )
    else
      error -> handle_error(conn, error)
    end
  end

  # Get authorization URL
  get "/authorize/:session_token" do
    with {:ok, redirect_uri} <- get_required_param(conn.query_params, "redirect_uri"),
         scopes <- get_optional_param(conn.query_params, "scopes", []),
         {:ok, auth_url} <-
           Auth.authorize_url_with_scopes(session_token, redirect_uri, Auth.parse_scopes(scopes)) do
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(
        200,
        Jason.encode!(%{
          authorization_url: auth_url
        })
      )
    else
      error -> handle_error(conn, error)
    end
  end

  # Exchange authorization code for connection
  post "/exchange" do
    with {:ok, params} <- validate_exchange_params(conn.body_params),
         {:ok, tenant_id} <- extract_tenant_id(conn),
         {:ok, connection} <-
           Tango.exchange_code(
             params["state"],
             params["code"],
             tenant_id,
             redirect_uri: params["redirect_uri"]
           ) do
      # Load provider for response
      {:ok, provider} = Tango.get_provider_by_id(connection.provider_id)

      # Include access token if requested for popup flows
      response_data = %{
        provider: provider.name,
        status: connection.status,
        scopes: connection.granted_scopes,
        expires_at: connection.expires_at
      }

      # Add access token for popup callback flows (when include_token=true)
      response_data =
        if params["include_token"] == "true" do
          access_token = Connection.get_raw_access_token(connection)
          Map.put(response_data, :access_token, access_token)
        else
          response_data
        end

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(200, Jason.encode!(response_data))
    else
      error -> handle_error(conn, error)
    end
  end

  # OAuth callback endpoint for popup flows
  get "/callback" do
    code = Map.get(conn.query_params, "code")
    state = Map.get(conn.query_params, "state")
    error = Map.get(conn.query_params, "error")
    error_description = Map.get(conn.query_params, "error_description")

    if error, do: Auth.log_oauth_callback_error(state, error, error_description)

    with exchange_result <- Auth.perform_callback_exchange(conn, code, state),
         html <-
           Auth.generate_callback_html(code, state, error, error_description, exchange_result) do
      conn
      |> put_resp_content_type("text/html")
      |> send_resp(200, html)
    end
  end

  # Health check endpoint
  get "/health" do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(
      200,
      Jason.encode!(%{
        status: "ok",
        library: "tango",
        timestamp: DateTime.utc_now()
      })
    )
  end

  # Catch-all for undefined routes
  match _ do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(
      404,
      Jason.encode!(%{
        error: "not_found",
        message: "OAuth API endpoint not found"
      })
    )
  end

  # Private helper functions

  defp authenticate_api_key(%{path_info: ["health"]} = conn, _opts), do: conn
  defp authenticate_api_key(%{path_info: ["callback"]} = conn, _opts), do: conn

  defp authenticate_api_key(conn, _opts) do
    with {:ok, api_key} <- get_api_key(conn),
         true <- validate_api_key(api_key) do
      conn
    else
      :error ->
        send_auth_error(
          conn,
          "missing_api_key",
          "API key required. Provide via Authorization header or X-API-Key header"
        )

      false ->
        send_auth_error(conn, "invalid_api_key", "Invalid or missing API key")
    end
  end

  defp send_auth_error(conn, error_type, message) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, Jason.encode!(%{error: error_type, message: message}))
    |> halt()
  end

  defp get_api_key(conn) do
    # Try Authorization header first (Bearer token style)
    case get_req_header(conn, "authorization") do
      ["Bearer " <> api_key] ->
        {:ok, api_key}

      _ ->
        # Fallback to X-API-Key header
        case get_req_header(conn, "x-api-key") do
          [api_key] when is_binary(api_key) -> {:ok, api_key}
          _ -> :error
        end
    end
  end

  defp validate_api_key(api_key) do
    configured_key = Application.get_env(:tango, :api_key)

    # Check if provided API key matches configured key
    api_key == configured_key
  end

  defp extract_tenant_id(conn) do
    # Try to get from headers first
    case get_req_header(conn, "x-tenant-id") do
      [tenant_id] when is_binary(tenant_id) ->
        {:ok, tenant_id}

      _ ->
        # Fallback to connection assigns
        case Map.get(conn.assigns, :current_tenant_id) do
          tenant_id when is_binary(tenant_id) -> {:ok, tenant_id}
          _ -> {:error, :tenant_id_required}
        end
    end
  end

  defp validate_session_params(params) do
    case params do
      %{"provider" => provider, "redirect_uri" => redirect_uri}
      when is_binary(provider) and is_binary(redirect_uri) ->
        {:ok, params}

      %{"provider" => provider} when is_binary(provider) ->
        {:ok, params}

      _ ->
        {:error, :invalid_session_params}
    end
  end

  defp validate_exchange_params(params) do
    case params do
      %{"state" => state, "code" => code}
      when is_binary(state) and is_binary(code) ->
        {:ok, params}

      _ ->
        {:error, :invalid_exchange_params}
    end
  end

  defp get_required_param(params, key) do
    case Map.get(params, key) do
      value when is_binary(value) -> {:ok, value}
      _ -> {:error, {:missing_required_param, key}}
    end
  end

  defp get_optional_param(params, key, default) do
    Map.get(params, key, default)
  end

  defp handle_error(conn, error) do
    {status, error_response} = format_error(error)

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(error_response))
  end

  defp format_error({:error, :provider_not_found}) do
    {404,
     %{
       error: "provider_not_found",
       message: "The specified OAuth provider was not found"
     }}
  end

  defp format_error({:error, :session_not_found}) do
    {404,
     %{
       error: "session_not_found",
       message: "OAuth session not found or expired"
     }}
  end

  defp format_error({:error, :session_expired}) do
    {410,
     %{
       error: "session_expired",
       message: "OAuth session has expired"
     }}
  end

  defp format_error({:error, :invalid_state}) do
    {400,
     %{
       error: "invalid_state",
       message: "Invalid or mismatched OAuth state parameter"
     }}
  end

  defp format_error({:error, :tenant_id_required}) do
    {401,
     %{
       error: "tenant_id_required",
       message:
         "Tenant ID is required. Provide via X-Tenant-ID header or conn.assigns.current_tenant_id"
     }}
  end

  defp format_error({:error, :invalid_session_params}) do
    {400,
     %{
       error: "invalid_params",
       message: "Missing required parameters: provider and/or redirect_uri"
     }}
  end

  defp format_error({:error, :invalid_exchange_params}) do
    {400,
     %{
       error: "invalid_params",
       message: "Missing required parameters: state and/or code"
     }}
  end

  defp format_error({:error, {:missing_required_param, param}}) do
    {400,
     %{
       error: "missing_required_param",
       message: "Missing required parameter: #{param}"
     }}
  end

  defp format_error({:error, reason}) when is_atom(reason) do
    {400,
     %{
       error: to_string(reason),
       message: "OAuth operation failed: #{reason}"
     }}
  end

  defp format_error({:error, %Ecto.Changeset{} = changeset}) do
    errors =
      Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
        Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
          opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
        end)
      end)

    {422,
     %{
       error: "validation_failed",
       message: "Request validation failed",
       details: errors
     }}
  end

  defp format_error(error) do
    Logger.error("Unhandled OAuth API error: #{inspect(error)}")

    {500,
     %{
       error: "internal_server_error",
       message: "An unexpected error occurred"
     }}
  end
end

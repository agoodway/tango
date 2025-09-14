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
           Tango.authorize_url(session_token,
             redirect_uri: redirect_uri,
             scopes: parse_scopes(scopes)
           ) do
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
    code = conn.query_params["code"]
    state = conn.query_params["state"]
    error = conn.query_params["error"]
    error_description = conn.query_params["error_description"]

    # Log OAuth callback errors if present
    if error do
      log_oauth_callback_error(state, error, error_description)
    end

    # Handle token exchange server-side if we have code and state
    exchange_result = perform_callback_exchange(conn, code, state)

    # Generate callback HTML page with server-side exchange result
    html = generate_callback_html(code, state, error, error_description, exchange_result)

    conn
    |> put_resp_content_type("text/html")
    |> send_resp(200, html)
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

  # Perform server-side OAuth token exchange for callback flows
  defp perform_callback_exchange(_conn, nil, _state), do: nil
  defp perform_callback_exchange(_conn, _code, nil), do: nil

  defp perform_callback_exchange(conn, code, state) do
    with {:ok, tenant_id, _original_state} <- decode_state_safely(state),
         callback_url <- build_https_callback_url(conn),
         {:ok, connection} <-
           Tango.exchange_code(state, code, tenant_id, redirect_uri: callback_url),
         {:ok, provider} <- Tango.get_provider_by_id(connection.provider_id),
         access_token <- Connection.get_raw_access_token(connection) do
      {:ok, build_connection_response(connection, provider, access_token)}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_state}
    end
  end

  defp build_https_callback_url(conn) do
    build_callback_url(conn)
    # Ensure HTTPS for compatibility
    |> String.replace("http://", "https://")
  end

  defp build_connection_response(connection, provider, access_token) do
    %{
      provider: provider.name,
      status: connection.status,
      scopes: connection.granted_scopes,
      expires_at: connection.expires_at,
      access_token: access_token
    }
  end

  defp authenticate_api_key(conn, _opts) do
    # Skip authentication for endpoints that don't need it
    if conn.path_info == ["health"] or conn.path_info == ["callback"] do
      conn
    else
      case get_api_key(conn) do
        {:ok, api_key} ->
          if validate_api_key(api_key) do
            conn
          else
            conn
            |> put_resp_content_type("application/json")
            |> send_resp(
              401,
              Jason.encode!(%{
                error: "invalid_api_key",
                message: "Invalid or missing API key"
              })
            )
            |> halt()
          end

        :error ->
          conn
          |> put_resp_content_type("application/json")
          |> send_resp(
            401,
            Jason.encode!(%{
              error: "missing_api_key",
              message: "API key required. Provide via Authorization header or X-API-Key header"
            })
          )
          |> halt()
      end
    end
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

  defp decode_state_safely(nil), do: :error

  defp decode_state_safely(state) do
    case Tango.Auth.decode_state_with_tenant(state) do
      {:ok, original_state, tenant_id} -> {:ok, tenant_id, original_state}
      _ -> :error
    end
  rescue
    _ -> :error
  end

  defp log_oauth_callback_error(state, error, error_description) do
    alias Tango.Schemas.AuditLog

    # Try to decode state to get tenant ID and session info
    {tenant_id, session_id, event_type, error_code} =
      case decode_state_safely(state) do
        {:ok, decoded_tenant_id, original_state} ->
          {decoded_tenant_id, original_state, classify_oauth_error(error),
           map_oauth_error_code(error)}

        _ ->
          {"unknown", nil, :oauth_callback_error, :missing_callback_params}
      end

    event_data = %{
      oauth_error: error,
      error_description: error_description,
      state_present: !is_nil(state),
      state_decodable: tenant_id != "unknown"
    }

    AuditLog.log_oauth_callback_error(event_type, error_code, tenant_id, session_id, event_data)
    |> Application.get_env(:tango, :repo, Tango.TestRepo).insert()
    |> case do
      {:ok, _} ->
        :ok

      {:error, reason} ->
        Logger.warning("Failed to log OAuth callback error: #{inspect(reason)}")
        :ok
    end
  end

  defp classify_oauth_error("access_denied"), do: :oauth_denied
  defp classify_oauth_error(_), do: :oauth_provider_error

  defp map_oauth_error_code("access_denied"), do: :access_denied
  defp map_oauth_error_code("invalid_request"), do: :invalid_request
  defp map_oauth_error_code("invalid_client"), do: :invalid_client
  defp map_oauth_error_code("invalid_grant"), do: :invalid_grant
  defp map_oauth_error_code("unsupported_grant_type"), do: :unsupported_grant_type
  defp map_oauth_error_code("invalid_scope"), do: :invalid_scope
  defp map_oauth_error_code("server_error"), do: :server_error
  defp map_oauth_error_code("temporarily_unavailable"), do: :temporarily_unavailable
  defp map_oauth_error_code(_), do: :provider_error

  defp build_callback_url(conn) do
    conn
    |> Plug.Conn.request_url()
    |> URI.parse()
    |> Map.put(:path, conn.request_path)
    |> Map.put(:query, nil)
    |> Map.put(:fragment, nil)
    |> URI.to_string()
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

  defp parse_scopes(scopes) when is_binary(scopes) do
    String.split(scopes, " ", trim: true)
  end

  defp parse_scopes(scopes) when is_list(scopes), do: scopes
  defp parse_scopes(_), do: []

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

  defp generate_callback_html(_code, _state, _error, _error_description, exchange_result) do
    # Safely encode exchange result for JavaScript injection
    # Use HTML escaping to prevent XSS attacks
    result_json =
      case exchange_result do
        {:ok, data} -> Jason.encode!(data)
        {:error, reason} -> Jason.encode!(%{error: to_string(reason)})
        nil -> "null"
      end
      |> html_escape_json()

    """
    <!DOCTYPE html>
    <html>
    <head>
      <title>OAuth Callback</title>
      <meta charset="utf-8">
      <meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';">
    </head>
    <body>
      <div id="status">Processing OAuth callback...</div>
      
      <script>
        (function() {
          const urlParams = new URLSearchParams(window.location.search);
          const code = urlParams.get('code');
          const state = urlParams.get('state');
          const error = urlParams.get('error');
          const errorDescription = urlParams.get('error_description');
          
          async function handleCallback() {
            try {
              if (error) {
                throw new Error(errorDescription || error);
              }
              
              // Use server-side exchange result instead of making API calls
              const exchangeResult = #{result_json};
              
              if (!exchangeResult) {
                throw new Error('Missing authorization code or state parameter');
              }
              
              if (exchangeResult.error) {
                throw new Error(exchangeResult.error);
              }
              
              // Send success result to parent window
              if (window.opener) {
                window.opener.postMessage({
                  type: 'oauth_complete',
                  connection: {
                    provider: exchangeResult.provider,
                    status: exchangeResult.status,
                    scopes: exchangeResult.scopes,
                    expires_at: exchangeResult.expires_at,
                    token: exchangeResult.access_token
                  }
                }, '*');
              }
              
              document.getElementById('status').textContent = 'OAuth flow completed successfully. You can close this window.';
              
            } catch (error) {
              console.error('OAuth callback error:', error);
              
              // Send error to parent window
              if (window.opener) {
                window.opener.postMessage({
                  type: 'oauth_error',
                  error: error.message
                }, '*');
              }
              
              document.getElementById('status').textContent = 'OAuth flow failed: ' + error.message;
            }
          }
          
          // Process callback when page loads
          handleCallback();
        })();
      </script>
    </body>
    </html>
    """
  end

  # Safely escape JSON for injection into HTML/JavaScript contexts
  defp html_escape_json(json_string) do
    # Jason.encode! with escape: :html_safe handles XSS prevention automatically
    json_string
    |> Jason.decode!()
    |> Jason.encode!(escape: :html_safe)
  end
end

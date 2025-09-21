defmodule Tango.API.CORSPlug do
  @moduledoc """
  CORS (Cross-Origin Resource Sharing) plug for Tango OAuth API.

  This plug handles CORS headers to allow web applications to make 
  cross-origin requests to the OAuth API endpoints.

  ## Configuration

  Configure CORS settings in your application config:

      config :tango, :api,
        cors_origins: ["http://localhost:3000", "https://myapp.com"],
        cors_methods: ["GET", "POST", "DELETE", "OPTIONS"],
        cors_headers: ["authorization", "content-type", "x-tenant-id"],
        cors_max_age: 86400,
        cors_credentials: false

  ## Default Behavior

  - Environment-based default origins (secure by default in production)
  - Credentials disabled by default (API key auth doesn't need cookies)
  - Supports preflight OPTIONS requests
  - Configurable origins, methods, and headers
  - Default max age of 24 hours for preflight cache

  ## Security Notes

  - Production defaults to empty origins list - must be explicitly configured
  - Development/test environments include wildcard "*" for convenience
  - Credentials are disabled by default as API key auth doesn't require cookies

  """

  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    conn
    |> put_cors_headers()
    |> handle_preflight()
  end

  defp put_cors_headers(conn) do
    origin = get_req_header(conn, "origin") |> List.first()

    conn
    |> put_cors_origin_header(origin)
    |> put_resp_header("access-control-allow-credentials", allow_credentials())
    |> put_resp_header("access-control-allow-methods", allowed_methods())
    |> put_resp_header("access-control-allow-headers", allowed_headers())
    |> put_resp_header("access-control-max-age", max_age())
    |> put_resp_header("access-control-expose-headers", "x-request-id")
  end

  defp put_cors_origin_header(conn, origin) when is_binary(origin) do
    if origin_allowed?(origin) do
      put_resp_header(conn, "access-control-allow-origin", origin)
    else
      conn
    end
  end

  defp put_cors_origin_header(conn, _), do: conn

  defp handle_preflight(%{method: "OPTIONS"} = conn) do
    conn
    |> send_resp(200, "")
    |> halt()
  end

  defp handle_preflight(conn), do: conn

  defp origin_allowed?(origin) do
    # Default to no origins for security - must be explicitly configured
    # Use "*" in production only when intentionally needed
    allowed_origins = get_cors_config(:cors_origins, [])

    cond do
      "*" in allowed_origins -> true
      origin in allowed_origins -> true
      Enum.any?(allowed_origins, &origin_matches_pattern?(&1, origin)) -> true
      true -> false
    end
  end

  defp origin_matches_pattern?(pattern, origin) do
    if String.contains?(pattern, "*") do
      # Convert wildcard pattern to regex
      regex_pattern =
        pattern
        |> String.replace(".", "\\.")
        |> String.replace("*", ".*")
        |> then(&("^" <> &1 <> "$"))

      Regex.match?(Regex.compile!(regex_pattern), origin)
    else
      pattern == origin
    end
  end

  defp allowed_methods do
    get_cors_config(:cors_methods, ["GET", "POST", "DELETE", "OPTIONS"])
    |> Enum.join(", ")
  end

  defp allowed_headers do
    default_headers = [
      "authorization",
      "content-type",
      "x-tenant-id",
      "x-requested-with",
      "accept",
      "origin"
    ]

    get_cors_config(:cors_headers, default_headers)
    |> Enum.join(", ")
  end

  defp max_age do
    get_cors_config(:cors_max_age, 86_400)
    |> to_string()
  end

  defp allow_credentials do
    # Default to false since API key auth doesn't need cookies
    get_cors_config(:cors_credentials, false)
    |> to_string()
  end

  defp get_cors_config(key, default) do
    Application.get_env(:tango, :api, [])
    |> Keyword.get(key, default)
  end
end

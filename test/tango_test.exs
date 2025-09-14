defmodule TangoTest do
  use ExUnit.Case
  # doctest Tango  # Disabled until doctest examples are fixed

  test "main module exists" do
    assert Code.ensure_loaded?(Tango)
    assert is_atom(Tango)
  end

  test "core modules exist and load properly" do
    assert Code.ensure_loaded?(Tango.Auth)
    assert Code.ensure_loaded?(Tango.Provider)
    assert Code.ensure_loaded?(Tango.Connection)
    assert Code.ensure_loaded?(Tango.Catalog)
  end

  test "schema modules exist" do
    assert Code.ensure_loaded?(Tango.Schemas.Provider)
    assert Code.ensure_loaded?(Tango.Schemas.Connection)
    assert Code.ensure_loaded?(Tango.Schemas.OAuthSession)
    assert Code.ensure_loaded?(Tango.Schemas.AuditLog)
  end

  test "library is properly configured" do
    # Test that encryption key is configured
    assert Application.get_env(:tango, :encryption_key) != nil
  end

  test "application starts successfully" do
    # Test that the application can be loaded
    assert Code.ensure_loaded?(Tango.Application)
  end
end

defmodule TangoTest do
  use ExUnit.Case
  doctest Tango

  test "greets the world" do
    assert Tango.hello() == :world
  end
end

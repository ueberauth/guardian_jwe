defmodule Guardian.Token.JweTest do
  use ExUnit.Case
  doctest Guardian.Token.Jwe

  test "greets the world" do
    assert Guardian.Token.Jwe.hello() == :world
  end
end

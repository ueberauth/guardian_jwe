# Guardian.Token.Jwe [![Hex.pm](https://img.shields.io/hexpm/v/guardian_jwe.svg)](https://hex.pm/packages/guardian_jwe)

This package is a plugin for [Guardian](https://hex.pm/packages/guardian).

## Documentation

API documentation is available at [https://hexdocs.pm/guardian_jwe](https://hexdocs.pm/guardian_jwe)

## Installation

To install `Guardian.Token.Jwe`, first add it to your `mix.exs` file:

```elixir
def deps do
  [
    {:guardian_jwe, "~> 0.2.0"}
  ]
end
```

To use JWEs, you'll need to configure the `token_module` parameter in your Guardian implementation module.

```elixir
defmodule GuardianTest.Auth do
  use Guardian,
    otp_app: :guardian_test,
    token_module: Guardian.Token.Jwe

  def subject_for_token(resource, _claims) do
    sub = to_string(resource.id)

    {:ok, sub}
  end

  def resource_from_claims(claims) do
    {:ok, claims}
  end
end
```

To change the default algorithm used to encrypt JWEs, set the `allowed_algos` in your Guardian configuration:

```elixir
config :guardian_test, GuardianTest.Auth,
       issuer: "guardian_test",
       allowed_algos: ["A128GCMKW"],
       secret_key: "aaaaaaaaaaaaaaaa"
```

The JWE module uses the same claims and validations as JWT for verification.  With this configuration, your application should work without additional changes to your Guardian configuration.

## Implemented algorithms

Currently, this package supports the following algorithms for encrypting JWT tokens.

```
A128GCMKW
A192GCMKW
A256GCMKW

PBES2-HS256+A128KW
PBES2-HS384+A192KW
PBES2-HS512+A256KW
```

Each of the `AxxxGCMKW` require keys of specific bit sizes where the `xxx` corresponds to the required size of the key.

The `PBES2-HSxxx+AxxxKW` secret can be generated using `mix guardian.gen.secret`.

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/guardian_jwe](https://hexdocs.pm/guardian_jwe).


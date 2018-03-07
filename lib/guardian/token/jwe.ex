defmodule Guardian.Token.Jwe do
  @moduledoc """
  Deals with all things JWE.

  This module should not be used directly.  It is intended to be used by Guardian
  on behalf of your implementation as it's token module.

  The usage is exactly the same as JWTs, but JWE encryption is more strict about secret key sizes.

  The `secret_key` bit sizes must be exact for `AnnnGCMKW` algorithms.

  Specifically sized secrets can be generated by running `mix guardian.gen.secret <byte_size>`.
  For secrets < 32 bytes, generate the secret and trim the result.

  A128GCMKW - 128 bits/16 bytes
  A192GCMKW - 192 bits/24 bytes
  A256GCMKW - 256 bits/32 bytes
  A512GCMKW - 512 bits/64 bytes

  Supported algorithms:
  A128GCMKW
  A192GCMKW
  A256GCMKW
  A512GCMKW
  PBES2-HS256+A128KW
  PBES2-HS384+A192KW
  PBES2-HS512+A256KW
  """

  alias Guardian.{Config, Token.Jwt.Verify}
  alias JOSE.{JWE, JWK}

  import Guardian, only: [stringify_keys: 1]

  @default_algos ["A256GCMKW"]
  @default_token_type "access"
  @type_key "typ"
  @default_ttl {12, :hours}

  @alg_to_enc %{
    "A128GCMKW" => "A128GCM",
    "A192GCMKW" => "A192GCM",
    "A256GCMKW" => "A256GCM",
    "PBES2-HS256+A128KW" => "A128GCM",
    "PBES2-HS384+A192KW" => "A192GCM",
    "PBES2-HS512+A256KW" => "A256GCM"
  }

  @doc """
  Peek is not implemented for JWE as the claims are encrypted.
  """
  def peek(_mod, _token) do
    raise "Peek cannot be used with encrypted tokens"
  end

  @doc """
  Generate unique token id
  """
  def token_id, do: UUID.uuid4()

  @doc """
  Create a token. Uses the claims and encrypts the token.

  The signing secret will be found first from the options.
  If not specified the secret key from the configuration will be used.

  Configuration:

  * `secret_key` The secret key to use for signing

  Options:

  * `secret` The secret key to use for signing
  * `headers` The Jose headers that should be used
  * `allowed_algos`

  The secret may be in the form of any resolved value from `Guardian.Config`

  `claims` must be a JSON-serializable structure.
  """
  def create_token(mod, claims, opts) do
    secret = fetch_secret(mod, opts)
    jwk = jose_jwk(secret)
    jws = jose_jws(mod, opts)

    {_, token} =
      jwk
      |> JWE.block_encrypt(Poison.encode!(claims), jws)
      |> JWE.compact()

    {:ok, token}
  end

  @doc """
  Builds the default claims for all JWT tokens.

  Note:

  * `aud` is set to the configured `issuer` unless `aud` is set

  Options:

  Options may override the defaults found in the configuration.

  * `token_type` - Override the default token type
  * `token_ttl` - The time to live. See `Guardian.Token.ttl` type
  """
  def build_claims(mod, _resource, sub, claims, options) do
    claims =
      claims
      |> stringify_keys()
      |> set_jti()
      |> set_iat()
      |> set_iss(mod, options)
      |> set_aud(mod, options)
      |> set_type(mod, options)
      |> set_sub(mod, sub, options)
      |> set_ttl(mod, options)

    {:ok, claims}
  end

  @doc """
  Decodes the token and validates the signature.

  Options:

  * `secret` - Override the configured secret. `Guardian.Config.config_value` is valid
  * `allowed_algos` - a list of allowable algos
  """
  def decode_token(mod, token, opts \\ []) do
    jwk =
      mod
      |> fetch_secret(opts)
      |> jose_jwk()

    decrypted =
      jwk
      |> JWE.block_decrypt(token)
      |> elem(0)
      |> Poison.decode!()

    {:ok, decrypted}
  rescue
    _ -> {:error, :invalid_token}
  end

  @doc """
  Verifies the claims.

  Configuration:

  * `token_verify_module` Default `Guardian.Token.Jwt.Verify` the module to use to verify the claims
  """
  def verify_claims(mod, claims, options) do
    result =
      mod
      |> apply(:config, [:token_verify_module, Verify])
      |> apply(:verify_claims, [mod, claims, options])

    case result do
      {:ok, claims} -> apply(mod, :verify_claims, [claims, options])
      err -> err
    end
  end

  @doc """
  Revoking a JWT by default does not do anything.
  You'll need to track the token in storage in some way
  and revoke in your implementation callbacks.
  See `GuardianDb` for an example.
  """
  def revoke(_mod, claims, _token, _opts), do: {:ok, claims}

  @doc """
  Refresh the token

  Options:

  * `secret` - Override the configured secret. `Guardian.Config.config_value` is valid
  * `allowed_algos` - a list of allowable algos
  * `token_ttl` - The time to live. See `Guardian.Token.ttl` type
  """
  def refresh(mod, old_token, options) do
    with {:ok, old_claims} <- apply(mod, :decode_and_verify, [old_token, %{}, options]),
         {:ok, claims} <- refresh_claims(mod, old_claims, options),
         {:ok, token} <- create_token(mod, claims, options) do
      {:ok, {old_token, old_claims}, {token, claims}}
    else
      {:error, _} = err -> err
      err -> {:error, err}
    end
  end

  @doc """
  Exchange a token of one type to another.

  Type is encoded in the `typ` field.

  Options:

  * `secret` - Override the configured secret. `Guardian.Config.config_value` is valid
  * `allowed_algos` - a list of allowable algos
  * `token_ttl` - The time to live. See `Guardian.Token.ttl` type
  """
  def exchange(mod, old_token, from_type, to_type, options) do
    with {:ok, old_claims} <- apply(mod, :decode_and_verify, [old_token, %{}, options]),
         {:ok, claims} <- exchange_claims(mod, old_claims, from_type, to_type, options),
         {:ok, token} <- create_token(mod, claims, options) do
      {:ok, {old_token, old_claims}, {token, claims}}
    else
      {:error, _} = err -> err
      err -> {:error, err}
    end
  end

  defp jose_jws(mod, opts) do
    algos = fetch_allowed_algos(mod, opts) || @default_algos
    headers = Keyword.get(opts, :headers, %{})

    alg = hd(algos)
    enc = Map.get(@alg_to_enc, alg)

    Map.merge(%{"alg" => alg, "enc" => enc}, headers)
  end

  defp jose_jwk(%JWK{} = the_secret), do: the_secret
  defp jose_jwk(the_secret) when is_binary(the_secret), do: JWK.from_oct(the_secret)
  defp jose_jwk(the_secret) when is_map(the_secret), do: JWK.from_map(the_secret)
  defp jose_jwk(value), do: Config.resolve_value(value)

  defp fetch_allowed_algos(mod, opts) do
    opts
    |> Keyword.get(:allowed_algos)
    |> Config.resolve_value() || apply(mod, :config, [:allowed_algos, @default_algos])
  end

  defp fetch_secret(mod, opts) do
    secret = Keyword.get(opts, :secret)
    secret = Config.resolve_value(secret) || apply(mod, :config, [:secret_key])

    case secret do
      nil -> raise "No secret key configured for JWE"
      val -> val
    end
  end

  defp set_type(%{"typ" => typ} = claims, _mod, _opts) when not is_nil(typ), do: claims

  defp set_type(claims, mod, opts) do
    defaults = apply(mod, :default_token_type, [])
    typ = Keyword.get(opts, :token_type, defaults)
    Map.put(claims, @type_key, to_string(typ || @default_token_type))
  end

  defp set_sub(claims, _mod, subject, _opts), do: Map.put(claims, "sub", subject)

  defp set_iat(claims) do
    ts = Guardian.timestamp()
    claims |> Map.put("iat", ts) |> Map.put("nbf", ts - 1)
  end

  defp set_ttl(%{"exp" => exp} = claims, _mod, _opts) when not is_nil(exp), do: claims

  defp set_ttl(%{"typ" => token_typ} = claims, mod, opts) do
    ttl = Keyword.get(opts, :ttl)

    if ttl do
      set_ttl(claims, ttl)
    else
      token_typ = to_string(token_typ)
      token_ttl = apply(mod, :config, [:token_ttl, %{}])
      fallback_ttl = apply(mod, :config, [:ttl, @default_ttl])

      ttl = Map.get(token_ttl, token_typ, fallback_ttl)
      set_ttl(claims, ttl)
    end
  end

  defp set_ttl(the_claims, {num, period}) when is_binary(num),
    do: set_ttl(the_claims, {String.to_integer(num), period})

  defp set_ttl(the_claims, {num, period}) when is_binary(period),
    do: set_ttl(the_claims, {num, String.to_existing_atom(period)})

  defp set_ttl(%{"iat" => iat_v} = the_claims, requested_ttl),
    do: assign_exp_from_ttl(the_claims, {iat_v, requested_ttl})

  # catch all for when the issued at iat is not yet set
  defp set_ttl(claims, requested_ttl), do: claims |> set_iat() |> set_ttl(requested_ttl)

  defp assign_exp_from_ttl(the_claims, {iat_v, {seconds, unit}}) when unit in [:second, :seconds],
    do: Map.put(the_claims, "exp", iat_v + seconds)

  defp assign_exp_from_ttl(the_claims, {iat_v, {minutes, unit}}) when unit in [:minute, :minutes],
    do: Map.put(the_claims, "exp", iat_v + minutes * 60)

  defp assign_exp_from_ttl(the_claims, {iat_v, {hours, unit}}) when unit in [:hour, :hours],
    do: Map.put(the_claims, "exp", iat_v + hours * 60 * 60)

  defp assign_exp_from_ttl(the_claims, {iat_v, {days, unit}}) when unit in [:day, :days],
    do: Map.put(the_claims, "exp", iat_v + days * 24 * 60 * 60)

  defp assign_exp_from_ttl(the_claims, {iat_v, {weeks, unit}}) when unit in [:week, :weeks],
    do: Map.put(the_claims, "exp", iat_v + weeks * 7 * 24 * 60 * 60)

  defp assign_exp_from_ttl(_, {_iat_v, {_, units}}), do: raise("Unknown Units: #{units}")

  defp set_iss(claims, mod, _opts) do
    issuer = mod |> apply(:config, [:issuer]) |> to_string()
    Map.put(claims, "iss", issuer)
  end

  defp set_aud(%{"aud" => aud} = claims, _mod, _opts) when not is_nil(aud), do: claims

  defp set_aud(claims, mod, _opts) do
    issuer = mod |> apply(:config, [:issuer]) |> to_string()
    Map.put(claims, "aud", issuer)
  end

  defp set_jti(claims), do: Map.put(claims, "jti", token_id())

  defp refresh_claims(mod, claims, options), do: {:ok, reset_claims(mod, claims, options)}

  defp exchange_claims(mod, old_claims, from_type, to_type, options) when is_list(from_type) do
    from_type = Enum.map(from_type, &to_string(&1))

    if Enum.member?(from_type, old_claims["typ"]) do
      exchange_claims(mod, old_claims, old_claims["typ"], to_type, options)
    else
      {:error, :incorrect_token_type}
    end
  end

  defp exchange_claims(mod, old_claims, from_type, to_type, options) do
    if old_claims["typ"] == to_string(from_type) do
      new_type = to_string(to_type)
      # set the type first because the ttl can depend on the type
      claims = Map.put(old_claims, "typ", new_type)
      claims = reset_claims(mod, claims, options)
      {:ok, claims}
    else
      {:error, :incorrect_token_type}
    end
  end

  defp reset_claims(mod, claims, options) do
    claims
    |> Map.drop(["jti", "iss", "iat", "nbf", "exp"])
    |> set_jti()
    |> set_iat()
    |> set_iss(mod, options)
    |> set_ttl(mod, options)
  end
end

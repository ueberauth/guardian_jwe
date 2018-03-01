defmodule Guardian.Token.Jwe do
  @moduledoc """
  Documentation for Guardian.Token.Jwe.
  """

  alias Guardian.{Config, Token.Jwt.Verify}
  alias JOSE.{JWE, JWS, JWK}

  import Guardian, only: [stringify_keys: 1]

  @default_algos ["A512GCMKW"]
  @default_token_type "access"
  @type_key "typ"
  @default_ttl {12, :hours}


  def peek(mod, token) do
    raise "Peek cannot be used with encrypted tokens"
  end

  def token_id(), do: UUID.uuid4()

#   @doc """
#   Build the default claims for the token
#   """
#   @callback build_claims(
#               mod :: module,
#               resource :: any,
#               sub :: String.t(),
#               claims :: claims,
#               options :: Keyword.t()
#             ) :: {:ok, claims} | {:error, atom}

  def build_claims(mod, resource, sub, claims, options) do
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

  # def create_token(mod, claims, options \\ []) do
  #   secret = fetch_secret(mod, options)

  #   {_, token} =
  #     secret
  #     |> jose_jwk()
  #     |> JWT.sign(jose_jws(mod, options), claims)
  #     |> JWS.compact()

  #   {:ok, token}
  # end
#   @doc """
#   Create the token including serializing and signing
#   """
#   @callback create_token(mod :: module, claims :: claims, options :: Guardian.options()) ::
#               {:ok, token} | signing_error | secret_error | encoding_error
# encrypted_a192gcmkw =
  # JOSE.JWE.block_encrypt(jwk_oct192, "{}", %{ "alg" => "A192GCMKW", "enc" => "A192GCM" })
  # |> JOSE.JWE.compact
  # |> elem(1)
  @alg_to_enc %{
    "A128GCMKW" => "A128GCM",
    "A192GCMKW" => "A192GCM",
    "A256GCMKW" => "A256GCM",
    "A512GCMKW" => "A512GCM",
    "PBES2-HS256+A128KW" => "A128GCM",
    "PBES2-HS384+A192KW" => "A192GCM",
    "PBES2-HS512+A256KW" => "A256GCM"
  }

  defp jose_jws(mod, opts) do
    algos = fetch_allowed_algos(mod, opts) || @default_algos
    headers = Keyword.get(opts, :headers, %{})

    alg = hd(algos)
    enc = Map.get(@alg_to_enc, alg)

    Map.merge(%{"alg" => alg, "enc" => enc}, headers)
  end

  def create_token(mod, claims, opts) do
    secret = fetch_secret(mod, opts)
    jwk = jose_jwk(secret)
    IO.puts "JWK : #{inspect jwk}"
    jws = jose_jws(mod, opts)

    {_, token} =
      jwk
      |> JWE.block_encrypt(Poison.encode!(claims), jws)
      |> JWE.compact()

    {:ok, token}
  end

#   @doc """
#   Decode the token. Without verification of the claims within it.
#   """
#   @callback decode_token(mod :: module, token :: token, options :: Guardian.options()) ::
#               {:ok, token} | secret_error | decoding_error
  # def decode_token(mod, token, options \\ []) do
  #   secret =
  #     mod
  #     |> fetch_secret(options)
  #     |> jose_jwk()

  #   algos = fetch_allowed_algos(mod, options)

  #   verify_result = JWT.verify_strict(secret, algos, token)

  #   case verify_result do
  #     {true, jose_jwt, _} -> {:ok, jose_jwt.fields}
  #     {false, _, _} -> {:error, :invalid_token}
  #   end
  # end

  def decode_token(mod, token, opts) do
    jwk =
      mod
      |> fetch_secret(opts)
      |> IO.inspect()
      |> jose_jwk()

    decrypt_result =
      JWE.block_decrypt(jwk, token)

# {"{\"typ\":\"access\",\"token\":\"heresatoken\",\"sub\":{\"id\":1},\"nbf\":1519885300,\"jti\":\"668989bc-7747-4d92-9afa-895db7c0a07d\",\"iss\":\"guardian_test\",\"iat\":1519885301,\"exp\":1519928501,\"auth\":\"github\",\"aud\":\"guardian_test\"}",
#  %JOSE.JWE{alg: {:jose_jwe_alg_pbes2,
#    {:jose_jwe_alg_pbes2, :sha512, 256,
#     <<80, 66, 69, 83, 50, 45, 72, 83, 53, 49, 50, 43, 65, 50, 53, 54, 75, 87, 0,
#       91, 116, 57, 255, 7, 0, 104, 61, 99, 162, 107, 125, 46, 49, 225, 241, 79,
#       250, 163, 44, 146, 78, 163, 132, ...>>, 8192}},
#   enc: {:jose_jwe_enc_aes,
#    {:jose_jwe_enc_aes, {:aes_gcm, 256}, 256, 32, 12, :undefined, :undefined,
#     :undefined, :undefined}}, fields: %{}, zip: :undefined}}
    case decrypt_result do
      {claims, _, _} -> {:ok, claims}
      _ -> {:error, :invalid_token}
    end

    {:ok, %{}}
  end

#   @callback verify_claims(mod :: module, claims :: claims, options :: Guardian.options()) ::
#               {:ok, claims} | {:error, any}
  def verify_claims(mod, claims, opts) do

    {:ok, %{}}
  end

#   @doc """
#   Revoke a token (if appropriate)
#   """
#   @callback revoke(mod :: module, claims :: claims, token :: token, options :: Guardian.options()) ::
#               {:ok, claims | {:error, any}}
  def revoke(mod, claims, token, opts) do

  end

#   @doc """
#   Refresh a token
#   """
#   @callback refresh(mod :: module, old_token :: token, options :: Guardian.options()) ::
#               {:ok, {token, claims}, {token, claims}} | {:error, any}

  def refresh(mod, old_token, token, opts) do

  end

#   @doc """
#   Exchange a token from one type to another
#   """
#   @callback exchange(
#               mod :: module,
#               old_token :: token,
#               from_type :: String.t() | [String.t(), ...],
#               to_type :: String.t(),
#               options :: Guardian.options()
#             ) :: {:ok, {token, claims}, {token, claims}} | {:error, any}
  def exchange(mod, old_token, from_type, to_type, opts) do

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
    secret = IO.inspect(Config.resolve_value(secret)) || apply(mod, :config, [:secret_key])

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
end

# defmodule Guardian.Token do
#   @moduledoc """
#   The behaviour module for all token modules.

#   Token modules are responsible for all the heavy lifting
#   in Guardian.
#   """
#   @type token :: String.t()
#   @type claims :: map
#   @type resource :: any
#   @type ttl ::
#           {pos_integer, :second}
#           | {pos_integer, :seconds}
#           | {pos_integer, :minute}
#           | {pos_integer, :minutes}
#           | {pos_integer, :day}
#           | {pos_integer, :days}
#           | {pos_integer, :week}
#           | {pos_integer, :weeks}

#   @type secret_error :: {:error, :secret_not_found}
#   @type signing_error :: {:error, :signing_error}
#   @type encoding_error :: {:error, atom}
#   @type decoding_error :: {:error, atom}
# end

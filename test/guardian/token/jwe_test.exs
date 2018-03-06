defmodule Guardian.Token.JweTest do
  use ExUnit.Case

  defmodule Impl do
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

  alias Guardian.Token.Jwe

  describe "A128GCMKW" do
    test "decrypts token successfully" do
      secret = JOSE.JWK.from_oct(<<0::128>>)

      {:ok, token} = create_token(secret, "A128GCMKW")
      {:ok, claims} = decode_token(token, secret, "A128GCMKW")

      assert claims["id"] == 1
    end

    test "returns invalid if secret is wrong" do
      secret = JOSE.JWK.from_oct(<<0::128>>)

      {:ok, token} = create_token(secret, "A128GCMKW")

      bad_secret = JOSE.JWK.from_oct("aaaaaaaaaaaaaaaa")

      {:error, :invalid_token} = decode_token(token, bad_secret, "A128GCMKW")
    end
  end

  describe "A192GCMKW" do
    test "successfully decrypts a token" do
      secret = JOSE.JWK.from_oct(<<0::192>>)

      {:ok, token} = create_token(secret, "A192GCMKW")
      {:ok, claims} = decode_token(token, secret, "A192GCMKW")

      assert claims["id"] == 1
    end

    test "returns error when token is invalid" do
      secret = JOSE.JWK.from_oct(<<0::192>>)

      {:ok, token} = create_token(secret, "A192GCMKW")

      bad_secret = JOSE.JWK.from_oct("aaaaaaaaaaaaaaaaaaaaaaaa")

      {:error, :invalid_token} = decode_token(token, bad_secret, "A192GCMKW")
    end
  end

  describe "A256GCMKW" do
    test "successfully decrypts a token" do
      secret = JOSE.JWK.from_oct(<<0::256>>)

      {:ok, token} = create_token(secret, "A256GCMKW")
      {:ok, claims} = decode_token(token, secret, "A256GCMKW")

      assert claims["id"] == 1
    end

    test "returns error when token is invalid" do
      secret = JOSE.JWK.from_oct(<<0::256>>)

      {:ok, token} = create_token(secret, "A256GCMKW")

      bad_secret = JOSE.JWK.from_oct("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

      {:error, :invalid_token} = decode_token(token, bad_secret, "A256GCMKW")
    end
  end

  @pbes_secret "gBMuMSI8o+gOoGP04iy/cXiGGwUyyNJNJLe7OA+uEkKZz6b8kDJ9y4to4Nf9umlG"

  describe "PBES2-HS256+A128KW" do
    test "successfully decrypts a token" do
      secret = JOSE.JWK.from_oct(@pbes_secret)

      {:ok, token} =
        create_token(secret, "PBES2-HS256+A128KW")

      {:ok, claims} =
        decode_token(token, secret, "PBES2-HS256+A128KW")

      assert claims["id"] == 1
    end

    test "returns error when decryption fails" do
      secret = JOSE.JWK.from_oct(@pbes_secret)

      {:ok, token} =
        create_token(secret, "PBES2-HS256+A128KW")

      bad_secret = JOSE.JWK.from_oct("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

      {:error, :invalid_token} =
        decode_token(token, bad_secret, "PBES2-HS256+A128KW")
    end
  end

  describe "PBES2-HS384+A192KW" do
    test "success" do
      secret = JOSE.JWK.from_oct(@pbes_secret)

      {:ok, token} =
        create_token(secret, "PBES2-HS256+A128KW")

      {:ok, claims} =
        decode_token(token, secret, "PBES2-HS256+A128KW")

      assert claims["id"] == 1
    end

    test "decryption failure" do
      secret = JOSE.JWK.from_oct(@pbes_secret)

      {:ok, token} =
        create_token(secret, "PBES2-HS256+A128KW")

      bad_secret = JOSE.JWK.from_oct("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

      {:error, :invalid_token} =
        decode_token(token, bad_secret, "PBES2-HS256+A128KW")
    end
  end

  describe "PBES2-HS512+A256KW" do
    test "success" do
      secret = JOSE.JWK.from_oct(@pbes_secret)

      {:ok, token} =
        create_token(secret, "PBES2-HS512+A256KW")

      {:ok, claims} =
        decode_token(token, secret, "PBES2-HS512+A256KW")

      assert claims["id"] == 1
    end

    test "decryption failure" do
      secret = JOSE.JWK.from_oct(@pbes_secret)

      {:ok, token} =
        create_token(secret, "PBES2-HS512+A256KW")

      bad_secret = JOSE.JWK.from_oct("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

      {:error, :invalid_token} =
        decode_token(token, bad_secret, "PBES2-HS512+A256KW")
    end
  end

  describe "exchange" do
    test "it refreshes the JWE exp" do
      secret = JOSE.JWK.from_oct(@pbes_secret)
      old_claims = %{
        "jti" => UUID.uuid4(),
        "aud" => "MyApp",
        "typ" => "access",
        "exp" => Guardian.timestamp + 10_000,
        "iat" => Guardian.timestamp,
        "iss" => "MyApp",
        "sub" => "User:1",
        "something_else" => "foo"
      }

      {:ok, token} =
        Jwe.create_token(
          __MODULE__.Impl,
          old_claims,
          secret: secret,
          allowed_algos: ["PBES2-HS512+A256KW"])

      {:ok, {^token = old_t, ^old_claims = old_c}, {new_t, new_c}} =
        Jwe.exchange(
          __MODULE__.Impl,
          token,
          "access",
          "refresh",
          [secret: secret, allowed_algos: ["PBES2-HS512+A256KW"]])

      refute old_t == new_t
      assert new_c["sub"] == old_c["sub"]
      assert new_c["aud"] == old_c["aud"]

      refute new_c["jti"] == old_c["jti"]
      refute new_c["nbf"] == old_c["nbf"]
      refute new_c["exp"] == old_c["exp"]
    end
  end

  defp create_token(secret, algo) do
    Jwe.create_token(
      __MODULE__.Impl,
      %{id: 1},
      secret: secret,
      allowed_algos: [algo])
  end

  defp decode_token(token, secret, algo) do
    Jwe.decode_token(
      __MODULE__.Impl,
      token,
      secret: secret,
      allowed_algos: [algo])
  end
end

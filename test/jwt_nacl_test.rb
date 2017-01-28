require "test_helper"
require "jwt_nacl/util"

describe JwtNacl do
  describe ".sign and .verify" do
    it "with private_key" do
      # seed = JwtNacl::Util.ed25519_random_seed
      # hex = seed.unpack("H*").first
      private_hex = "d2c5c54bc205266f12a8a21809aa2989536959f666a5d68710e6fab94674041a"
      private_key = [private_hex].pack("H*")
      claims = {iss: "mike", exp: 1300819380, :"http://example.com/is_root" => false}

      hsh_0 = JWT.sign(claims, private_key)
      jwt = hsh_0[:jwt]
      expect(jwt.split(".").length).must_equal 3
      expect(jwt).must_equal "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJpc3MiOiJtaWtlIiwiZXhwIjoxMzAwODE5MzgwLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6ZmFsc2V9.f2y6Sax9eK9M3JiFCt4ZfzzOL56SWNhydHpPPIoVkm21D3_bJq5DmFLgH8ee2OlzSlZMoq009jLSg6AC0mn4DA"

      public_key = hsh_0[:public_key]
      public_hex = public_key.unpack("H*").first
      expect(public_hex).must_equal "1e10af4b79b8d005c8b4237161f1350844b2e6c1a8d6aa4817151c04a2751731"
      expect(public_key.length).must_equal 32

      hsh_1 = JWT.verify(jwt, public_key)
      expect(hsh_1[:claims]).must_equal claims
    end

    it "without private_key" do
      claims = {iss: "carol", exp: 1900723794, :"http://example.com/is_root" => true}
      hsh_0 = JWT.sign(claims)
      jwt = hsh_0[:jwt]
      expect(jwt.split(".").length).must_equal 3

      private_key = hsh_0[:private_key]
      expect(private_key.length).must_equal 32
      public_key = hsh_0[:public_key]
      expect(public_key.length).must_equal 32

      hsh_1 = JWT.verify(jwt, public_key)
      expect(hsh_1[:claims]).must_equal claims
    end
  end

  describe ".sign with invalid claims" do
    it "nil" do
      e = assert_raises(RuntimeError) { JWT.sign(nil) }
      assert_match(/invalid claims/, e.message)
    end

    it "an empty string" do
      e = assert_raises(RuntimeError) { JWT.sign("") }
      assert_match(/invalid claims/, e.message)
    end

    it "an empty hash" do
      e = assert_raises(RuntimeError) { JWT.sign(Hash.new) }
      assert_match(/invalid claims/, e.message)
    end

    it "a string" do
      e = assert_raises(RuntimeError) { JWT.sign("claims") }
      assert_match(/invalid claims/, e.message)
    end
  end
end

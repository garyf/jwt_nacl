require "test_helper"
require "jwt_nacl/ed25519"
require "jwt_nacl/util"

module JwtNacl
  describe Ed25519 do
    describe ".sign and .verify" do
      it "with seed, rejects a changed message or signature" do
        seed = Util.ed25519_random_seed
        # Base64Url.encode('{"typ":"JWT", "alg":"Ed25519"}').Base64Url.encode('{"iss":"alice","exp":1506459923,"http://example.com/admin":true}')
        message_0 = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoiRWQyNTUxOSJ9.eyJpc3MiOiJhbGljZSIsImV4cCI6MTUwNjQ1OTkyMywiaHR0cDovL2V4YW1wbGUuY29tL2FkbWluIjp0cnVlfQ"
        hsh_0 = Ed25519.sign(message_0, seed)

        public_key = hsh_0[:public_key]
        expect(public_key.length).must_equal 32

        expect(Ed25519.verify(public_key, hsh_0[:signature], message_0)).must_equal message_0
        expect(hsh_0[:private_key].length).must_equal 32

        # Base64Url.encode('{"typ":"JWT", "alg":"Ed25519"}').Base64Url.encode('{"iss":"bob","exp":1506459923,"http://example.com/admin":false}')
        message_1 = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoiRWQyNTUxOSJ9.eyJpc3MiOiJib2IiLCJleHAiOjE1MDY0NTk5MjMsImh0dHA6Ly9leGFtcGxlLmNvbS9hZG1pbiI6ZmFsc2V9"
        expect(Ed25519.verify(public_key, hsh_0[:signature], message_1)).must_equal false

        e = assert_raises(RbNaCl::BadSignatureError) do
          Ed25519.verify_key(public_key, hsh_0[:signature], message_1)
        end
        assert_match(/signature was forged\/corrupt/, e.message)

        hsh_1 = Ed25519.sign(message_1, seed)
        expect(Ed25519.verify(public_key, hsh_1[:signature], message_0)).must_equal false

        e = assert_raises(RbNaCl::BadSignatureError) do
          Ed25519.verify_key(public_key, hsh_1[:signature], message_0)
        end
        assert_match(/signature was forged\/corrupt/, e.message)
      end

      it "without seed, rejects a changed message or signature" do
        # Base64Url.encode('{"typ":"JWT", "alg":"Ed25519"}').Base64Url.encode('{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}')
        message_0 = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoiRWQyNTUxOSJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        hsh_0 = Ed25519.sign(message_0)

        public_key = hsh_0[:public_key]
        expect(public_key.length).must_equal 32

        expect(Ed25519.verify(public_key, hsh_0[:signature], message_0)).must_equal message_0
        expect(hsh_0[:private_key].length).must_equal 32

        # Base64Url.encode('{"typ":"JWT", "alg":"Ed25519"}').Base64Url.encode('{"iss":"mike","exp":1300819380,"http://example.com/is_root":false}')
        message_1 = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoiRWQyNTUxOSJ9.eyJpc3MiOiJtaWtlIiwiZXhwIjoxMzAwODE5MzgwLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6ZmFsc2V9"
        expect(Ed25519.verify(public_key, hsh_0[:signature], message_1)).must_equal false

        e = assert_raises(RbNaCl::BadSignatureError) do
          Ed25519.verify_key(public_key, hsh_0[:signature], message_1)
        end
        assert_match(/signature was forged\/corrupt/, e.message)

        hsh_1 = Ed25519.sign(message_1)
        expect(Ed25519.verify(public_key, hsh_1[:signature], message_0)).must_equal false

        e = assert_raises(RbNaCl::BadSignatureError) do
          Ed25519.verify_key(public_key, hsh_1[:signature], message_0)
        end
        assert_match(/signature was forged\/corrupt/, e.message)
      end

      it "with reuse of keys" do
        # seed = Util.ed25519_random_seed.to_s
        # hex = seed.unpack("H*").first
        hex = "fd2387a2c23d5f675ab0616c32ce5cf89cef2ca099348b817852bae7210735e7"
        expect(hex.length).must_equal 64
        private_key = [hex].pack("H*")

        # Base64Url.encode('{"typ":"JWT", "alg":"Ed25519"}').Base64Url.encode('{"iss":"alice","exp":1506459923,"http://example.com/admin":true}')
        message_0 = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoiRWQyNTUxOSJ9.eyJpc3MiOiJhbGljZSIsImV4cCI6MTUwNjQ1OTkyMywiaHR0cDovL2V4YW1wbGUuY29tL2FkbWluIjp0cnVlfQ"
        hsh_0 = Ed25519.sign(message_0, private_key)
        public_key = hsh_0[:public_key]
        expect(Ed25519.verify(public_key, hsh_0[:signature], message_0)).must_equal message_0

        # Base64Url.encode('{"typ":"JWT", "alg":"Ed25519"}').Base64Url.encode('{"iss":"bob","exp":1506459923,"http://example.com/admin":false}')
        message_1 = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoiRWQyNTUxOSJ9.eyJpc3MiOiJib2IiLCJleHAiOjE1MDY0NTk5MjMsImh0dHA6Ly9leGFtcGxlLmNvbS9hZG1pbiI6ZmFsc2V9"
        hsh_1 = Ed25519.sign(message_1, private_key)
        expect(Ed25519.verify(public_key, hsh_1[:signature], message_1)).must_equal message_1
      end
    end
  end
end

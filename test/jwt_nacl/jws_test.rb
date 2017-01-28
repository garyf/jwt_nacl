require "test_helper"
require "jwt_nacl/jws"
require "jwt_nacl/util"

module JwtNacl
  describe Jws do
    describe ".sign and .verify" do
      it "with private_key" do
        # seed = Util.ed25519_random_seed
        # hex = seed.unpack("H*").first
        hex = "52647b30343608659d043fc880ed8c39d5765d6e91117e58694ff2f8e66e940e"
        private_key = [hex].pack("H*")
        payload = '{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}'

        hsh_0 = Jws.sign(payload, private_key)
        jwt = hsh_0[:jwt]
        expect(jwt.split(".").length).must_equal 3
        expect(hsh_0[:private_key]).must_equal private_key

        hsh_1 = Jws.verify(jwt, hsh_0[:public_key])
        expect(hsh_1[:jwt]).must_equal jwt
      end

      it "without private_key" do
        payload = '{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}'
        hsh_0 = Jws.sign(payload)
        jwt = hsh_0[:jwt]
        expect(jwt.split(".").length).must_equal 3
        expect(hsh_0[:private_key].length).must_equal 32

        hsh_1 = Jws.verify(jwt, hsh_0[:public_key])
        expect(hsh_1[:jwt]).must_equal jwt
      end
    end
  end
end

require "test_helper"
require "jwt_nacl/util"

module JwtNacl
  describe Util do
    describe ".ed25519_random_seed" do
      it "32 byte length" do
        expect(Util.ed25519_random_seed.length).must_equal 32
      end
    end
  end
end

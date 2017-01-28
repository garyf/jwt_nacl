require "test_helper"
require "jwt_nacl/util"

module JwtNacl
  describe Util do
    describe ".ed25519_random_seed" do
      it "32 byte length" do
        expect(Util.ed25519_random_seed.length).must_equal 32
      end
    end

    describe ".symbolize_keys" do
      it "returns a new hash with all keys converted to symbols" do
        original = {"a" =>  0, "b" => "2", c: "3"}
        expect(Util.symbolize_keys original).must_equal({a: 0, b: "2", c: "3"})
        expect(original).must_equal original
      end
    end
  end
end

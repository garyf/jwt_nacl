require "test_helper"
require "jwt_nacl/base64_url"

module JwtNacl
  describe Base64Url do
    describe ".encode" do
      it "typical" do
        str = '{"typ":"JWT", "alg":"Ed25519"}'
        encoded = Base64Url.encode(str)
        expect(Base64Url.decode encoded).must_equal str
      end

      it "with whitespace" do
        str = '{"typ" :"JWT" ,  "alg" :"Ed25519"   }'
        encoded = Base64Url.encode(str)
        expect(Base64Url.decode encoded).must_equal str
      end

      it "with line feed and carriage return" do
        str = '{"typ":"JWT",/n "a/rlg":"Ed25519"}'
        encoded = Base64Url.encode(str)
        expect(Base64Url.decode encoded).must_equal str
      end

      describe ".decode, given encoding" do
        it "with no padding char" do
          str = '{"typ":"JWT", "alg":"none"}'
          encoded = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoibm9uZSJ9"
          expect(Base64Url.encode str).must_equal encoded
          expect(Base64Url.decode encoded).must_equal str
        end

        it "with 1 padding char present" do
          str = '{"typ":"JWT", "alg":"algorithm"}'
          encoded = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoiYWxnb3JpdGhtIn0="
          expect(Base64Url.decode encoded).must_equal str
        end

        it "with 1 padding char removed" do
          str = '{"typ":"JWT", "alg":"algorithm"}'
          encoded = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoiYWxnb3JpdGhtIn0"
          expect(Base64Url.encode str).must_equal encoded
          expect(Base64Url.decode encoded).must_equal str
        end

        it "with 2 padding char present" do
          str = '{"typ":"JWT", "alg":"Ed448"}'
          encoded = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoiRWQ0NDgifQ=="
          expect(Base64Url.decode encoded).must_equal str
        end

        it "with 2 padding char removed" do
          str = '{"typ":"JWT", "alg":"Ed448"}'
          encoded = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoiRWQ0NDgifQ"
          expect(Base64Url.encode str).must_equal encoded
          expect(Base64Url.decode encoded).must_equal str
        end
      end

      describe "invalid encoding" do
        it "raises" do
          encoded = "InR5cCI6IkpXVCIsICJhbGciOiJub25lI"
          e = assert_raises(RuntimeError) { Base64Url.decode(encoded) }
          assert_match(/Invalid base64 string/, e.message)
        end
      end
    end
  end
end

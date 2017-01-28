require "jwt_nacl/base64_url"
require "jwt_nacl/ed25519"

module JwtNacl
  # Represent content to be secured with digital signatures
  # @see http://tools.ietf.org/html/rfc7515
  module Jws
    HEADER = {
      alg: "Ed25519",
      typ: "JWT"
    }
    JWS_PARTS = 3

    module_function

    # @param payload [String] input for a digital signature computation
    # @param private_key [String] 32 random bytes (optional)
    # @return [Hash] a hash with a signed jwt, private_key, and public_key
    # @example
    #   Jws.sign(payload, private_key)
    #   # => {jwt: jwt, private_key: private_key, public_key: public_key}
    def sign(payload, private_key = nil)
      signing_input = encode_input(payload)
      hsh = Ed25519.sign(signing_input, private_key)
      {
        jwt: "#{signing_input}.#{Base64Url.encode(hsh[:signature])}",
        private_key: hsh[:private_key],
        public_key: hsh[:public_key]
      }
    end

    # @param jwt [String] input to be authenticated
    # @param public_key [String] 32 byte key used to authenticate a digital signature
    # @return [Hash] a hash with a verified jwt (e.g. jwt: jwt) or not verified (e.g. error: "invalid")
    # @example
    #   Jws.verify(jwt, public_key)
    #   # => {jwt: jwt}
    def verify(jwt, public_key)
      verified?(jwt, public_key) ? {jwt: jwt} : {error: "invalid"}
    end

    def encode_input(payload)
      "#{Base64Url.encode(HEADER.to_json)}.#{Base64Url.encode(payload)}"
    end

    def verified?(jwt, public_key)
      ary = jwt.split(".")
      return unless ary.length == JWS_PARTS
      signature = Base64Url.decode(ary[2])
      message = "#{ary[0]}.#{ary[1]}"

      Ed25519.verify(public_key, signature, message)
    end

    private_class_method :encode_input,
      :verified?
  end
end

require "rbnacl/libsodium"
require "rbnacl"

module JwtNacl
  # Sign or verify JSON Web Signature (JWS) signing input using Edwards-curve
  # Digital Signature Algorithm (EdDSA) curve Ed25519
  # @see https://ed25519.cr.yp.to/
  module Ed25519
    module_function

    # @param message [String] input payload for a digital signature computation
    # @param seed [String] 32 random bytes (optional)
    # @return [Hash] a hash with the private_key, public_key, and signature
    # @example
    #   Ed25519.sign(message, seed)
    #   # => {private_key: private_key, public_key: public_key, signature: signature}
    def sign(message, seed = nil)
      signing_key = seed ? RbNaCl::SigningKey.new(seed) : RbNaCl::SigningKey.generate
      {
        private_key: signing_key.to_bytes,
        public_key: signing_key.verify_key.to_bytes,
        signature: signing_key.sign(message)
      }
    end

    # @param public_key [String] 32 byte key used to authenticate a digital signature
    # @param signature [String] alleged signature to be checked
    # @param message [String] message to be authenticated
    # @return [String, Boolean] verified message or false
    # @example
    #   Ed25519.verify(public_key, signature, message)
    #   # => message
    def verify(public_key, signature, message)
      verify_key(public_key, signature, message)
      message
    rescue
      false
    end

    def verify_key(public_key, signature, message)
      RbNaCl::VerifyKey.new(public_key)
        .verify(signature, message)
    end
  end
end

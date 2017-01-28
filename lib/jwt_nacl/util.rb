require "rbnacl/libsodium"
require "rbnacl"

module JwtNacl
  # Utility methods
  module Util
    ED25519_SEEDBYTES = 32

    module_function

    def ed25519_random_seed
      RbNaCl::Random.random_bytes(ED25519_SEEDBYTES)
    end
  end
end

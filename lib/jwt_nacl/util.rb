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

    # @param hsh [Hash]
    # @return [Hash] a new hash with all keys converted to symbols,
    #   provided that they respond to .to_sym
    # @example
    #   Util.symbolize_keys({"a" =>  0, "b" => "2", c: "3"})
    #   # => {a: 0, b: "2", c: "3"}
    # @see cf. rails activesupport/lib/active_support/core_ext/hash/keys.rb
    def symbolize_keys(hsh)
      transform_keys(hsh) { |key| key.to_sym rescue key }
    end

    def transform_keys(hsh)
      result = Hash.new
      hsh.keys.each { |k| result[yield(k)] = hsh[k] }
      result
    end

    private_class_method :transform_keys
  end
end

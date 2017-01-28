require "jwt_nacl/jws"
require "jwt_nacl/util"

# Encode claims for transmission as a JSON object that is used as the payload
# of a JSON Web Signature (JWS) structure, enabling the claims
# to be integrity protected with a signature for later verification
# @see http://tools.ietf.org/html/rfc7519
module JwtNacl
  module_function

  # @param claims [Hash] input for a digital signature computation
  # @param private_key [String] 32 random bytes (optional)
  # @return [Hash] a hash with a signed jwt, private_key, and public_key
  # @example
  #   claims = {iss: "mike", exp: 1300819380, :"http://example.com/is_root" => false}
  #   private_hex = "d2c5c54bc205266f12a8a21809aa2989536959f666a5d68710e6fab94674041a"
  #   private_key = [private_hex].pack("H*")
  #   public_hex = "1e10af4b79b8d005c8b4237161f1350844b2e6c1a8d6aa4817151c04a2751731"
  #   public_key = [public_hex].pack("H*")
  #   JwtNacl.sign(claims, private_key)
  #   # => {jwt: "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJpc3MiOiJtaWtlIiwiZXhwIjoxMzAwODE5MzgwLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6ZmFsc2V9.f2y6Sax9eK9M3JiFCt4ZfzzOL56SWNhydHpPPIoVkm21D3_bJq5DmFLgH8ee2OlzSlZMoq009jLSg6AC0mn4DA", private_key: private_key, public_key: public_key}
  def sign(claims, private_key = nil)
    Jws.sign(validated_payload(claims), private_key)
  end

  # @param jwt [String] a JSON Web Token
  # @param public_key [String] 32 byte verifying key
  # @return [Hash] +{claims: < the jwt claims set hash >}+ if the jwt verifies,
  #   or +{error: "invalid"}+ otherwise
  # @example
  #   jwt = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJpc3MiOiJtaWtlIiwiZXhwIjoxMzAwODE5MzgwLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6ZmFsc2V9.f2y6Sax9eK9M3JiFCt4ZfzzOL56SWNhydHpPPIoVkm21D3_bJq5DmFLgH8ee2OlzSlZMoq009jLSg6AC0mn4DA"
  #   hex = "1e10af4b79b8d005c8b4237161f1350844b2e6c1a8d6aa4817151c04a2751731"
  #   public_key = [hex].pack("H*")
  #   JwtNacl.verify(jwt, public_key)
  #   # => {claims: {iss: "mike", exp: 1300819380, :"http://example.com/is_root" => false}}
  def verify(jwt, public_key)
    verified_claims(Jws.verify(jwt, public_key))
  end

  def validated_payload(claims)
    raise("invalid claims") if !claims || claims.empty? || !claims.is_a?(Hash)
    claims.to_json
  end

  def verified_claims(hsh)
    return {error: "invalid"} if hsh[:error]
    {claims: decoded_claims(hsh[:jwt].split(".")[1])}
  end

  def decoded_claims(str)
    Util.symbolize_keys(
      JSON.parse(
        Base64Url.decode(str)
      )
    )
  end

  private_class_method :validated_payload,
    :verified_claims,
    :decoded_claims
end

# alias
JWT = JwtNacl

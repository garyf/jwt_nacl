# JWT NaCl [![travis][ci_img]][travis] [![yard docs][yd_img]][yard_docs] [![code climate][cc_img]][code_climate]

## A JSON Web Token (JWT) implementation using NaCl cryptography

### Description
A Ruby JSON Web Token implementation using Edwards-curve Digital Signature Algorithm ([EdDSA][eddsa]) [curve Ed25519 digital signatures][ed25519] from the state-of-the-art NaCl [Networking and Cryptography library][nacl] by [Daniel J. Bernstein][bernstein].

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'jwt_nacl'
```

And then execute:

    $ bundle

Or install it directly as:

    $ gem install jwt_nacl

### Philosophy & Design Goals
* Convention over configuration
* Use of state-of-the-art cryptography, including EdDSA Curve25519 elliptic curves
* Minimal API surface area
* Thorough test coverage
* Modularity for comprehension and extensibility

### Why NaCl?
Cryptography typically exposes a high degree of complexity, due to many possible configuration decisions. One poor choice could result in an insecure system.

NaCl is different. NaCl provides an expertly-assembled, high-level cryptographic API with the correct configuration already built-in. See [RbNaCl][rbnacl] for more rationale.

For a more conventional JWT implementation, please refer to the related [json_web_token](https://github.com/garyf/json_web_token) gem.

## Usage

### JWT.sign(claims, private_key)

Returns a 3 element hash that includes:
* a JSON Web Token
* the private key
* the public key

`claims` (required) hash (non-empty)

`private_key` (optional) string, 32 random byte signing key

Example

```ruby
require 'jwt_nacl'

claims = {iss: "mike", exp: 1300819380, :"http://example.com/is_root" => false}

private_hex = "d2c5c54bc205266f12a8a21809aa2989536959f666a5d68710e6fab94674041a"
private_key = [private_hex].pack("H*")

public_hex = "1e10af4b79b8d005c8b4237161f1350844b2e6c1a8d6aa4817151c04a2751731"
public_key = [public_hex].pack("H*")

# Sign with an elliptical curve Ed25519 digital signature
jwt = JWT.sign(claims, private_key)
#=> {
  jwt: "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJpc3MiOiJtaWtlIiwiZXhwIjoxMzAwODE5MzgwLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6ZmFsc2V9.f2y6Sax9eK9M3JiFCt4ZfzzOL56SWNhydHpPPIoVkm21D3_bJq5DmFLgH8ee2OlzSlZMoq009jLSg6AC0mn4DA",
  private_key: private_key,
  public_key: public_key
}
```

### JWT.verify(jwt, public_key)

Returns a hash:
* \{claims: < JWT claims set >\}, if the digital signature, is verified
* \{error: "invalid"\}, otherwise

`jwt` (required) is a JSON web token string

`public_key` (required) string, 32 byte verifying key

Example

```ruby
require 'jwt_nacl'

jwt = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJpc3MiOiJtaWtlIiwiZXhwIjoxMzAwODE5MzgwLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6ZmFsc2V9.f2y6Sax9eK9M3JiFCt4ZfzzOL56SWNhydHpPPIoVkm21D3_bJq5DmFLgH8ee2OlzSlZMoq009jLSg6AC0mn4DA"

hex = "1e10af4b79b8d005c8b4237161f1350844b2e6c1a8d6aa4817151c04a2751731"
public_key = [hex].pack("H*")

# Verify with an elliptical curve Ed25519 public key
JWT.verify(jwt, public_key)
#=> {claims: {iss: "mike", exp: 1300819380, :"http://example.com/is_root" => false}}
```

### Supported encryption algorithm
Ed25519, Edwards-curve Digital Signature Algorithm (EdDSA) using Curve25519

### Supported Ruby versions
Ruby 2.2.6 and up

[eddsa]: https://en.wikipedia.org/wiki/EdDSA
[ed25519]: http://ed25519.cr.yp.to/
[nacl]: http://nacl.cr.yp.to/
[bernstein]: https://en.wikipedia.org/wiki/Daniel_J._Bernstein

[rbnacl]: https://github.com/cryptosphere/rbnacl/blob/master/README.md
[travis]: https://travis-ci.org/garyf/jwt_nacl
[ci_img]: https://travis-ci.org/garyf/jwt_nacl.svg?branch=master
[yard_docs]: http://www.rubydoc.info/github/garyf/jwt_nacl
[yd_img]: http://img.shields.io/badge/yard-docs-blue.svg
[code_climate]: https://codeclimate.com/github/garyf/jwt_nacl
[cc_img]: https://codeclimate.com/github/garyf/jwt_nacl/badges/gpa.svg

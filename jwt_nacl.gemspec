# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'jwt_nacl/version'

Gem::Specification.new do |spec|
  spec.name          = "jwt_nacl"
  spec.version       = JwtNacl::VERSION
  spec.authors       = ["Gary Fleshman"]
  spec.email         = ["gfleshman@newforge-tech.com"]

  spec.summary       = "JSON Web Token (JWT) for Ruby using NaCl cryptography"
  spec.description   = <<-HERE
    A Ruby JSON Web Token implementation using NaCl Ed25519 digital signatures from the
    state-of-the-art networking and cryptography library by Daniel J. Bernstein.
  HERE
  spec.homepage      = "https://github.com/garyf/jwt_nacl"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.required_ruby_version = ">= 2.2.6"

  spec.add_runtime_dependency "rbnacl", "~> 4.0"
  spec.add_runtime_dependency "rbnacl-libsodium", "~> 1.0"

  spec.add_development_dependency "bundler", "~> 1.13"
  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "minitest-reporters", "~> 1.1"
  spec.add_development_dependency "rake", "~> 12.0"
  spec.add_development_dependency "simplecov", "~> 0.13"
  spec.add_development_dependency "yard", "~> 0.9"
  spec.add_development_dependency "wwtd", "~> 1.3"
end

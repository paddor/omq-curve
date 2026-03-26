# frozen_string_literal: true

require_relative "lib/omq/curve/version"

Gem::Specification.new do |s|
  s.name     = "omq-curve"
  s.version  = OMQ::CURVE_VERSION
  s.authors  = ["Patrik Wenger"]
  s.email    = ["paddor@gmail.com"]
  s.summary  = "CurveZMQ (RFC 26) encryption for OMQ"
  s.description = "Adds CURVE security (Curve25519 encryption and authentication) " \
                  "to OMQ sockets. Requires libsodium via rbnacl."
  s.homepage = "https://github.com/paddor/omq-curve"
  s.license  = "ISC"

  s.required_ruby_version = ">= 3.3"

  s.files      = Dir["lib/**/*.rb", "exe/*", "README.md", "LICENSE", "CHANGELOG.md"]
  s.bindir     = "exe"
  s.executables = ["omq-keygen"]

  s.add_dependency "omq", "~> 0.2"
  s.add_dependency "rbnacl", "~> 7.0"
end

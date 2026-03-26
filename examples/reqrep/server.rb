#!/usr/bin/env ruby
# frozen_string_literal: true

# Encrypted REQ/REP server using CURVE.
#
# Generates an ephemeral keypair and prints SERVER_KEY for the client.
#
# Usage:
#   ruby server.rb [endpoint]
#
# For persistent keys, use omq-keygen and set env vars:
#   SERVER_PUBLIC=<z85> SERVER_SECRET=<z85> ruby server.rb

require_relative "../../lib/omq/curve"
require "async"

endpoint = ARGV[0] || "tcp://*:5555"

if ENV["SERVER_SECRET"] && ENV["SERVER_PUBLIC"]
  server_secret = OMQ::Z85.decode(ENV["SERVER_SECRET"])
  server_public = OMQ::Z85.decode(ENV["SERVER_PUBLIC"])
else
  key           = RbNaCl::PrivateKey.generate
  server_secret = key.to_s
  server_public = key.public_key.to_s
end

server_key_z85 = OMQ::Z85.encode(server_public)

Async do
  rep           = OMQ::REP.new
  rep.mechanism = OMQ::Curve.server(server_public, server_secret)
  rep.bind(endpoint)

  puts "Server listening on #{rep.last_endpoint} (CURVE encrypted)"
  puts ""
  puts "  Start client with:"
  puts "  SERVER_KEY='#{server_key_z85}' ruby client.rb"
  puts ""

  loop do
    msg = rep.receive
    puts "  ← #{msg.inspect}"
    rep << msg.map(&:upcase)
  end
ensure
  rep&.close
end

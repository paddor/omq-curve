#!/usr/bin/env ruby
# frozen_string_literal: true

# Encrypted REQ/REP client using CURVE.
#
# Usage:
#   SERVER_KEY=<z85> ruby client.rb [endpoint]
#
# SERVER_KEY is printed by server.rb on startup.

require_relative "../../lib/omq/curve"
require "async"

endpoint   = ARGV[0] || "tcp://localhost:5555"
server_key = ENV["SERVER_KEY"]

unless server_key
  abort "Usage: SERVER_KEY=<z85> ruby client.rb [endpoint]"
end

# Ephemeral client keypair — a new one per session is fine.
client_key = RbNaCl::PrivateKey.generate

Async do
  req           = OMQ::REQ.new
  req.mechanism = OMQ::Curve.client(client_key.public_key.to_s, client_key.to_s,
                                    server_key: OMQ::Z85.decode(server_key))
  req.connect(endpoint)
  puts "Connected to #{endpoint} (CURVE encrypted)"

  loop do
    print "> "
    input = $stdin.gets&.chomp
    break if input.nil? || input.empty?

    req << input
    reply = req.receive
    puts "  → #{reply.inspect}"
  end
ensure
  req&.close
end

# frozen_string_literal: true

$VERBOSE = nil

require_relative '../lib/omq/curve'
require 'async'
require 'benchmark/ips'
require 'console'
Console.logger = Console::Logger.new(Console::Output::Null.new)

server_key = RbNaCl::PrivateKey.generate
server_pub = server_key.public_key.to_s
server_sec = server_key.to_s
client_key = RbNaCl::PrivateKey.generate
client_pub = client_key.public_key.to_s
client_sec = client_key.to_s

TRANSPORTS = {
  'ipc' => 'ipc:///tmp/omq_bench_curve_latency.sock',
  'tcp' => 'tcp://127.0.0.1:9100',
}

jit = defined?(RubyVM::YJIT) && RubyVM::YJIT.enabled? ? "+YJIT" : "no JIT"
puts "OMQ #{OMQ::VERSION} + CURVE | Ruby #{RUBY_VERSION} (#{jit})"
puts

payload = 'ping'

TRANSPORTS.each do |transport, addr|
  puts "--- #{transport} ---"

  Async do |task|
    rep           = OMQ::REP.new
    rep.mechanism = OMQ::Curve.server(server_pub, server_sec)
    rep.bind(addr)

    req           = OMQ::REQ.new
    req.mechanism = OMQ::Curve.client(client_pub, client_sec, server_key: server_pub)
    req.connect(addr)

    responder = task.async do
      loop do
        msg = rep.receive
        rep << msg
      end
    end

    # Warm up
    100.times do
      req << payload
      req.receive
    end

    Benchmark.ips do |x|
      x.config(warmup: 1, time: 3)

      x.report('roundtrip') do
        req << payload
        req.receive
      end
    end

    responder.stop
  ensure
    req&.close
    rep&.close
  end

  puts
end

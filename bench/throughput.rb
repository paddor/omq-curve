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

MSG_SIZES  = [64, 256, 1024, 4096]
TRANSPORTS = {
  'ipc' => ->(tag) { "ipc:///tmp/omq_bench_curve_tp_#{tag}.sock" },
  'tcp' => ->(tag) { "tcp://127.0.0.1:#{9000 + tag.hash.abs % 1000}" },
}

jit = defined?(RubyVM::YJIT) && RubyVM::YJIT.enabled? ? "+YJIT" : "no JIT"
puts "OMQ #{OMQ::VERSION} + CURVE | Ruby #{RUBY_VERSION} (#{jit})"
puts

TRANSPORTS.each do |transport, addr_fn|
  puts "--- #{transport} ---"

  MSG_SIZES.each do |size|
    payload = 'x' * size
    addr    = addr_fn.call("#{transport}_#{size}")

    Async do
      pull           = OMQ::PULL.new
      pull.mechanism = OMQ::Curve.server(server_pub, server_sec)
      pull.bind(addr)

      push           = OMQ::PUSH.new
      push.mechanism = OMQ::Curve.client(client_pub, client_sec, server_key: server_pub)
      push.connect(addr)

      # Warm up
      100.times do
        push << payload
        pull.receive
      end

      Benchmark.ips do |x|
        x.config(warmup: 1, time: 3)

        x.report("#{size}B") do
          push << payload
          pull.receive
        end
      end
    ensure
      push&.close
      pull&.close
    end
  end

  puts
end

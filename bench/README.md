# CURVE Benchmark Results

Measured on Linux x86_64, Ruby 4.0.2 +YJIT, using `benchmark-ips`.

## Latency (REQ/REP roundtrip)

| Transport | CURVE |
|-----------|-------|
| ipc | 148 µs |
| tcp | 170 µs |

## Throughput (PUSH/PULL, msg/s)

| Transport | 64 B | 256 B | 1024 B | 4096 B |
|-----------|------|-------|--------|--------|
| ipc | 22k | 20k | 17k | 11k |
| tcp | 15k | 15k | 11k | 7.5k |

## Notes

Each message is encrypted on send and decrypted on receive via
libsodium/rbnacl. Bare `crypto_box` encrypt+decrypt takes ~4 µs for
64B and ~17 µs for 4KB. The rest of the per-message overhead comes from
the larger CurveZMQ MESSAGE command framing (nonce + ciphertext + Poly1305
tag) increasing bytes on the wire.

## Running

```sh
bundle exec ruby --yjit bench/throughput.rb
bundle exec ruby --yjit bench/latency.rb
```

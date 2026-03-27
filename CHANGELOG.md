# Changelog

## 0.2.4 — 2026-03-27

### Fixed

- CURVE handshake deadlocks with buffered IO — missing `io.flush` after
  greeting, HELLO, INITIATE (client) and greeting, WELCOME, READY
  (server) writes caused both peers to block on read
- Tests used `minimum_write_size: 0` which bypassed IO buffering entirely,
  masking the flush bug

## 0.2.3 — 2026-03-26

### Changed

- Move version constant from `OMQ_CURVE_VERSION` to `OMQ::CURVE_VERSION`
  (also available as `OMQ::Curve::VERSION`)

## 0.2.2 — 2026-03-26

### Improved

- Inline frame wire encoding in encrypt, bypassing `Frame.new.to_wire`
  and its `IO::Buffer` allocation — especially helps larger messages
  (4KB TCP: +87% vs v0.2.0)

## 0.2.1 — 2026-03-26

### Improved

- 15–55% throughput improvement by bypassing `Command.from_body` in the
  MESSAGE decrypt hot path — parses the prefix directly via `byteslice`
  instead of allocating an `IO::Buffer`

## 0.2.0 — 2026-03-26

### Changed

- New API: `OMQ::Curve.server(pub, sec)` and `OMQ::Curve.client(pub, sec, server_key: k)`
  replace verbose per-socket options (`curve_server`, `curve_public_key`, etc.)
- `OMQ::Curve` is a convenience alias for `OMQ::ZMTP::Mechanism::Curve`
- Requires omq ~> 0.2

### Added

- `omq-keygen` executable for Z85 keypair generation
- `examples/reqrep/` with encrypted server/client scripts

## 0.1.0 — 2026-03-25

Initial release. CurveZMQ (RFC 26) encryption for OMQ.

- Curve25519-XSalsa20-Poly1305 encryption and authentication
- 4-step handshake (HELLO/WELCOME/INITIATE/READY)
- Anti-amplification and server statelessness per RFC 26
- Client authentication via allowlist or custom callable
- Z85 key encoding/decoding
- Requires libsodium via rbnacl

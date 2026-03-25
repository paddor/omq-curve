# Changelog

## 0.1.0 — 2026-03-25

Initial release. CurveZMQ (RFC 26) encryption for OMQ.

- Curve25519-XSalsa20-Poly1305 encryption and authentication
- 4-step handshake (HELLO/WELCOME/INITIATE/READY)
- Anti-amplification and server statelessness per RFC 26
- Client authentication via allowlist or custom callable
- Z85 key encoding/decoding
- Requires libsodium via rbnacl

# Contributing to zeronet-rust

## Setup

- Rust 1.75+ (stable). No special toolchain needed.
- `cargo build --workspace` and `cargo test --workspace` are the two commands that matter.
- SQLite is bundled (`rusqlite` `bundled` feature), so no system libsql required.

## Conventions

- Keep crate boundaries: `kad` (discovery) / `content` (crypto + addressing) /
  `net` (transport) / `storage` (persistence) / `worker` (download) / `api` (HTTP/WS).
  Put a change in the lowest-level crate that owns the concept.
- Zero warnings on `cargo build --workspace` is a hard requirement (CI enforces it).
- New wire RPCs go in `crates/net/src/rpc.rs`; server-side handlers in `server.rs`;
  client-side in `peer.rs` / `dht.rs`. Encrypted variant of a path should mirror the
  plaintext one so both stay in sync.
- Crypto changes: prefer vetted primitive crates over hand-rolled ciphers. The Noise-XX
  layer in `net::secure` is an exception, and only because the async `noise` crate was
  not viable; keep its test vectors and spec citation.

## Testing

- `cargo test -p <crate>` for focused work.
- Integration tests live in `crates/<crate>/tests/`.
- For real-network smoke, two processes are spawned; keep their ports off
  well-known ranges and use `std::env::temp_dir()` for scratch state.

## Commit style

Conventional-ish, lowercase imperative subject:

```
net: add Noise-XX encrypted transport (X25519+HKDF+ChaCha20-Poly1305)
<blank line>
- bullet list of what changed and why
- security-relevant notes
- test counts if meaningful
```

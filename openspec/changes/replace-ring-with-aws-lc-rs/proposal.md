## Why

The `paseto-wasm` library cannot be compiled for `wasm64-unknown-unknown` target because its dependency `rusty_paseto` requires `ring v0.17`, which does not support wasm64. This blocks the project from running in WebAssembly 64-bit environments such as Cloudflare Workers (which uses wasm32) but more importantly future-proofs for wasm64 targets. Additionally, `ring` is not actively maintained for new targets.

## What Changes

- Replace `ring` dependency with `aws-lc-rs` in `rusty_paseto` fork
- Fork `rusty_paseto` at latest version to enable wasm64 support
- Update `paseto-wasm` to use the forked `rusty_paseto` with `aws-lc-rs`
- Maintain API compatibility with existing `paseto-wasm` public API
- Ensure all PASETO versions (v3, v4, v5) continue to work

## Capabilities

### New Capabilities

- `wasm64-compatibility`: Core cryptographic operations must work on `wasm64-unknown-unknown` target using `aws-lc-rs` backend instead of `ring`

### Modified Capabilities

- (none - this is an implementation infrastructure change, not a behavior change)

## Impact

**Dependencies Modified:**

- `rusty_paseto` (forked) - replace `ring v0.17` with `aws-lc-rs v1.17`
- `paseto-wasm/Cargo.toml` - point to forked `rusty_paseto`

**Affected Code:**

- `src/v3.rs` - uses `rusty_paseto_v3`
- `src/v4.rs` - uses `rusty_paseto`
- `src/v5.rs` - already ring-free, no changes needed

**Build Targets:**

- `wasm32-unknown-unknown` - must continue working
- `wasm64-unknown-unknown` - must become buildable

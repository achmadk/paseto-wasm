## Why

Upgrade `getrandom` from v0.3 to v0.4.3 to stay current with upstream. v0.4.3 adds `wasm64-unknown-unknown` support for the `wasm_js` backend, drops unnecessary WASI dependency bindings, and brings various improvements. No API changes affect our usage — `getrandom::fill()` with the `wasm_js` feature works identically.

## What Changes

- Bump `getrandom` dependency from `0.3` to `0.4` in `Cargo.toml`
- Keep the `wasm_js` feature flag (unchanged in v0.4.x)
- No source code changes needed — `fill()` API is identical
- `Cargo.lock` will gain a third `getrandom` version (0.2.x and 0.3.x remain for transitive deps)

## Capabilities

### New Capabilities

_(none — pure dependency upgrade, no new capabilities)_

### Modified Capabilities

_(none — no spec-level behavior changes)_

## Impact

- **Dependencies**: `getrandom 0.4.3` replaces `0.3.4` as direct dep; `rand_core 0.9.5` still pulls `0.3.4` transitively
- **Source files**: None — all call sites (`src/v3.rs`, `src/v4.rs`, `src/v5.rs`) use `getrandom::fill()` which is unchanged
- **Build**: MSRV requirement bumps to Rust 1.85 (covered by our nightly 1.98.0 toolchain)

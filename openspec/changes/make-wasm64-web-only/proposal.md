## Why

The `build:wasm64:*` scripts claim to produce memory64 (`wasm64-unknown-unknown`) artifacts, but most of them silently build ordinary wasm32 modules — only `build:wasm64:web` passes the real target flags. Worse, full memory64 support is currently impossible in this project: Node v24's V8 lacks the shipped memory64 grammar (upstream V8 13.3 bump never landed in Node 24), and every PASETO feature (even default v4) pulls `ring`, a C/assembly library that cannot compile for wasm64 (no libc / C toolchain exists for that target). Keeping fake "wasm64" scripts misleads users into believing they ship 64-bit memory artifacts when they do not.

## What Changes

- **Remove the misleading wasm64 scripts that produce 32-bit output**: the `node`, `node:v3`, `web:v3`, and un-flagged variants are either impossible (node: no runtime support) or silently wrong (v3: ring cannot build for wasm64; node: no runtime support).
- **Keep a single honest web-only wasm64 build** (`build:wasm64:web`) that genuinely targets `wasm64-unknown-unknown` with `-Z build-std=std,panic_abort`, gated on default features only.
- **Add a pre-build guard** that fails loudly if the wasm64 target would be built with the `v3` feature or any `ring`-carrying dependency in the graph, instead of silently producing wasm32.
- **Document the constraints** in `package.json`/`README`: wasm64 is web-only, requires nightly + `-Z build-std`, no `threads` feature (panic=unwind unsupported), and Node.js runtime support is blocked upstream.
- **BREAKING**: the `build:wasm64:node*`, `build:wasm64:*:v3*`, and `build:wasm64:optimized:*` variants are removed rather than producing silent 32-bit output.

## Capabilities

### New Capabilities

- `wasm64-build`: Honest, web-only memory64 build pipeline — correct target flags, guard against ring/v3, documented runtime and toolchain constraints.

### Modified Capabilities

<!-- No existing specs; this is a new capability. -->

## Impact

- `package.json` — wasm64 script set rewritten; misleading variants removed.
- Build tooling — pre-build guard (shell or small Node script) checking feature/target compatibility before invoking wasm-pack.
- `README.md` — document wasm64 scope (web-only, nightly, build-std, no threads, ring-free requirement).
- Dependencies — none changed in this change; explicitly out of scope: ring removal (tracked separately) and Node memory64 runtime support (blocked upstream).

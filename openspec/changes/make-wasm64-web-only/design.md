## Context

The project ships WebAssembly bindings for PASETO via wasm-pack. `package.json` contains a family of `build:wasm64:*` scripts that imply memory64 (`wasm64-unknown-unknown`) output, but verification shows:

- Only `build:wasm64:web` passes the genuine target flags (`--target wasm64-unknown-unknown -Z build-std=std,panic_abort`).
- The `node`, `node:v3`, `web:v3`, and `optimized:*` variants run plain wasm32 builds, silently producing 32-bit artifacts under a "wasm64" name.
- Runtime reality: Node.js v24 ships V8 13.0, which lacks the final memory64 JS grammar (`WebAssembly.Memory({address:"i64"})` throws `TypeError: Cannot convert 10 to a BigInt`; upstream bump to V8 13.3 for Node 24 never landed — nodejs/node#57469 → PR #57114).
- Build reality: `wasm64-unknown-unknown` is Tier 3, has no prebuilt `std` (requires `-Z build-std`), does not support `panic=unwind` (so no `threads`), and — per rustc docs — has no libc/C toolchain, so any C/assembly dependency cannot compile. `ring` (an unconditional dependency of `rusty_paseto` 0.10 both registry and git, and of `paserk`) is exactly such a dependency; aws-lc-rs is C-backed too, so the ring→aws-lc swap does not unblock wasm64.
- Existing OpenSpec changes: `upgrade-getrandom-to-v0-4-3` (in progress), `replace-ring-with-aws-lc-rs` (proposed, not started).

## Goals / Non-Goals

**Goals:**

- Make the one viable wasm64 build (web, default features) genuinely target memory64 and be verifiable as such.
- Eliminate misleading "wasm64" scripts that emit wasm32.
- Guard wasm64 builds so incompatible feature/dependency combinations fail loudly with actionable messages.
- Document the real constraints (web-only, nightly + build-std, no threads, ring-free requirement, Node blocked upstream).

**Non-Goals:**

- Removing `ring` / replacing with aws-lc-rs or a pure-Rust backend (tracked in `replace-ring-with-aws-lc-rs`; note aws-lc does not help wasm64 — pure Rust would be required).
- Making wasm64 work on Node.js (blocked upstream on Node/V8).
- Adding the `threads` feature to wasm64 (impossible: no `panic=unwind`).

## Decisions

### D1: Keep only `build:wasm64:web` (default features); delete the rest

The non-web and v3 variants have no valid output: Node runtime cannot load memory64, and v3 pulls ring (C-backed) which cannot compile for wasm64. Keeping them honest means removing them — a half-implemented script that emits wasm32 under a wasm64 name is worse than none (it silently misleads).

- **Alternative considered**: Keep all scripts but add flags. Rejected: impossible for node (runtime) and v3 (compile) regardless of flags.
- **Alternative considered**: Keep scripts and mark "experimental". Rejected: they don't just fail — they produce wrong output that looks right.

### D2: Guard against ring/v3/threads via a small pre-build check

A `scripts/check-wasm64.js` (Node, no deps) runs before wasm-pack and:

1. Reads the requested features (default = v4 only).
2. Rejects `v3` (ring via rusty_paseto) and `threads` (panic=unwind) with targeted messages.
3. Optionally inspects `Cargo.lock` for `ring` presence and warns/fails per the spec requirement.
   This is cheaper and more reliable than relying on cargo's error text, and gives us one place to update messages when the ring-free migration lands.

- **Alternative considered**: Let cargo fail naturally. Rejected: error is cryptic and arrives late; we want an actionable pre-flight message.

### D3: Explicit wasm64 artifact verification in CI/scripts

Add a check that the produced module is actually memory64 (inspect the wasm binary's memory type via a tiny reader or `wasm-tools`/`wasm-opt` output), so "wasm64 build" cannot silently regress to wasm32. This makes D1 verifiable end-to-end.

### D4: Document constraints in README + package.json

Add a short "memory64 / wasm64" section: web-only, nightly toolchain required, `-Z build-std=std,panic_abort`, no threads, ring-free requirement, Node blocked upstream with references.

## Risks / Trade-offs

- [Removing scripts may break CI/user scripts that referenced `build:wasm64:node*`] → Mitigation: document removal in README migration note; message in the removed script slot if left as a stub (or note in release notes).
- [Guard false-negatives if feature resolution changes] → Mitigation: keep the guard minimal (feature names + `ring` in lock) and re-verify when deps change.
- [wasm64 web build still requires nightly and manual std build, which is slow/fragile] → Mitigation: keep it a separate explicit script (`build:wasm64:web`) never part of default `build`; document the nightly pin.
- [Pure-Rust crypto migration may change the guard's assumptions] → Mitigation: guard messages reference the ring-removal change; update guard as part of that change.

## Migration Plan

1. Implement the guard script and wire it into `build:wasm64:web`.
2. Rewrite the wasm64 script set in `package.json` (keep only honest web variants).
3. Add artifact memory64 verification to the script (or a `verify:wasm64` companion).
4. Update README with constraints and migration note for removed scripts.
5. Run `pnpm build:wasm64:web` and confirm: build succeeds, artifact verifies as memory64; run `pnpm build` (wasm32 path) to confirm no regression.

## Open Questions

- Should removed script names be left as failing stubs (clear error) or fully deleted? (Preference: full deletion + README note; stubs risk being mistaken for functional.)
- Should the guard fail or merely warn when `ring` is present in the lock graph but the default build path wouldn't link it into the wasm64 artifact? (Spec says fail — pending confirmation during implementation if lock analysis proves noisy.)

## 1. Guard Script

- [ ] 1.1 Create `scripts/check-wasm64.js` (zero-dependency Node) that rejects the `v3` feature (ring via rusty_paseto) and the `threads` feature with actionable messages
- [ ] 1.2 Add `ring` presence detection in `Cargo.lock` to the guard; fail with a message pointing at the ring-removal change
- [ ] 1.3 Ensure the guard exits non-zero on any blocked condition and prints the specific feature/dependency + mitigation

## 2. package.json Scripts

- [ ] 2.1 Rewrite the `build:wasm64:*` script set so only honest, default-feature web variants remain
- [ ] 2.2 Remove the misleading `build:wasm64:node*`, `build:wasm64:*:v3*`, and `build:wasm64:optimized:*` variants (or leave failing stubs per open question — prefer full removal)
- [ ] 2.3 Prepend the guard to `build:wasm64:web` before invoking wasm-pack

## 3. Artifact Verification

- [ ] 3.1 Add memory64 artifact verification (inspect wasm memory type) as a companion script or inline check
- [ ] 3.2 Wire verification so `build:wasm64:web` proves the produced module is memory64, not wasm32

## 4. Documentation

- [ ] 4.1 Add a "memory64 / wasm64" section to README: web-only, nightly + `-Z build-std=std,panic_abort`, no threads, ring-free requirement, Node blocked upstream (with upstream refs)
- [ ] 4.2 Add a migration note for removed wasm64 scripts

## 5. Verification

- [ ] 5.1 Run `pnpm build:wasm64:web` and confirm it builds and the artifact verifies as memory64
- [ ] 5.2 Confirm the guard rejects `v3`/`threads`/ring-bearing scenarios with actionable output
- [ ] 5.3 Run the standard wasm32 `build` path to confirm no regression

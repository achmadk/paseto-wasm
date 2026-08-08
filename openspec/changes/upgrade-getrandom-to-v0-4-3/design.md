## Context

The project uses `getrandom 0.3.4` with the `wasm_js` feature for cryptographically secure random number generation in WASM targets. The upgrade to `0.4.3` is a semver-compatible bump at the direct-dependency level — the `fill()` API and `wasm_js` feature are unchanged in behavior.

Currently there are two getrandom versions in the lock file:

- `0.2.17` — pulled by `rand_core 0.6.4` (used by `p384`, `ed25519-dalek`, `ring`)
- `0.3.4` — direct dep + pulled by `rand_core 0.9.5`

After the upgrade, `0.4.3` will replace `0.3.4` as the direct dependency; `rand_core 0.9.5` will keep `0.3.4` transitively.

## Goals / Non-Goals

**Goals:**

- Upgrade direct `getrandom` dependency to `0.4.3` with `wasm_js` feature
- Zero source code changes — same API, same feature flag
- Verify build and tests pass

**Non-Goals:**

- Consolidating transitive getrandom versions (0.2.x and 0.3.x stay)
- Changing any cryptographic behavior or random source selection
- Updating `rand_core` or other indirect dependencies

## Decisions

| Decision                   | Choice                                                 | Rationale                                                                                                         |
| -------------------------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| Version spec in Cargo.toml | `"0.4"` (minimum-compat) rather than `"0.4.3"` (exact) | Allows patch updates within 0.4.x; `Cargo.lock` pins the exact version                                            |
| Feature flag               | Keep `wasm_js` as-is                                   | Feature name and semantics unchanged in 0.4.x                                                                     |
| No changes to source files | Confirmed API compatibility                            | `getrandom::fill()` signature (`fn fill(dest: &mut [u8]) -> Result<(), Error>`) identical between 0.3.x and 0.4.x |

## Risks / Trade-offs

- **[Duplicate versions]** `getrandom 0.3.4` stays in the lock file due to `rand_core 0.9.5` → slight bloat but no functional impact
- **[MSRV]** getrandom 0.4.x requires Rust 1.85; our nightly 1.98.0 covers this, but if CI uses an older pinned toolchain it may need updating

## Context

The `paseto-wasm` project provides PASETO cryptographic operations (v3, v4, v5) compiled to WebAssembly. Currently, it depends on `rusty_paseto v0.9` which transitively requires `ring v0.17`. The `ring` crate does not support the `wasm64-unknown-unknown` target because it relies on precompiled assembly for specific architectures.

**Current dependency chain:**

```
paseto-wasm
├── rusty_paseto v0.9.0
│   └── ring v0.17.14  ← THE BLOCKER (no wasm64 support)
└── rusty_paseto_v3 (git dependency)
    └── ring v0.17.14  ← THE BLOCKER
```

**Key constraint**: The forked `rusty_paseto` must maintain API compatibility with the existing `paseto-wasm` API. No changes to `paseto-wasm/src/*.rs` should be needed beyond updating the dependency reference.

## Goals / Non-Goals

**Goals:**

- Enable compilation of `paseto-wasm` for `wasm64-unknown-unknown` target
- Maintain full backward compatibility with existing `paseto-wasm` API
- Ensure `wasm32-unknown-unknown` builds continue to work
- Replace `ring` with `aws-lc-rs` which has wasm64 support and is actively maintained

**Non-Goals:**

- Modifying `paseto-wasm` source code (src/*.rs)
- Changing PASETO cryptographic specifications or behavior
- Supporting other targets beyond wasm32 and wasm64
- Creating a general-purpose fork (focused on wasm64 compatibility only)

## Decisions

### Decision 1: Fork Strategy

**Choice**: Fork `rusty_paseto` from `https://github.com/rrrodzilla/rusty_paseto` at version `0.10.0` (latest)

**Rationale**:

- Version 0.10.0 is the latest stable release with updated dependencies
- Starting from latest version reduces the gap between fork and upstream
- Easier to maintain long-term if upstream accepts our changes

**Alternatives Considered**:

- Forking v0.9.0 (current): Simpler diff but stuck with older dependencies
- Creating fresh implementation: Too much work, reinvents wheel

### Decision 2: Replace `ring` with `aws-lc-rs`

**Choice**: Replace `ring = "0.17"` with `aws-lc-rs = "1.17"` in forked Cargo.toml

**Rationale**:

- `aws-lc-rs` is API-compatible with `ring` (designed as drop-in replacement)
- Supports `wasm64-unknown-unknown` target
- Actively maintained by AWS
- FIPS-capable (bonus)

**Key changes in fork Cargo.toml**:

```toml
# Before
ring = { version = "0.17", features = ["std"], optional = false }

# After
aws-lc-rs = { version = "1.17", features = ["std"], default-features = false }
```

**Alternatives Considered**:

- `ring` with custom wasm64 patches: Not maintainable
- Pure Rust implementations (chacha20poly1305): Would require significant rewrite
- Other FFI crypto libraries: Less compatible with existing API

### Decision 3: Cargo Feature Preservation

**Choice**: Keep same feature structure, just replace the underlying crypto crate

**Rationale**:

- `v4_local`, `v4_public`, `v3_local`, `v3_public` features remain
- Only the crypto backend changes, not the PASETO logic
- Minimal risk of breaking `paseto-wasm` integration

### Decision 4: WASM Target Compilation

**Choice**: Use `getrandom = "0.3"` with `wasm_js` feature for both wasm32 and wasm64

**Rationale**:

- `getrandom 0.3.x` supports wasm64
- `wasm_js` feature uses JavaScript's `crypto.getRandomValues()`
- Ensures consistent random number generation across WASM targets

## Risks / Trade-offs

| Risk                                               | Impact | Mitigation                                           |
| -------------------------------------------------- | ------ | ---------------------------------------------------- |
| `aws-lc-rs` API differs from `ring` in subtle ways | Medium | Write integration tests; may need small adapter code |
| Fork maintenance burden                            | Medium | Keep changes minimal; upstream PR if feasible        |
| Performance regression                             | Low    | Benchmark before/after; aws-lc-rs is optimized       |
| PASETO test vectors failing                        | Low    | Verify against official PASETO test vectors          |

### API Compatibility Notes

`aws-lc-rs` and `ring` have similar APIs but some differences in:

1. **Constant-time operations**: Slight API differences in `subtle` module
2. **Agreement (ECDH)**: Module path and trait names differ slightly
3. **Initialization**: `aws-lc-rs` may need explicit initialization

The forked code will need adapter shims where these differences occur.

## Migration Plan

1. **Phase 1: Fork Creation**
   - Fork `rusty_paseto` repository
   - Replace `ring` with `aws-lc-rs` in Cargo.toml
   - Fix any compile errors from API differences

2. **Phase 2: Testing**
   - Test `wasm32-unknown-unknown` builds
   - Run PASETO test vectors against forked implementation
   - Benchmark to ensure no regression

3. **Phase 3: Integration**
   - Update `paseto-wasm/Cargo.toml` to use forked `rusty_paseto`
   - Verify full test suite passes

4. **Phase 4: wasm64 Validation**
   - Install `wasm64-unknown-unknown` target
   - Build for wasm64 target
   - Run wasm64-specific tests

## Open Questions

1. **Will upstream accept a PR?** Should we attempt to contribute the `aws-lc-rs` replacement upstream instead of maintaining a fork?

2. **Which rusty_paseto version?** v0.10.0 has `ring` as non-optional dependency. Should we patch v0.9.0 instead (simpler diff but older)?

3. **v3_local specifically**: The v3 local encryption uses AES-CTR + HMAC-SHA384 via `aes`, `ctr`, `hmac`, `sha2`. This path doesn't use `ring` at the `rusty_paseto` level, but the dependency is still pulled in. Verify this is actually replaced.

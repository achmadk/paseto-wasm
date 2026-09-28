# Design

## Context

See proposal.md (Why) for motivation. Current state shaping this design:

- `src/v4.rs` already implements the exact key schedule v6.local needs: keyed BLAKE2b (`Blake2bMac<U56>` split into 32-byte `Ek` + 24-byte XChaCha20 nonce; `Blake2bMac<U32>` for `Ak`) over `"paseto-encryption-key" || n` / `"paseto-auth-key-for-aead" || n` with a 32-byte random `n`, XChaCha20 stream encryption, and a 32-byte tag over `PAE(h, n, c, f, i)`. Only the header (`v6.local.`) and PASERK prefixes differ.
- `src/common.rs` provides reusable `pae_encode`, `parse_token`, `format_token`, `constant_time_eq`, `decode_hex_key`, and PASERK helpers used identically by v3/v4/v5.
- `src/v5.rs` establishes the local-only precedent and the `pkg/v5` + `./v5` build/export pattern; `Cargo.toml` uses opt-in features (`v3`, `v5`) with `v4` as default.
- Nothing in the tree implements SLH-DSA (FIPS 205). The v6.public `PAE(pk, h, m, f, i)` order (public key first) is the opposite of v4-public's `PAE(h, m, f, i)`.
- Key-size coincidence: v6 key widths (32-byte symmetric, 64-byte secret / 32-byte public) match v4 widths, so the hex API shape (`64-char` / `128-char` / `64-char`) and `KeyPair` struct can be mirrored.

## Goals / Non-Goals

**Goals:**

- Byte-level interop with the v6 specification for both purposes, verified by official test vectors (not just roundtrips).
- v6.public signs and verifies inside WASM at acceptable latency; signing slowness (SLH-DSA-SHA2-128s is the small-but-slow parameter set) is documented, not solved.
- Zero changes to v3/v4/v5 behavior, exports, or bundle outputs.

**Non-Goals:**

- CBOR or other future encodings mentioned as future-proofing in the spec (JSON/string messages only, as today).
- `v6.public` key-wrapping / PASERK `k6.*` private-key encryption operations (no equivalent exists for v4 either).
- Performance optimization of the SLH-DSA implementation itself.

## Decisions

### 1. v6.local reuses the v4 key schedule verbatim

New `src/v6.rs` local functions mirror `v4_auth_key` / `v4_enc_parts` / `v4_tag` with `V6_LOCAL_HEADER = "v6.local."`. Rationale: the Version6.md Encrypt/Decrypt steps are identical to v4's construction (same domain-separation strings, same 56/32 split, same PAE piece order), so a direct port minimizes interop risk and review surface. Alternative (shared generic helper parameterized by header) was rejected: v3/v4/v5 each keep independent helpers and consistency with that pattern matters more than deduplication.

### 2. SLH-DSA via the RustCrypto `slh-dsa` crate, `SLH-DSA-SHA2-128s` parameter set (spike confirms)

Recommended: RustCrypto `slh-dsa` (pure Rust, FIPS 205, `no_std`-compatible, all 12 parameter sets, `signature`-crate traits) — it matches the existing RustCrypto dependency family (`chacha20`, `aes`, `sha2`, `hmac`, `ed25519-dalek`) and therefore the project's audit story. Fallback: `fips205` (integritychain; pure Rust, no-alloc, ships WASM examples, exposes RNG for FIPS 205 section 3.1 compliance). A first implementation task runs a spike that (a) confirms the exact parameter-set type name and key/signature byte layouts (pk 32B, sk 64B, sig 7856B), (b) builds for `wasm32-unknown-unknown`, and (c) measures sign/verify time plus `.wasm` size delta; the fallback is adopted only if any of those fail. Deterministic signing randomness follows the crate's default hedged construction; no custom RNG plumbing beyond the existing `getrandom` key generation.

### 3. `v6` is an opt-in Cargo feature like `v3`/`v5`

`v6 = [...]` in `Cargo.toml`, `#[cfg(feature = "v6")] pub mod v6;` in `lib.rs`, `pkg/v6` outputs and `./v6` export in `package.json`, mirroring the v5 entries. Rationale: SLH-DSA substantially grows the WASM binary; default-bundle users should not pay for it. The `default = ["v4"]` line is untouched.

### 4. PASERK `k6.*` prefixes mirror `k4.*`

`k6.local.` / `k6.secret.` / `k6.public.` for keys and `k6.lid.` / `k6.sid.` / `k6.pid.` for IDs, reusing `common::paserk_*` helpers with the v4 `sid`-from-public-half convention. Rationale: Version6.md does not define PASERK strings, and `k4.*`/`k5.*` precedent is the only in-repo signal; the assumption is recorded here and validated against official PASERK vectors during implementation — if the standard chose different prefixes, only the prefix constants change.

### 5. Test strategy: official vectors first, roundtrips second

Locate authoritative v6 vectors (`paseto-standard/test-vectors`, expected `v6.json` following the `v4.json` schema with fixed nonces; community fallback: `paseto-rs` `paseto-v6` vectors). Extend `test-vectors.mjs` / `test-cross-impl.mjs` harnesses rather than inventing a new format. Roundtrip + tamper tests in `tests/web.rs` cover what vectors cannot (random-nonce paths). PQ interop is claimed only after vector tests pass against an independent implementation's output.

## Risks / Trade-offs

- [Risk] RustCrypto `slh-dsa` allocates signatures on the stack (~7.8KB) and may stress WASM stack limits → Mitigation: spike measures under `wasm32-unknown-unknown`; fallback crate has no-alloc design.
- [Risk] SLH-DSA-SHA2-128s signing is slow (seconds-scale in naive builds) → Mitigation: document expected latency; keep sign off hot paths; benchmark via `benchmark.mjs` so the cost is visible, not hidden.
- [Risk] ~10KB+ tokens break cookie/header size assumptions for JS consumers → Mitigation: document size guidance in `readme.md`; `parse_token`'s 64KB cap already accommodates but is re-verified with max-size sig tokens.
- [Risk] `k6.*` prefix guess wrong → Mitigation: isolated prefix constants; vector cross-check task catches it before release.
- [Risk] WASM binary size regression from PQ code → Mitigation: opt-in feature keeps default bundle unchanged; size recorded in spike.

## Migration Plan

Additive only: new module, feature, exports, and artifacts. No migration or rollback beyond not enabling the `v6` feature. Release notes call out token sizes and signing latency.

## Open Questions

- Exact upstream location of official v6 test vectors (answered by the first implementation task; does not change specs or approach — fallbacks are defined above).
- Whether `benchmark.mjs` should include a separate PQ benchmark section or extend the existing table (presentation detail; resolved during implementation).

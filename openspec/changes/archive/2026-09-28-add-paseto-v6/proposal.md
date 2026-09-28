# Proposal

## Why

PASETO v6 (draft, `paseto-spec` commit `3c6faec`) introduces a post-quantum `v6.public` purpose (SLH-DSA-SHA256-128s) alongside a `v6.local` symmetric construction. This library currently ships v3/v4 plus draft v5-local only; users tracking the PASETO standard have no v6 path in WASM/JS environments. Adding full v6 now keeps `paseto-wasm` aligned with the spec while the PQ migration is still early.

## What Changes

- Add `v6.local` encrypt/decrypt (`v6.local.` tokens, 32-byte symmetric keys, XChaCha20 + keyed BLAKE2b) with footer and implicit-assertion binding, matching the Version6.md Encrypt/Decrypt steps.
- Add `v6.public` sign/verify (`v6.public.` tokens, SLH-DSA-SHA256-128s, 32-byte pk / 64-byte sk / 7856-byte sig, `PAE(pk,h,m,f,i)`) with footer and implicit-assertion binding, matching the Version6.md Sign/Verify steps.
- Add PASERK `k6.*` key serialization and key-ID derivation for local and public keys, mirroring the existing `k4.*`/`k5.*` API shape.
- Add `v6` Cargo feature, `src/v6.rs` module, WASM bindings, `pkg/v6` build outputs, and `./v6` package export, mirroring the v3/v5 build matrix.
- Add roundtrip, tamper-rejection, and official test-vector coverage for both purposes (vectors located during design; PQ interop cannot be claimed from roundtrips alone).

## Capabilities

### New Capabilities

- `paseto-v6-local`: symmetric v6.local encryption for WASM/JS (key generation, encrypt, decrypt with authentication, PASERK local serialization and key IDs).
- `paseto-v6-public`: post-quantum v6.public signatures for WASM/JS (keypair generation, sign, verify, PASERK secret/public serialization and key IDs).

### Modified Capabilities

- None. No existing capability requirements change; v3/v4/v5 behavior is untouched.

## Impact

- Affected code: new `src/v6.rs`, `src/lib.rs` (`pub mod v6`), `Cargo.toml` (`v6` feature + SLH-DSA dependency), `package.json` build scripts and `exports["./v6"]`, `tests/` + JS vector harnesses.
- New dependency: an SLH-DSA-SHA256-128s crate that is audited, FIPS-205-compatible for the `128s` parameter set, and WASM-compatible; selected during design via spike (binary-size and performance impact evaluated there).
- API surface: new `*_v6_local_*` / `*_v6_public_*` WASM exports only; no changes to existing v3/v4/v5 exports.
- Risk: 7856-byte signatures produce ~10KB+ tokens; downstream JS users (cookies/headers) and benchmark expectations are affected and documented in design.

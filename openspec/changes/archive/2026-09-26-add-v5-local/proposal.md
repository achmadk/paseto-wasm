# Proposal

## Why

The PASETO v5 draft (paseto-spec, pinned commit `3c6faec`) defines a new
protocol version whose `v5.local` construction is byte-for-byte identical to
the already-implemented `v3.local` (HKDF-SHA384 key split, AES-256-CTR,
HMAC-SHA384), differing only in header and PASERK prefixes. Adding `v5.local`
now gives users a forward-compatible symmetric-encryption API at near-zero
cryptographic risk, while the post-quantum `v5.public` (ML-DSA-87) side stays
out of scope until its open questions (signing randomness, key encoding,
missing test vectors) are resolved.

## What Changes

- New `v5` cargo feature gating a new `src/v5.rs` module with:
  - `generate_v5_local_key`, `encrypt_v5_local`, `decrypt_v5_local`
  - `key_to_paserk_v5_local`, `paserk_v5_local_to_key` (`k5.local.` prefix)
  - `get_v5_local_key_id` (`k5.lid.` prefix)
- `v5` feature reuses the existing optional crypto deps (`aes`, `ctr`,
  `digest`, `hkdf`, `hmac`, `sha2`); no new dependencies.
- New `pkg/v5` build outputs and `./v5` package export, mirroring the `v3`
  pattern (`build:wasm:web:v5`, `build:wasm:node:v5`, test script).
- New roundtrip/footer/rejection tests for v5.local, mirroring the v3 tests.
- No changes to v3/v4 code paths, no asymmetric (`k5.secret`/`k5.public`,
  sign/verify) APIs in this change.

## Capabilities

### New Capabilities

- `paseto-v5-local`: symmetric encryption/decryption of PASETO v5.local
  tokens (encrypt, decrypt, key generation, PASERK `k5.local` conversion,
  `k5.lid` key IDs), per the v5 draft Encrypt/Decrypt sections.

### Modified Capabilities

(none — no existing spec-level behavior changes)

## Impact

- `Cargo.toml` (feature + optional-dep wiring), new `src/v5.rs`, `src/lib.rs`
  module gate, `package.json` scripts/exports, `tests/web.rs` additions,
  readme docs.
- WASM bundle size grows only when the `v5` feature is enabled; default
  (v4) build unaffected.

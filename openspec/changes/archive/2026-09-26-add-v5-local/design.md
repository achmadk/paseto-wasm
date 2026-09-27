# Design: add-v5-local

## Context

`src/v3.rs` implements HKDF-SHA384 key splitting, AES-256-CTR, and HMAC-SHA384
tagging behind the `v3` feature, with shared PAE/token/PASERK helpers in
`src/common.rs` (`pae_encode`, `format_token`, `parse_token`,
`paserk_encode`/`paserk_decode`, `paserk_id_from_bytes`). The v5 draft's
Encrypt/Decrypt sections specify the identical construction, differing only
in header (`v5.local.`) and PASERK (`k5.*`) constants. See proposal.md (Why)
for motivation.

## Goals / Non-Goals

- Goals: byte-exact v5.local construction per the draft; zero new
  dependencies; default (v4) build output unchanged.
- Non-Goals: any asymmetric API (`k5.secret`/`k5.public`, sign/verify);
  official cross-implementation vectors (none exist for v5 yet); changes to
  v3/v4 behavior or outputs.

## Decisions

1. **New `src/v5.rs` mirroring `src/v3.rs` local section, gated by a new
   `v5` feature.**
   Rationale: v5.local and v3.local share the algorithm but differ in
   version-bound constants; a separate module keeps version lucidity
   (key-to-algorithm binding per the draft's Algorithm Lucidity rule) and
   matches the existing one-module-per-version layout.
   Alternative (parameterize v3.rs by header): rejected — it would invite
   cross-version key reuse bugs and break the established layout.

2. **Reuse `common.rs` helpers unchanged** (`pae_encode`, `format_token`,
   `parse_token` with constant-time footer/tag comparison).
   Rationale: the draft mandates PAE order `(h, n, c, f, i)`,
   `n || c || t` payload layout, and constant-time compares — all already
   implemented and tested there.

3. **`v5 = ["dep:aes", "dep:ctr", "dep:digest", "dep:hkdf", "dep:hmac",
   "dep:sha2"]`** — the v3 optional-dep set minus `p384`.
   Rationale: optional deps may be enabled by multiple features, so v3 and
   v5 share them without duplication; `p384` stays v3-only.

4. **PASERK `k5.local.` + `k5.lid.` only.**
   Rationale: only the symmetric-key PASERK forms apply to a local-only
   scope; secret/public forms belong to the future asymmetric change. (The
   draft does not specify v5 PASERK; prefixes follow the v3/v4 convention.)

5. **`pkg/v5` outputs + `./v5` export + `build:wasm:{web,node}:v5` scripts,
   mirroring v3.**
   Rationale: consistent consumer experience across versions.

## Risks / Trade-offs

- [Draft drift] The v5 document is a draft at a pinned commit; final v5 may
  change → Mitigation: proposal records the exact commit; re-verify before
  release.
- [No cross-impl vectors] Interop cannot be proven, only self-roundtrip →
  Mitigation: spec scenarios require roundtrip/footer/rejection tests; add
  vector tests if official v5 vectors appear.
- [Draft typo] Verify step 5 says "`pk` MUST be 4627 bytes" (a sig length,
  not a key length) → Mitigation: irrelevant to local-only scope; recorded
  for the future asymmetric change.

## Migration Plan

Additive only: new feature flag, new module, new build outputs. No
migration or rollback beyond `cargo build` / `wasm-pack` verification;
disable by not enabling `v5`.

## Open Questions

None — remaining unknowns (ML-DSA randomness, key encoding) belong to the
future asymmetric change, not this one.

# Phase 5: PASETO V5 Implementation

**Phase:** 05-v5-implementation
**Goal:** Add PASETO v5 (Version 5) support as an optional feature (not default)

## User Vision

Implement PASETO Version 5 based on the official specification at https://raw.githubusercontent.com/paseto-standard/paseto-spec/02695e822cffc4c50915af84325423ee4a0da72b/docs/01-Protocol-Versions/Version5.md

## Cryptographic Specifications

| Property  | Local                     | Public                               |
| --------- | ------------------------- | ------------------------------------ |
| Algorithm | AES-256-CTR + HMAC-SHA384 | ML-DSA-87 (FIPS 204)                 |
| Key Size  | 32 bytes                  | 32 bytes (seed), 2592 bytes (public) |
| Signature | 48 bytes (MAC)            | 2420 bytes                           |
| Header    | `v5.local.`               | `v5.public.`                         |

### V5 Local Encryption Details

- Uses HKDF-HMAC-SHA384 for key splitting (into Ek and Ak)
- HKDF info: "paseto-encryption-key" || n and "paseto-auth-key-for-aead" || n
- 32-byte nonce generated from CSPRNG
- AES-256-CTR with derived key Ek and counter nonce n2
- HMAC-SHA384 for authentication

### V5 Public Signatures

- Uses ML-DSA-87 (CRYSTALS-Dilithium, now standardized as FIPS 204)
- 32-byte seed expands to 2560-byte key at runtime
- Public key is 2592 bytes
- Signature is 2420 bytes
- PAE includes: pk || h || m || f || i

## Key Differences from V3/V4

| Aspect      | V3                        | V4                   | V5                        |
| ----------- | ------------------------- | -------------------- | ------------------------- |
| Local Algo  | AES-256-CTR + HMAC-SHA384 | X25519 + AES-256-GCM | AES-256-CTR + HMAC-SHA384 |
| Public Algo | P-384 ECDSA               | Ed25519              | ML-DSA-87                 |
| Public Key  | 49 bytes                  | 32 bytes             | 2592 bytes                |
| Signature   | 96 bytes                  | 64 bytes             | 2420 bytes                |
| Key Split   | None (raw key)            | None (raw key)       | HKDF-SHA384               |

## Feature Configuration

- **Default features:** `v4` (existing)
- **Added feature:** `v3` (existing)
- **New feature:** `v5` (to be added) - must be optional, not default

## Implementation Files

### New files to create:

1. `src/v5.rs` - Main V5 implementation module
2. Modify `src/lib.rs` - Add v5 module and feature flag

### External dependencies needed:

- `ml-dsa` - For ML-DSA-87 signatures (FIPS 204)
- `hkdf` (existing) - For V5 local key splitting
- `aes`/ctr/hmac/sha2 (existing) - Already available

## Decisions Required

None - follows existing v3/v4 patterns exactly.

# Plan: Fix V5 Local Encryption (RFC Compliant)

## Goal

Fix `encrypt_v5_local` / `decrypt_v5_local` to use AES-256-CTR + HMAC-SHA-384 per RFC spec.

## RFC Specification (v5.local)

- **Encryption**: AES-256-CTR (256-bit key)
- **Authentication**: HMAC-SHA-384 (Encrypt-then-MAC)
- **Key Derivation**: HKDF-SHA-384
- **MAC Size**: 48 bytes

## Current Issues

- Dependency version conflicts prevented correct implementations
- Need to pin compatible crate versions

## Changes Required

### 1. Cargo.toml - Pin Working Versions

```toml
aes = "0.8"        # was 0.9
ctr = "0.7"        # was 0.10
hmac = "0.10"       # was 0.12
sha2 = "0.10"       # was 0.11
hkdf = "0.12"       # was 0.13
```

### 2. src/v5.rs - Implement RFC-Compliant Algorithms

#### encrypt_v5_local:

1. Generate random nonce (32 bytes)
2. HKDF-SHA-384 expand: key + nonce → Ek (32b), Ak (48b), n2 (32b)
3. AES-256-CTR encrypt message with Ek + n2
4. HMAC-SHA-384 over PAE(m || c) with Ak → MIC (48 bytes)
5. Build token: v5.local.[footer.]nonce || ciphertext || MIC

#### decrypt_v5_local:

1. Parse nonce, ciphertext, MIC from token
2. HKDF-SHA-384 expand: key + nonce → Ek, Ak, n2
3. Verify HMAC-SHA-384 matches
4. AES-256-CTR decrypt with Ek + n2

### 3. Tests

- `test_v5_local` - basic encrypt/decrypt
- `test_v5_local_with_footer` - with footer
- `test_v5_local_wrong_key_fails` - error handling

## Acceptance Criteria

- [ ] Cargo builds with v5 feature
- [ ] WASM builds successfully
- [ ] Tests pass (or manually verified)
- [ ] Algorithm matches RFC spec exactly

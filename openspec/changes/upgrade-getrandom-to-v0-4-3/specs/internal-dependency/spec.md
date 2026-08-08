## MODIFIED Requirements

### Requirement: Cryptographic randomness source

The system SHALL use `getrandom` crate as the cryptographically secure random number generator for WASM targets (v3, v4, v5 key/nonce generation). The `wasm_js` feature SHALL be enabled to ensure `Crypto.getRandomValues` is used in browser/Node.js WASM environments.

**Change**: The `getrandom` crate version is updated from 0.3.x to 0.4.x. The `fill()` API and `wasm_js` feature are unchanged, so no behavioral difference exists.

#### Scenario: Key generation uses random bytes

- **WHEN** `generate_v3_local_key`, `generate_v4_local_key`, or `generate_v5_local_key` is called
- **THEN** a cryptographically random key is generated via `getrandom::fill()`

#### Scenario: Encryption uses random nonce

- **WHEN** `encrypt_v3_local`, `encrypt_v4_local`, or `encrypt_v5_local` is called
- **THEN** a random nonce is generated via `getrandom::fill()`

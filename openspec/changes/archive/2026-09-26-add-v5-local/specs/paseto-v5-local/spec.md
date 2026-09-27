# paseto-v5-local

## Purpose

Provide PASETO v5.local symmetric encryption for JavaScript environments via
WebAssembly, implementing the Encrypt and Decrypt operations of the PASETO v5
draft specification with the same API shape as the existing v3/v4 versions.

## ADDED Requirements

### Requirement: v5 local key generation

The system SHALL generate cryptographically random 32-byte symmetric keys
for v5.local encryption, encoded as 64-character hex strings.

#### Scenario: Generate key

- WHEN a caller requests a new v5 local key
- THEN the system returns a 64-character hex string decoding to 32 random
  bytes, with successive calls returning distinct keys.

### Requirement: v5 local encryption

The system SHALL encrypt string or JSON-object messages into tokens starting
with `v5.local.`, using a caller-supplied 32-byte hex key and optional footer
and implicit assertion strings, such that only the matching key, footer, and
implicit assertion can decrypt the token.

#### Scenario: Encrypt and decrypt roundtrip

- WHEN a message is encrypted with a valid key and then decrypted with the
  same key, footer, and implicit assertion
- THEN decryption returns the original message bytes.

#### Scenario: Reject invalid key

- WHEN encryption or decryption is attempted with a key that is not valid
  hex or not 32 bytes
- THEN the operation fails with a key-length error and no token is produced.

#### Scenario: Footer binding

- WHEN a token is created with a footer and decrypted with a different or
  missing footer
- THEN decryption fails.

### Requirement: v5 local decryption authentication

The system SHALL verify token integrity with a constant-time comparison of
the authentication tag before decrypting, and SHALL reject tokens with an
invalid header, truncated payload, tampered ciphertext, or wrong key.

#### Scenario: Reject tampered token

- WHEN any byte of the ciphertext or tag portion of a valid token is altered
- THEN decryption fails and no plaintext is returned.

#### Scenario: Reject wrong key

- WHEN a token is decrypted with a different valid-length key than the one
  used for encryption
- THEN decryption fails.

### Requirement: v5 PASERK local key serialization

The system SHALL convert 32-byte v5 local keys to and from PASERK
`k5.local.` strings, and SHALL derive `k5.lid.` key identifiers from key
material without exposing the key.

#### Scenario: PASERK roundtrip

- WHEN a key is converted to `k5.local.` form and back
- THEN the recovered key is identical to the original.

#### Scenario: Key ID derivation

- WHEN a key identifier is requested for a local key
- THEN the system returns a string starting with `k5.lid.` that is stable
  for the same key and distinct for different keys.

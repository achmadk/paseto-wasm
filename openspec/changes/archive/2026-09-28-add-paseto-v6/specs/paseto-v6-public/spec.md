# Spec Delta

## Purpose

Provide PASETO v6.public post-quantum signatures for JavaScript environments via WebAssembly, implementing the Sign and Verify operations of the PASETO v6 draft specification using SLH-DSA-SHA256-128s with the same API shape as the existing v4-public implementation.

## ADDED Requirements

### Requirement: v6 public keypair generation

The system SHALL generate SLH-DSA-SHA256-128s keypairs where the secret key is 64 bytes (encoded as a 128-character hex string) and the public key is 32 bytes (encoded as a 64-character hex string).

#### Scenario: Generate keypair

- WHEN a caller requests a new v6 public keypair
- THEN the system returns a secret key decoding to 64 bytes and a public key decoding to 32 bytes, with successive calls returning distinct keypairs, and the public key corresponds to the secret key.

### Requirement: v6 public signing

The system SHALL sign string or JSON-object messages into tokens starting with `v6.public.`, using a caller-supplied 64-byte secret key and optional footer and implicit assertion strings. The signed pre-authentication encoding SHALL be `PAE(pk, h, m, f, i)` with the 32-byte public key first, and the signature SHALL be a 7856-byte SLH-DSA-SHA256-128s signature appended to the message.

#### Scenario: Sign and verify roundtrip

- WHEN a message is signed with a valid secret key and then verified with the corresponding public key, footer, and implicit assertion
- THEN verification returns the original message bytes.

#### Scenario: Reject invalid secret key

- WHEN signing is attempted with a key that is not valid hex or not 64 bytes
- THEN the operation fails with a key-length error and no token is produced.

#### Scenario: Footer binding

- WHEN a token is created with a footer and verified with a different or missing footer
- THEN verification fails.

#### Scenario: Implicit assertion binding

- WHEN a token is created with an implicit assertion and verified with a different or missing implicit assertion
- THEN verification fails.

### Requirement: v6 public signature verification

The system SHALL verify the 7856-byte trailing signature over `PAE(pk, h, m, f, i)` using the caller-supplied 32-byte public key, with algorithm selection bound to the key rather than the token header, and SHALL reject tokens with an invalid header, truncated payload, tampered message or signature, or wrong key.

#### Scenario: Reject tampered token

- WHEN any byte of the message or signature portion of a valid token is altered
- THEN verification fails and no message is returned.

#### Scenario: Reject wrong key

- WHEN a token is verified with a different valid public key than the one corresponding to the signing key
- THEN verification fails.

#### Scenario: Reject invalid header

- WHEN a token not beginning with `v6.public.` is submitted for verification
- THEN verification fails.

#### Scenario: Pass official test vectors

- WHEN the verify operation is run against the official v6.public test vectors with the given public key, footer, and implicit assertion
- THEN verification returns the expected message for vectors marked passing and fails for vectors marked failing.

### Requirement: v6 PASERK public key serialization

The system SHALL convert 64-byte v6 secret keys to and from PASERK `k6.secret.` strings and 32-byte v6 public keys to and from PASERK `k6.public.` strings, and SHALL derive `k6.sid.` identifiers from secret keys and `k6.pid.` identifiers from public keys without exposing key material.

#### Scenario: PASERK roundtrip

- WHEN a secret key is converted to `k6.secret.` form and back, and a public key is converted to `k6.public.` form and back
- THEN the recovered keys are identical to the originals.

#### Scenario: Key ID derivation

- WHEN key identifiers are requested for secret and public keys
- THEN the system returns strings starting with `k6.sid.` and `k6.pid.` respectively that are stable for the same key and distinct for different keys.

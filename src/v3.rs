//! PASETO V3 (Platform-Agnostic Security Tokens) Implementation
//!
//! This module provides WebAssembly bindings for PASETO version 3, which uses
//! P-384 (secp384r1) elliptic curve cryptography for both encryption and signatures.
//!
//! ## Overview
//!
//! PASETO is a security token format that provides a secure, simple alternative
//! to JWTs. Unlike JWTs, PASETO has no algorithm confusion vulnerabilities because
//! the version is embedded in the token structure.
//!
//! ### V3 Specifications
//! - **Local (Encryption)**: AES-256-CTR + HMAC-SHA384 (EtM mode)
//! - **Public (Signatures)**: ECDSA with P-384 (secp384r1)
//! - **Key Sizes**: 32 bytes (local key), 48 bytes (secret key), 49 bytes (public key)
//!
//! ## Token Formats
//!
//! ### Local Token (Encrypted)
//! ```text
//! v3.local.<base64-encoded-ciphertext-with-nonce>
//! ```
//!
//! ### Public Token (Signed)
//! ```text
//! v3.public.<base64-encoded-message-signature-pair>
//! ```
//!
//! ## Usage Example (JavaScript)
//!
//! ```javascript
//! // Generate a local key for encryption
//! const localKey = generate_v3_local_key();
//!
//! // Encrypt a message
//! const token = encrypt_v3_local(localKey, { data: "secret" });
//!
//! // Decrypt the message
//! const decrypted = decrypt_v3_local(localKey, token);
//!
//! // Or use public key cryptography for signed tokens
//! const keyPair = generate_v3_public_key_pair();
//! const signedToken = sign_v3_public(keyPair.secret, { data: "message" });
//! const verified = verify_v3_public(keyPair.public, signedToken);
//! ```
//!
//! ## Security Considerations
//!
//! 1. **Key Management**: Keys must be kept secret. Never expose keys in client-side code.
//! 2. **Key Size**: V3 local keys are 32 bytes (256-bit), secret keys are 48 bytes (384-bit).
//! 3. **Footer Usage**: The footer is transmitted in plaintext. Don't put secrets there.
//! 4. **Implicit Assertion**: Additional authenticated data that is verified but not included in the token.
//! 5. **Nonce Generation**: Nonces are randomly generated for each encryption operation.
//!
//! ## PASERK (Key Serialization)
//!
//! PASERK provides a standardized format for serializing keys:
//! - `k3.local.*` - Symmetric encryption key
//! - `k3.secret.*` - Signing secret key (48 bytes)
//! - `k3.public.*` - Verification public key (49 bytes compressed)
//! - `k3.lid.*` - Key ID for local keys (BLAKE2b-264 hash)
//! - `k3.pid.*` - Key ID for public keys
//! - `k3.sid.*` - Key ID for secret keys
//!
//! See: <https://paseto.io/paserk>

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rusty_paseto_v3::core::{
    Footer, ImplicitAssertion, Key, Local, Paseto, PasetoNonce, PasetoSymmetricKey, Payload, V3,
};
use std::convert::TryInto;
use wasm_bindgen::prelude::*;

// Constants
const V3_PUBLIC_HEADER: &str = "v3.public.";
const SIG_SIZE: usize = 96; // P-384 signature: 48 bytes * 2 (r + s)

/// Pre-Authentication Encoding (PAE) - builds authenticated data for V3 signatures.
///
/// PAE encodes multiple pieces of data into a single buffer with length prefixes,
/// ensuring the signature covers all components (header, public key, message, footer, implicit).
fn pae(pieces: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&(pieces.len() as u64).to_le_bytes());
    for piece in pieces {
        output.extend_from_slice(&(piece.len() as u64).to_le_bytes());
        output.extend_from_slice(piece);
    }
    output
}

/// Encrypt a message using PASETO V3 Local (symmetric encryption).
///
/// # Arguments
/// * `key_hex` - 32-byte symmetric key as hex string
/// * `message` - JSON object or string to encrypt
/// * `footer` - Optional footer (transmitted in plaintext)
/// * `implicit_assertion` - Optional implicit assertion (additional authenticated data)
///
/// # Returns
/// Base64-encoded token: `v3.local.<ciphertext>`
///
/// # Example
/// ```javascript
/// const key = generate_v3_local_key();
/// const token = encrypt_v3_local(key, { "data": "secret" });
/// // token: "v3.local.eyJkYXRhIjoic2VjcmV0In0..."
/// ```
#[wasm_bindgen]
pub fn encrypt_v3_local(
    key_hex: &str,
    message: JsValue,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    let key_array: [u8; 32] = key_vec
        .try_into()
        .map_err(|_| JsValue::from_str("Key must be 32 bytes"))?;
    let k = Key::<32>::from(key_array);
    let key = PasetoSymmetricKey::<V3, Local>::from(k);

    // Convert message to JSON string - accept either a string or an object
    let message_str = crate::common::serialize_message(message)?;

    let mut builder = Paseto::<V3, Local>::default();
    builder.set_payload(Payload::from(message_str.as_str()));
    if let Some(f) = footer.as_ref() {
        builder.set_footer(Footer::from(f.as_str()));
    }
    if let Some(i) = implicit_assertion.as_ref() {
        builder.set_implicit_assertion(ImplicitAssertion::from(i.as_str()));
    }

    let nonce_key =
        Key::<32>::try_new_random().map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce_key);
    let token = builder
        .try_encrypt(&key, &nonce)
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;
    Ok(token)
}

#[wasm_bindgen]
pub fn decrypt_v3_local(
    key_hex: &str,
    token: &str,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    let key_array: [u8; 32] = key_vec
        .try_into()
        .map_err(|_| JsValue::from_str("Key must be 32 bytes"))?;
    let k = Key::<32>::from(key_array);
    let key = PasetoSymmetricKey::<V3, Local>::from(k);

    let f_val = footer.as_deref().map(Footer::from);
    let i_val = implicit_assertion.as_deref().map(ImplicitAssertion::from);

    let message = Paseto::<V3, Local>::try_decrypt(token, &key, f_val, i_val)
        .map_err(|e| JsValue::from_str(&format!("Decryption failed: {}", e)))?;
    Ok(message)
}

#[wasm_bindgen]
pub fn sign_v3_public(
    secret_key_hex: &str,
    message: JsValue,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(secret_key_hex, 48)?;

    let signing_key =
        SigningKey::from_slice(&key_vec).map_err(|_| JsValue::from_str("Invalid secret key"))?;
    let verifying_key = VerifyingKey::from(&signing_key);
    let pk_bytes = verifying_key.to_encoded_point(true); // compressed
    let pk_slice = pk_bytes.as_bytes();

    let message_str = crate::common::serialize_message(message)?;

    let footer_str = footer.unwrap_or_default();
    let implicit = implicit_assertion.unwrap_or_default();

    let pre_auth = pae(&[
        V3_PUBLIC_HEADER.as_bytes(),
        pk_slice,
        message_str.as_bytes(),
        footer_str.as_bytes(),
        implicit.as_bytes(),
    ]);

    let signature: Signature = signing_key.sign(&pre_auth);
    let sig_bytes = signature.to_bytes();

    let mut payload = Vec::new();
    payload.extend_from_slice(message_str.as_bytes());
    payload.extend_from_slice(&sig_bytes);

    Ok(format!(
        "{}{}",
        V3_PUBLIC_HEADER,
        URL_SAFE_NO_PAD.encode(&payload)
    ))
}

#[wasm_bindgen]
pub fn verify_v3_public(
    public_key_hex: &str,
    token: &str,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    if !token.starts_with(V3_PUBLIC_HEADER) {
        return Err(JsValue::from_str("Invalid token header"));
    }
    let key_vec = crate::common::decode_hex_key(public_key_hex, 49)?;

    let verifying_key = VerifyingKey::from_sec1_bytes(&key_vec)
        .map_err(|_| JsValue::from_str("Invalid public key"))?;

    let footer_str = footer.unwrap_or_default();
    let implicit = implicit_assertion.unwrap_or_default();

    let encoded_payload = &token[V3_PUBLIC_HEADER.len()..];
    let payload = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .map_err(|e| JsValue::from_str(&format!("Base64 Error: {}", e)))?;

    if payload.len() < SIG_SIZE {
        return Err(JsValue::from_str("Token too short"));
    }

    let message_len = payload.len() - SIG_SIZE;
    let message_bytes = &payload[..message_len];
    let sig_bytes = &payload[message_len..];

    let pre_auth = pae(&[
        V3_PUBLIC_HEADER.as_bytes(),
        &key_vec,
        message_bytes,
        footer_str.as_bytes(),
        implicit.as_bytes(),
    ]);

    let signature = Signature::from_slice(sig_bytes)
        .map_err(|_| JsValue::from_str("Invalid signature format"))?;

    verifying_key
        .verify(&pre_auth, &signature)
        .map_err(|_| JsValue::from_str("Signature verification failed"))?;

    String::from_utf8(message_bytes.to_vec())
        .map_err(|_| JsValue::from_str("Message is not valid UTF-8"))
}

#[wasm_bindgen]
pub fn generate_v3_local_key() -> String {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("RNG failure");
    hex::encode(key)
}

#[wasm_bindgen]
pub struct V3KeyPair {
    secret: String,
    public: String,
}

#[wasm_bindgen]
impl V3KeyPair {
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> String {
        self.secret.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> String {
        self.public.clone()
    }
}

// Key generation logic
use p384::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::rand_core::OsRng,
};

#[wasm_bindgen]
pub fn generate_v3_public_key_pair() -> V3KeyPair {
    let signing_key = SigningKey::random(&mut OsRng);
    let secret_bytes = signing_key.to_bytes(); // 48 bytes
    let verifying_key = VerifyingKey::from(&signing_key);
    let public_bytes = verifying_key.to_encoded_point(true); // 49 bytes

    V3KeyPair {
        secret: hex::encode(secret_bytes),
        public: hex::encode(public_bytes.as_bytes()),
    }
}

// ============================================================================
// PASERK (Platform-Agnostic Serialized Keys) Functions V3
// ============================================================================

/// Convert a hex-encoded local key to PASERK format (k3.local.*)
#[wasm_bindgen]
pub fn key_to_paserk_v3_local(key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(key_hex, 32, "k3.local.")
}

/// Parse a PASERK local key (k3.local.*) back to hex format
#[wasm_bindgen]
pub fn paserk_v3_local_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k3.local.", 32)
}

/// Convert a hex-encoded secret key (48 bytes) to PASERK format (k3.secret.*)
#[wasm_bindgen]
pub fn key_to_paserk_v3_secret(secret_key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(secret_key_hex, 48, "k3.secret.")
}

/// Parse a PASERK secret key (k3.secret.*) back to hex format
#[wasm_bindgen]
pub fn paserk_v3_secret_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k3.secret.", 48)
}

/// Convert a hex-encoded public key (49 bytes) to PASERK format (k3.public.*)
#[wasm_bindgen]
pub fn key_to_paserk_v3_public(public_key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(public_key_hex, 49, "k3.public.")
}

/// Parse a PASERK public key (k3.public.*) back to hex format
#[wasm_bindgen]
pub fn paserk_v3_public_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k3.public.", 49)
}

/// Get the key ID (lid) for a local key (k3.lid.*)
/// The lid is a BLAKE2b-264 hash of "k3.local." + key bytes
#[wasm_bindgen]
pub fn get_v3_local_key_id(key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    Ok(crate::common::paserk_id_from_bytes(
        &key_vec,
        "k3.local.",
        "k3.lid.",
    ))
}

/// Get the key ID (pid) for a public key (k3.pid.*)
/// The pid is a BLAKE2b-264 hash of "k3.public." + key bytes
#[wasm_bindgen]
pub fn get_v3_public_key_id(public_key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(public_key_hex, 49)?;
    Ok(crate::common::paserk_id_from_bytes(
        &key_vec,
        "k3.public.",
        "k3.pid.",
    ))
}

/// Get the key ID (sid) for a secret key (k3.sid.*)
/// The sid is derived from the public key portion associated with the secret key
#[wasm_bindgen]
pub fn get_v3_secret_key_id(secret_key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(secret_key_hex, 48)?;

    let signing_key =
        SigningKey::from_slice(&key_vec).map_err(|_| JsValue::from_str("Invalid secret key"))?;
    let verifying_key = VerifyingKey::from(&signing_key);
    let pk_bytes = verifying_key.to_encoded_point(true); // compressed
    let pk_slice = pk_bytes.as_bytes(); // 49 bytes

    Ok(crate::common::paserk_id_from_bytes(
        pk_slice, "k3.sid.", "k3.sid.",
    )) // NOTE: using k3.sid. for both usage and id header
}

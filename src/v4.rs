//! # PASETO V4 WebAssembly Implementation
//!
//! PASETO Version 4 using Ed25519 for signatures and X25519 for key exchange.
//!
//! ## Cryptographic Specifications
//!
//! | Property | Local | Public |
//! |----------|-------|--------|
//! | Algorithm | X25519 + AES-256-GCM | Ed25519 (EdDSA) |
//! | Key Size | 32 bytes | 32 bytes (public), 64 bytes (secret) |
//! | Signature | 16 bytes (GCM tag) | 64 bytes |
//!
//! ## Token Formats
//!
//! - Local: `v4.local.<nonce || ciphertext || tag>`
//! - Public: `v4.public.<message || signature>`
//!
//! ## PASERK Formats
//!
//! - `k4.local.*` - 32-byte symmetric key
//! - `k4.secret.*` - 64-byte secret key
//! - `k4.public.*` - 32-byte public key
//! - `k4.lid.*`, `k4.pid.*`, `k4.sid.*` - Key IDs

use ed25519_dalek::{SigningKey, VerifyingKey};
use rusty_paseto::core::{
    Footer, ImplicitAssertion, Key, Local, Paseto, PasetoAsymmetricPrivateKey,
    PasetoAsymmetricPublicKey, PasetoNonce, PasetoSymmetricKey, Payload, Public, V4,
};
use std::convert::TryInto;
use wasm_bindgen::prelude::*;

/// Generates a random 32-byte symmetric key for V4 local encryption.
///
/// @example
/// ```javascript
/// const key = paseto.generate_v4_local_key();
/// // Returns: "2a04316d13e1e479e288861df6eaec3b088ee33d..."
/// ```
///
/// @returns {string} 64-character hex string (32 bytes)
#[wasm_bindgen]
pub fn generate_v4_local_key() -> String {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("RNG failure");
    hex::encode(key)
}

/// Encrypts a message using V4 Local (X25519 + AES-256-GCM).
///
/// @example
/// ```javascript
/// const key = paseto.generate_v4_local_key();
/// const token = paseto.encrypt_v4_local(key, { user: "123" }, null, null);
/// // Returns: "v4.local.eyJ1c2VyIjoiMTIzIn0..."
/// ```
///
/// @param {string} keyHex - 32-byte key as hex string
/// @param {string|object} message - Payload to encrypt
/// @param {string|null} footer - Optional footer
/// @param {string|null} implicitAssertion - Optional implicit assertion
/// @returns {string} Token: `v4.local.<ciphertext>`
#[wasm_bindgen]
pub fn encrypt_v4_local(
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
    let key = PasetoSymmetricKey::<V4, Local>::from(k);

    let message_str = crate::common::serialize_message(message)?;

    let mut builder = Paseto::<V4, Local>::default();
    builder.set_payload(Payload::from(message_str.as_str()));
    if let Some(f) = footer.as_ref() {
        builder.set_footer(Footer::from(f.as_str()));
    }
    if let Some(i) = implicit_assertion.as_ref() {
        builder.set_implicit_assertion(ImplicitAssertion::from(i.as_str()));
    }

    let nonce_key =
        Key::<32>::try_new_random().map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;
    let nonce = PasetoNonce::<V4, Local>::from(&nonce_key);
    let token = builder
        .try_encrypt(&key, &nonce)
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;
    Ok(token)
}

/// Decrypts a V4 Local token.
///
/// @example
/// ```javascript
/// const decrypted = paseto.decrypt_v4_local(key, token, null, null);
/// // Returns: '{"user":"123"}'
/// ```
///
/// @param {string} keyHex - 32-byte key as hex string
/// @param {string} token - Encrypted token
/// @param {string|null} footer - Footer used during encryption
/// @param {string|null} implicitAssertion - Implicit assertion used during encryption
/// @returns {string} Decrypted message
#[wasm_bindgen]
pub fn decrypt_v4_local(
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
    let key = PasetoSymmetricKey::<V4, Local>::from(k);

    let f_val = footer.as_deref().map(Footer::from);
    let i_val = implicit_assertion.as_deref().map(ImplicitAssertion::from);

    let message = Paseto::<V4, Local>::try_decrypt(token, &key, f_val, i_val)
        .map_err(|e| JsValue::from_str(&format!("Decryption failed: {}", e)))?;
    Ok(message)
}

/// V4 asymmetric key pair.
#[wasm_bindgen]
pub struct KeyPair {
    secret: String,
    public: String,
}

#[wasm_bindgen]
impl KeyPair {
    /// 64-byte secret key (128 hex chars).
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> String {
        self.secret.clone()
    }
    /// 32-byte public key (64 hex chars).
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> String {
        self.public.clone()
    }
}

/// Generates an Ed25519 key pair.
///
/// @example
/// ```javascript
/// const kp = paseto.generate_v4_public_key_pair();
/// console.log(kp.secret); // "48b5699fefd5be715cedab759c278e4cf..."
/// console.log(kp.public); // "d392fc09ebb0e479d01ce793c33839004..."
/// ```
///
/// @returns {KeyPair} { secret: 128-hex, public: 64-hex }
#[wasm_bindgen]
pub fn generate_v4_public_key_pair() -> KeyPair {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("RNG failure");
    let signing_key = SigningKey::from_bytes(&bytes);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let mut secret_64 = [0u8; 64];
    secret_64[..32].copy_from_slice(&signing_key.to_bytes());
    secret_64[32..].copy_from_slice(&verifying_key.to_bytes());

    KeyPair {
        secret: hex::encode(secret_64),
        public: hex::encode(verifying_key.to_bytes()),
    }
}

/// Signs a message using V4 Public (Ed25519).
///
/// @example
/// ```javascript
/// const kp = paseto.generate_v4_public_key_pair();
/// const token = paseto.sign_v4_public(kp.secret, { data: "test" }, null, null);
/// // Returns: "v4.public.eyJkYXRhIjoidGVzdCJ9..."
/// ```
///
/// @param {string} secretKeyHex - 64-byte secret key as hex
/// @param {string|object} message - Payload to sign
/// @param {string|null} footer - Optional footer
/// @param {string|null} implicitAssertion - Optional implicit assertion
/// @returns {string} Token: `v4.public.<message || signature>`
#[wasm_bindgen]
pub fn sign_v4_public(
    secret_key_hex: &str,
    message: JsValue,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(secret_key_hex, 64)?;
    let key = PasetoAsymmetricPrivateKey::<V4, Public>::from(key_vec.as_slice());

    let message_str = crate::common::serialize_message(message)?;

    let mut builder = Paseto::<V4, Public>::default();
    builder.set_payload(Payload::from(message_str.as_str()));
    if let Some(f) = footer.as_ref() {
        builder.set_footer(Footer::from(f.as_str()));
    }
    if let Some(i) = implicit_assertion.as_ref() {
        builder.set_implicit_assertion(ImplicitAssertion::from(i.as_str()));
    }

    let token = builder
        .try_sign(&key)
        .map_err(|e| JsValue::from_str(&format!("Signing failed: {}", e)))?;
    Ok(token)
}

/// Verifies a V4 Public token (Ed25519).
///
/// @example
/// ```javascript
/// const verified = paseto.verify_v4_public(kp.public, token, null, null);
/// // Returns: '{"data":"test"}'
/// ```
///
/// @param {string} publicKeyHex - 32-byte public key as hex
/// @param {string} token - Signed token
/// @param {string|null} footer - Footer used during signing
/// @param {string|null} implicitAssertion - Implicit assertion used during signing
/// @returns {string} Verified message
#[wasm_bindgen]
pub fn verify_v4_public(
    public_key_hex: &str,
    token: &str,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(public_key_hex, 32)?;
    let key_array: [u8; 32] = key_vec
        .try_into()
        .map_err(|_| JsValue::from_str("Key must be 32 bytes"))?;
    let k = Key::<32>::from(key_array);
    let key = PasetoAsymmetricPublicKey::<V4, Public>::from(&k);

    let f_val = footer.as_deref().map(Footer::from);
    let i_val = implicit_assertion.as_deref().map(ImplicitAssertion::from);

    let message = Paseto::<V4, Public>::try_verify(token, &key, f_val, i_val)
        .map_err(|e| JsValue::from_str(&format!("Verification failed: {}", e)))?;
    Ok(message)
}

/// Converts a V4 local key to PASERK format.
///
/// @example
/// ```javascript
/// paseto.key_to_paserk_local("2a04316d13e1e479...")
/// // Returns: "k4.local.VKBDGxE+4XmOKIhh3y6Ow4IP4jXQ..."
/// ```
///
/// @param {string} keyHex - 32-byte key as hex
/// @returns {string} PASERK: `k4.local.<base64>`
#[wasm_bindgen]
pub fn key_to_paserk_local(key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(key_hex, 32, "k4.local.")
}

/// Converts a PASERK local key to hex format.
///
/// @example
/// ```javascript
/// paseto.paserk_local_to_key("k4.local.VKBDGxE...")
/// // Returns: "2a04316d13e1e479e288861df6eaec3b..."
/// ```
///
/// @param {string} paserk - PASERK string starting with "k4.local."
/// @returns {string} 32-byte key as hex
#[wasm_bindgen]
pub fn paserk_local_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k4.local.", 32)
}

/// Converts a V4 secret key to PASERK format.
///
/// @example
/// ```javascript
/// paseto.key_to_paserk_secret("48b5699fefd5be715...")
/// // Returns: "k4.secret.SYhZn+/VvnFc7auFW..."
/// ```
///
/// @param {string} secretKeyHex - 64-byte key as hex
/// @returns {string} PASERK: `k4.secret.<base64>`
#[wasm_bindgen]
pub fn key_to_paserk_secret(secret_key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(secret_key_hex, 64, "k4.secret.")
}

/// Converts a PASERK secret key to hex format.
///
/// @example
/// ```javascript
/// paseto.paserk_secret_to_key("k4.secret.SYhZn+/Vvn...")
/// // Returns: "48b5699fefd5be715cedab759c278e4cf..."
/// ```
///
/// @param {string} paserk - PASERK string starting with "k4.secret."
/// @returns {string} 64-byte key as hex
#[wasm_bindgen]
pub fn paserk_secret_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k4.secret.", 64)
}

/// Converts a V4 public key to PASERK format.
///
/// @example
/// ```javascript
/// paseto.key_to_paserk_public("d392fc09ebb0e479...")
/// // Returns: "k4.public.TZL8Ceuw5HncB85HszM4MAQGtfI1..."
/// ```
///
/// @param {string} publicKeyHex - 32-byte key as hex
/// @returns {string} PASERK: `k4.public.<base64>`
#[wasm_bindgen]
pub fn key_to_paserk_public(public_key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(public_key_hex, 32, "k4.public.")
}

/// Converts a PASERK public key to hex format.
///
/// @example
/// ```javascript
/// paseto.paserk_public_to_key("k4.public.TZL8Ceuw5Hnc...")
/// // Returns: "d392fc09ebb0e479d01ce793c33839004..."
/// ```
///
/// @param {string} paserk - PASERK string starting with "k4.public."
/// @returns {string} 32-byte key as hex
#[wasm_bindgen]
pub fn paserk_public_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k4.public.", 32)
}

/// Generates a key ID for a V4 local key (k4.lid.*).
///
/// @example
/// ```javascript
/// paseto.get_local_key_id("2a04316d13e1e479...")
/// // Returns: "k4.lid.V2JnQ4LmhP0fYh3T..."
/// ```
///
/// @param {string} keyHex - 32-byte key as hex
/// @returns {string} PASERK ID: `k4.lid.<base64>`
#[wasm_bindgen]
pub fn get_local_key_id(key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    Ok(crate::common::paserk_id_from_bytes(
        &key_vec,
        "k4.local.",
        "k4.lid.",
    ))
}

/// Generates a key ID for a V4 public key (k4.pid.*).
///
/// @example
/// ```javascript
/// paseto.get_public_key_id("d392fc09ebb0e479...")
/// // Returns: "k4.pid.aG5hY2hxR3fN..."
/// ```
///
/// @param {string} publicKeyHex - 32-byte key as hex
/// @returns {string} PASERK ID: `k4.pid.<base64>`
#[wasm_bindgen]
pub fn get_public_key_id(public_key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(public_key_hex, 32)?;
    Ok(crate::common::paserk_id_from_bytes(
        &key_vec,
        "k4.public.",
        "k4.pid.",
    ))
}

/// Generates a key ID for a V4 secret key (k4.sid.*).
///
/// @example
/// ```javascript
/// paseto.get_secret_key_id("48b5699fefd5be715...")
/// // Returns: "k4.sid.mG5iZGln..."
/// ```
///
/// @param {string} secretKeyHex - 64-byte key as hex
/// @returns {string} PASERK ID: `k4.sid.<base64>`
#[wasm_bindgen]
pub fn get_secret_key_id(secret_key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(secret_key_hex, 64)?;

    let public_key = &key_vec[32..64];

    Ok(crate::common::paserk_id_from_bytes(
        public_key, "k4.sid.", "k4.sid.",
    ))
}

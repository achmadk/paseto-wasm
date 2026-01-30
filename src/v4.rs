use wasm_bindgen::prelude::*;
use rusty_paseto::core::{
    PasetoSymmetricKey, PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, Key,
    Local, Public, Paseto, Payload, Footer, ImplicitAssertion, PasetoNonce, V4
};
use std::convert::TryInto;
use ed25519_dalek::{SigningKey, VerifyingKey};


#[wasm_bindgen]
pub fn encrypt_v4_local(
    key_hex: &str,
    message: JsValue,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    let key_array: [u8; 32] = key_vec.try_into().map_err(|_| JsValue::from_str("Key must be 32 bytes"))?;
    let k = Key::<32>::from(key_array);
    let key = PasetoSymmetricKey::<V4, Local>::from(k);

    // Convert message to JSON string - accept either a string or an object
    let message_str = crate::common::serialize_message(message)?;

    let mut builder = Paseto::<V4, Local>::default();
    builder.set_payload(Payload::from(message_str.as_str()));
    if let Some(f) = footer.as_ref() {
        builder.set_footer(Footer::from(f.as_str()));
    }
    if let Some(i) = implicit_assertion.as_ref() {
        builder.set_implicit_assertion(ImplicitAssertion::from(i.as_str()));
    }

    let nonce_key = Key::<32>::try_new_random().map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;
    let nonce = PasetoNonce::<V4, Local>::from(&nonce_key);
    let token = builder.try_encrypt(&key, &nonce)
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;
    Ok(token)
}

#[wasm_bindgen]
pub fn decrypt_v4_local(
    key_hex: &str,
    token: &str,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    let key_array: [u8; 32] = key_vec.try_into().map_err(|_| JsValue::from_str("Key must be 32 bytes"))?;
    let k = Key::<32>::from(key_array);
    let key = PasetoSymmetricKey::<V4, Local>::from(k);

    let f_val = footer.as_deref().map(Footer::from);
    let i_val = implicit_assertion.as_deref().map(ImplicitAssertion::from);

    let message = Paseto::<V4, Local>::try_decrypt(token, &key, f_val, i_val)
        .map_err(|e| JsValue::from_str(&format!("Decryption failed: {}", e)))?;
    Ok(message)
}

#[wasm_bindgen]
pub fn sign_v4_public(
    secret_key_hex: &str,
    message: JsValue,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(secret_key_hex, 64)?;
    // PasetoAsymmetricPrivateKey::from(&[u8]) will handle the size check (expects 64 bytes for V4)
    let key = PasetoAsymmetricPrivateKey::<V4, Public>::from(key_vec.as_slice());

    // Convert message to JSON string - accept either a string or an object
    let message_str = crate::common::serialize_message(message)?;

    let mut builder = Paseto::<V4, Public>::default();
    builder.set_payload(Payload::from(message_str.as_str()));
    if let Some(f) = footer.as_ref() {
        builder.set_footer(Footer::from(f.as_str()));
    }
    if let Some(i) = implicit_assertion.as_ref() {
        builder.set_implicit_assertion(ImplicitAssertion::from(i.as_str()));
    }

    let token = builder.try_sign(&key)
        .map_err(|e| JsValue::from_str(&format!("Signing failed: {}", e)))?;
    Ok(token)
}

#[wasm_bindgen]
pub fn verify_v4_public(
    public_key_hex: &str,
    token: &str,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(public_key_hex, 32)?;
    let key_array: [u8; 32] = key_vec.try_into().map_err(|_| JsValue::from_str("Key must be 32 bytes"))?;
    let k = Key::<32>::from(key_array);
    let key = PasetoAsymmetricPublicKey::<V4, Public>::from(&k);

    let f_val = footer.as_deref().map(Footer::from);
    let i_val = implicit_assertion.as_deref().map(ImplicitAssertion::from);

    let message = Paseto::<V4, Public>::try_verify(token, &key, f_val, i_val)
        .map_err(|e| JsValue::from_str(&format!("Verification failed: {}", e)))?;
    Ok(message)
}

#[wasm_bindgen]
pub fn generate_v4_local_key() -> String {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("RNG failure");
    hex::encode(key)
}

#[wasm_bindgen]
pub struct KeyPair {
    secret: String,
    public: String,
}

#[wasm_bindgen]
impl KeyPair {
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> String {
        self.secret.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn public(&self) -> String {
        self.public.clone()
    }
}

#[wasm_bindgen]
pub fn generate_v4_public_key_pair() -> KeyPair {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("RNG failure");
    let signing_key = SigningKey::from_bytes(&bytes);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    
    // For PASETO V4 Public, rusty_paseto expects 64 bytes for the private key (seed + public key)
    let mut secret_64 = [0u8; 64];
    secret_64[..32].copy_from_slice(&signing_key.to_bytes());
    secret_64[32..].copy_from_slice(&verifying_key.to_bytes());

    KeyPair {
        secret: hex::encode(secret_64),
        public: hex::encode(verifying_key.to_bytes()),
    }
}

// ============================================================================
// PASERK (Platform-Agnostic Serialized Keys) Functions
// ============================================================================

/// Convert a hex-encoded local key to PASERK format (k4.local.*)
#[wasm_bindgen]
pub fn key_to_paserk_local(key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(key_hex, 32, "k4.local.")
}

/// Parse a PASERK local key (k4.local.*) back to hex format
#[wasm_bindgen]
pub fn paserk_local_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k4.local.", 32)
}

/// Convert a hex-encoded secret key (64 bytes) to PASERK format (k4.secret.*)
#[wasm_bindgen]
pub fn key_to_paserk_secret(secret_key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(secret_key_hex, 64, "k4.secret.")
}

/// Parse a PASERK secret key (k4.secret.*) back to hex format
#[wasm_bindgen]
pub fn paserk_secret_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k4.secret.", 64)
}

/// Convert a hex-encoded public key (32 bytes) to PASERK format (k4.public.*)
#[wasm_bindgen]
pub fn key_to_paserk_public(public_key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(public_key_hex, 32, "k4.public.")
}

/// Parse a PASERK public key (k4.public.*) back to hex format
#[wasm_bindgen]
pub fn paserk_public_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k4.public.", 32)
}

/// Get the key ID (lid) for a local key (k4.lid.*)
/// The lid is a BLAKE2b-264 hash of "k4.local." + key bytes
#[wasm_bindgen]
pub fn get_local_key_id(key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    Ok(crate::common::paserk_id_from_bytes(&key_vec, "k4.local.", "k4.lid."))
}

/// Get the key ID (pid) for a public key (k4.pid.*)
/// The pid is a BLAKE2b-264 hash of "k4.public." + key bytes
#[wasm_bindgen]
pub fn get_public_key_id(public_key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(public_key_hex, 32)?;
    Ok(crate::common::paserk_id_from_bytes(&key_vec, "k4.public.", "k4.pid."))
}

/// Get the key ID (sid) for a secret key (k4.sid.*)
/// The sid is derived from the public key portion of the secret key
#[wasm_bindgen]
pub fn get_secret_key_id(secret_key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(secret_key_hex, 64)?;
    
    // The public key is the last 32 bytes of the 64-byte secret key
    let public_key = &key_vec[32..64];

    Ok(crate::common::paserk_id_from_bytes(public_key, "k4.sid.", "k4.sid.")) // NOTE: using k4.sid. for both usage and id header
}

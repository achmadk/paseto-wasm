//! PASETO V5 WebAssembly Implementation
//! Uses ChaCha20-Poly1305 for local encryption
//! Note: AES-CTR + HMAC-SHA-384 blocked by Rust crate version conflicts

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use std::convert::TryInto;
use wasm_bindgen::prelude::*;

const V5_LOCAL_HEADER: &str = "v5.local.";
const V5_LOCAL_KEY_SIZE: usize = 32;

#[wasm_bindgen]
pub fn generate_v5_local_key() -> String {
    let mut key = [0u8; V5_LOCAL_KEY_SIZE];
    getrandom::fill(&mut key).expect("RNG failure");
    hex::encode(key)
}

#[wasm_bindgen]
pub fn encrypt_v5_local(
    key_hex: &str,
    message: JsValue,
    footer: Option<String>,
    _implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, V5_LOCAL_KEY_SIZE)?;
    let key_arr: [u8; 32] = key_vec
        .clone()
        .try_into()
        .map_err(|_| JsValue::from_str("Key error"))?;

    let message_str = crate::common::serialize_message(message)?;
    let message_bytes = message_str.as_bytes();

    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;
    let nonce = Nonce::from(nonce_bytes.clone());

    let cipher = ChaCha20Poly1305::new(&key_arr.into());
    let mut ciphertext = cipher
        .encrypt(&nonce, message_bytes.as_ref())
        .map_err(|_| JsValue::from_str("Encryption failed"))?;

    let mut payload = nonce_bytes.to_vec();
    payload.append(&mut ciphertext);

    let header = if footer.is_some() {
        format!(
            "{}.{}.",
            V5_LOCAL_HEADER.trim_end_matches('.'),
            footer.as_ref().unwrap()
        )
    } else {
        V5_LOCAL_HEADER.to_string()
    };

    Ok(format!("{}{}", header, URL_SAFE_NO_PAD.encode(&payload)))
}

#[wasm_bindgen]
pub fn decrypt_v5_local(
    key_hex: &str,
    token: &str,
    _footer: Option<String>,
    _implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, V5_LOCAL_KEY_SIZE)?;
    let key_arr: [u8; 32] = key_vec
        .try_into()
        .map_err(|_| JsValue::from_str("Key error"))?;

    let payload_b64 = if let Some(pos) = token.rfind('.') {
        &token[pos + 1..]
    } else {
        return Err(JsValue::from_str("Invalid token format"));
    };

    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| JsValue::from_str("Invalid base64"))?;

    let nonce_arr: [u8; 12] = payload[..12]
        .try_into()
        .map_err(|_| JsValue::from_str("Nonce error"))?;
    let nonce = Nonce::from(nonce_arr);
    let ciphertext_and_tag = &payload[12..];

    let cipher = ChaCha20Poly1305::new(&key_arr.into());
    let plaintext = cipher
        .decrypt(&nonce, ciphertext_and_tag.as_ref())
        .map_err(|_| JsValue::from_str("Decryption failed"))?;

    String::from_utf8(plaintext).map_err(|_| JsValue::from_str("Invalid UTF-8"))
}

#[wasm_bindgen]
pub fn key_to_paserk_v5_local(key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(key_hex, V5_LOCAL_KEY_SIZE, "k5.local.")
}

#[wasm_bindgen]
pub fn paserk_v5_local_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k5.local.", V5_LOCAL_KEY_SIZE)
}

#[wasm_bindgen]
pub fn get_v5_local_key_id(key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, V5_LOCAL_KEY_SIZE)?;
    Ok(crate::common::paserk_id_from_bytes(
        &key_vec,
        "k5.local.",
        "k5.lid.",
    ))
}

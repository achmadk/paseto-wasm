//! # PASETO V5 WebAssembly Implementation (local only)
//!
//! PASETO Version 5 (draft) symmetric encryption using AES-256-CTR +
//! HMAC-SHA384, following the same construction as PASETO v3 local with
//! version-specific headers and PASERK prefixes.
//!
//! ## Token Format
//!
//! - Local: `v5.local.<nonce || ciphertext || mac>`
//!
//! ## PASERK Formats
//!
//! - `k5.local.*` - 32-byte symmetric key
//! - `k5.lid.*` - Key ID

use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ctr::Ctr128BE;
use digest::KeyInit;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha384;
use wasm_bindgen::prelude::*;

const V5_LOCAL_HEADER: &str = "v5.local.";
const V5_AUTH_INFO: &[u8] = b"paseto-auth-key-for-aead";
const V5_ENC_INFO: &[u8] = b"paseto-encryption-key";

type Aes256Ctr = Ctr128BE<Aes256>;
type HmacSha384 = Hmac<Sha384>;

fn hkdf_sha384(ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, JsValue> {
    let hk = Hkdf::<Sha384>::new(Some(&[]), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .map_err(|_| JsValue::from_str("HKDF expand failed"))?;
    Ok(okm)
}

fn v5_derive(key: &[u8], nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), JsValue> {
    let mut ak_info = Vec::with_capacity(56);
    ak_info.extend_from_slice(V5_AUTH_INFO);
    ak_info.extend_from_slice(nonce);
    let mut ek_info = Vec::with_capacity(53);
    ek_info.extend_from_slice(V5_ENC_INFO);
    ek_info.extend_from_slice(nonce);

    let ak = hkdf_sha384(key, &ak_info, 48)?;
    let ek_full = hkdf_sha384(key, &ek_info, 48)?;
    let ek = ek_full[..32].to_vec();
    let cn = ek_full[32..].to_vec();
    Ok((ak, ek, cn))
}

fn aes_ctr_crypt(enc_key: &[u8], counter_nonce: &[u8], data: &[u8]) -> Vec<u8> {
    let mut cipher = Aes256Ctr::new_from_slices(enc_key, counter_nonce).expect("CTR init");
    let mut out = data.to_vec();
    cipher.apply_keystream(&mut out);
    out
}

fn v5_tag(auth_key: &[u8], pae: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut mac =
        HmacSha384::new_from_slice(auth_key).map_err(|_| JsValue::from_str("Invalid auth key"))?;
    mac.update(pae);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Generates a random 32-byte symmetric key for V5 local encryption.
///
/// @example
/// ```javascript
/// const key = paseto.generate_v5_local_key();
/// // Returns: "2a04316d13e1e479e288861df6eaec3b088ee33d..."
/// ```
///
/// @returns {string} 64-character hex string (32 bytes)
#[wasm_bindgen]
pub fn generate_v5_local_key() -> String {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("RNG failure");
    hex::encode(key)
}

/// Encrypts a message using V5 Local (AES-256-CTR + HMAC-SHA384).
///
/// @example
/// ```javascript
/// const key = paseto.generate_v5_local_key();
/// const token = paseto.encrypt_v5_local(key, { user: "123" }, null, null);
/// // Returns: "v5.local.eyJ1c2VyIjoiMTIzIn0..."
/// ```
///
/// @param {string} keyHex - 32-byte key as hex string
/// @param {string|object} message - Payload to encrypt
/// @param {string|null} footer - Optional footer
/// @param {string|null} implicitAssertion - Optional implicit assertion
/// @returns {string} Token: `v5.local.<ciphertext>`
#[wasm_bindgen]
pub fn encrypt_v5_local(
    key_hex: &str,
    message: JsValue,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    let message_str = crate::common::serialize_message(message)?;

    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;

    let (ak, ek, cn) = v5_derive(&key_vec, &nonce)?;
    let ciphertext = aes_ctr_crypt(&ek, &cn, message_str.as_bytes());

    let footer_str = footer.clone().unwrap_or_default();
    let implicit_str = implicit_assertion.clone().unwrap_or_default();
    let pae = crate::common::pae_encode(&[
        V5_LOCAL_HEADER.as_bytes(),
        &nonce,
        &ciphertext,
        footer_str.as_bytes(),
        implicit_str.as_bytes(),
    ]);
    let tag = v5_tag(&ak, &pae)?;

    let mut raw = Vec::with_capacity(80 + ciphertext.len());
    raw.extend_from_slice(&nonce);
    raw.extend_from_slice(&ciphertext);
    raw.extend_from_slice(&tag);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&raw);
    Ok(crate::common::format_token(
        V5_LOCAL_HEADER,
        &payload_b64,
        &footer,
    ))
}

/// Decrypts a V5 Local token.
///
/// @example
/// ```javascript
/// const decrypted = paseto.decrypt_v5_local(key, token, null, null);
/// // Returns: '{"user":"123"}'
/// ```
///
/// @param {string} keyHex - 32-byte key as hex string
/// @param {string} token - Encrypted token
/// @param {string|null} footer - Footer used during encryption
/// @param {string|null} implicitAssertion - Implicit assertion used during encryption
/// @returns {string} Decrypted message
#[wasm_bindgen]
pub fn decrypt_v5_local(
    key_hex: &str,
    token: &str,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    let raw = crate::common::parse_token(token, V5_LOCAL_HEADER, &footer)?;
    if raw.len() < 80 {
        return Err(JsValue::from_str("Token too short"));
    }
    let nonce = &raw[..32];
    let tag_start = raw.len() - 48;
    let ciphertext = &raw[32..tag_start];
    let tag = &raw[tag_start..];

    let (ak, ek, cn) = v5_derive(&key_vec, nonce)?;

    let footer_str = footer.clone().unwrap_or_default();
    let implicit_str = implicit_assertion.clone().unwrap_or_default();
    let pae = crate::common::pae_encode(&[
        V5_LOCAL_HEADER.as_bytes(),
        nonce,
        ciphertext,
        footer_str.as_bytes(),
        implicit_str.as_bytes(),
    ]);
    let expected_tag = v5_tag(&ak, &pae)?;
    if !crate::common::constant_time_eq(tag, &expected_tag) {
        return Err(JsValue::from_str("Decryption failed: invalid tag"));
    }

    let plaintext = aes_ctr_crypt(&ek, &cn, ciphertext);
    String::from_utf8(plaintext).map_err(|_| JsValue::from_str("Message is not valid UTF-8"))
}

/// Converts a V5 local key to PASERK format.
///
/// @example
/// ```javascript
/// paseto.key_to_paserk_v5_local("2a04316d13e1e479...")
/// // Returns: "k5.local.VKBDGxE+4XmOKIhh3y6Ow4IP4jXQ..."
/// ```
///
/// @param {string} keyHex - 32-byte key as hex
/// @returns {string} PASERK: `k5.local.<base64>`
#[wasm_bindgen]
pub fn key_to_paserk_v5_local(key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(key_hex, 32, "k5.local.")
}

/// Converts a PASERK local key to hex format.
///
/// @example
/// ```javascript
/// paseto.paserk_v5_local_to_key("k5.local.VKBDGxE...")
/// // Returns: "2a04316d13e1e479e288861df6eaec3b..."
/// ```
///
/// @param {string} paserk - PASERK string starting with "k5.local."
/// @returns {string} 32-byte key as hex
#[wasm_bindgen]
pub fn paserk_v5_local_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k5.local.", 32)
}

/// Generates a key ID for a V5 local key (k5.lid.*).
///
/// @example
/// ```javascript
/// paseto.get_v5_local_key_id("2a04316d13e1e479...")
/// // Returns: "k5.lid.V2JnQ4LmhP0fYh3T..."
/// ```
///
/// @param {string} keyHex - 32-byte key as hex
/// @returns {string} PASERK ID: `k5.lid.<base64>`
#[wasm_bindgen]
pub fn get_v5_local_key_id(key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    Ok(crate::common::paserk_id_from_bytes(
        &key_vec,
        "k5.local.",
        "k5.lid.",
    ))
}

use wasm_bindgen::prelude::*;
use crate::PasetoClaims;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use blake2::{Blake2b, Digest};
use blake2::digest::consts::U33;

/// Decodes a hex string into a byte vector and validates its length.
pub fn decode_hex_key(key_hex: &str, expected_len: usize) -> Result<Vec<u8>, JsValue> {
    let key_vec = hex::decode(key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid hex key: {}", e)))?;
    
    if key_vec.len() != expected_len {
        return Err(JsValue::from_str(&format!("Key must be {} bytes", expected_len)));
    }
    
    Ok(key_vec)
}

/// Serializes a JS message (string or object) into a JSON string.
pub fn serialize_message(message: JsValue) -> Result<String, JsValue> {
    if message.is_string() {
        Ok(message.as_string().unwrap())
    } else if message.is_object() {
        let claims: PasetoClaims = serde_wasm_bindgen::from_value(message)
            .map_err(|e| JsValue::from_str(&format!("Invalid claims object: {}", e)))?;
        serde_json::to_string(&claims)
            .map_err(|e| JsValue::from_str(&format!("JSON serialization failed: {}", e)))
    } else {
        Err(JsValue::from_str("Message must be a string or an object"))
    }
}

/// Generic helper to encode a key into PASERK format
pub fn paserk_encode(key_hex: &str, expected_len: usize, prefix: &str) -> Result<String, JsValue> {
    let key_vec = decode_hex_key(key_hex, expected_len)?;
    let encoded = URL_SAFE_NO_PAD.encode(&key_vec);
    Ok(format!("{}{}", prefix, encoded))
}

/// Generic helper to decode a PASERK string back to hex key
pub fn paserk_decode(paserk: &str, prefix: &str, expected_len: usize) -> Result<String, JsValue> {
    if !paserk.starts_with(prefix) {
        return Err(JsValue::from_str(&format!("Invalid PASERK format: must start with '{}'", prefix)));
    }
    let encoded = &paserk[prefix.len()..];
    let key_bytes = URL_SAFE_NO_PAD.decode(encoded)
        .map_err(|e| JsValue::from_str(&format!("Invalid base64: {}", e)))?;
    if key_bytes.len() != expected_len {
        return Err(JsValue::from_str(&format!("Invalid key length: expected {} bytes", expected_len)));
    }
    Ok(hex::encode(key_bytes))
}

/// Generic helper to calculate a PASERK ID from raw key bytes
pub fn paserk_id_from_bytes(key_bytes: &[u8], usage_header: &str, id_header: &str) -> String {
    let mut hasher = Blake2b::<U33>::new();
    hasher.update(usage_header.as_bytes());
    hasher.update(key_bytes);
    let hash = hasher.finalize();
    
    let encoded = URL_SAFE_NO_PAD.encode(&hash);
    format!("{}{}", id_header, encoded)
}

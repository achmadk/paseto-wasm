//! # Common Utilities
//!
//! This module provides shared utility functions used by both PASETO v3 and v4 implementations.
//! These functions handle key decoding, message serialization, and PASERK format conversion.

use crate::PasetoClaims;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use blake2::digest::consts::U33;
use blake2::{Blake2b, Digest};
use wasm_bindgen::prelude::*;

/// Decodes a hex-encoded string and validates the key length.
///
/// This is an internal helper function used by the public API functions.
/// It converts a hex string to bytes and verifies it matches the expected key size.
///
/// # Arguments
///
/// * `key_hex` - A hex-encoded key string
/// * `expected_len` - The expected key length in bytes
///
/// # Returns
///
/// A `Vec<u8>` containing the decoded key bytes
///
/// # Errors
///
/// Returns an error if:
/// - The hex string is invalid
/// - The decoded length doesn't match `expected_len`
pub fn decode_hex_key(key_hex: &str, expected_len: usize) -> Result<Vec<u8>, JsValue> {
    let key_vec =
        hex::decode(key_hex).map_err(|e| JsValue::from_str(&format!("Invalid hex key: {}", e)))?;

    if key_vec.len() != expected_len {
        return Err(JsValue::from_str(&format!(
            "Key must be {} bytes",
            expected_len
        )));
    }

    Ok(key_vec)
}

/// Serializes a JavaScript message (string or object) into a JSON string.
///
/// This function accepts either a string or an object as the message and converts
/// it to a JSON string for encryption/signing.
///
/// # Arguments
///
/// * `message` - Either a JavaScript string or an object
///
/// # Returns
///
/// A JSON-encoded string
///
/// # Errors
///
/// Returns an error if:
/// - The message is neither a string nor an object
/// - The object cannot be serialized to JSON
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

/// Encodes a key into PASERK (Platform-Agnostic Serialized Keys) format.
///
/// This is an internal helper function that converts a hex-encoded key to the
/// PASERK format using URL-safe base64 encoding.
///
/// # Arguments
///
/// * `key_hex` - A hex-encoded key string
/// * `expected_len` - The expected key length in bytes
/// * `prefix` - The PASERK prefix (e.g., "k4.local.", "k4.public.")
///
/// # Returns
///
/// A PASERK-encoded string with the specified prefix
///
/// # Errors
///
/// Returns an error if the key is invalid
pub fn paserk_encode(key_hex: &str, expected_len: usize, prefix: &str) -> Result<String, JsValue> {
    let key_vec = decode_hex_key(key_hex, expected_len)?;
    let encoded = URL_SAFE_NO_PAD.encode(&key_vec);
    Ok(format!("{}{}", prefix, encoded))
}

/// Decodes a PASERK string back to a hex-encoded key.
///
/// This is an internal helper function that converts a PASERK string
/// back to the original hex-encoded format.
///
/// # Arguments
///
/// * `paserk` - A PASERK-encoded string
/// * `prefix` - The expected PASERK prefix (e.g., "k4.local.")
/// * `expected_len` - The expected key length in bytes
///
/// # Returns
///
/// The original key as a hex-encoded string
///
/// # Errors
///
/// Returns an error if:
/// - The prefix doesn't match
/// - The decoded key length is incorrect
pub fn paserk_decode(paserk: &str, prefix: &str, expected_len: usize) -> Result<String, JsValue> {
    if !paserk.starts_with(prefix) {
        return Err(JsValue::from_str(&format!(
            "Invalid PASERK format: must start with '{}'",
            prefix
        )));
    }
    let encoded = &paserk[prefix.len()..];
    let key_bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| JsValue::from_str(&format!("Invalid base64: {}", e)))?;
    if key_bytes.len() != expected_len {
        return Err(JsValue::from_str(&format!(
            "Invalid key length: expected {} bytes",
            expected_len
        )));
    }
    Ok(hex::encode(key_bytes))
}

/// Generates a PASERK key ID from raw key bytes.
///
/// This function computes a key ID (kid) by hashing the key usage prefix
/// and the key bytes using BLAKE2b-264. The resulting ID can be used
/// to identify keys without exposing the key material itself.
///
/// # Arguments
///
/// * `key_bytes` - The raw key bytes
/// * `usage_header` - The key usage string (e.g., "k4.local.")
/// * `id_header` - The ID prefix (e.g., "k4.lid.")
///
/// # Returns
///
/// A PASERK key ID string
pub fn paserk_id_from_bytes(key_bytes: &[u8], usage_header: &str, id_header: &str) -> String {
    let mut hasher = Blake2b::<U33>::new();
    hasher.update(usage_header.as_bytes());
    hasher.update(key_bytes);
    let hash = hasher.finalize();

    let encoded = URL_SAFE_NO_PAD.encode(&hash);
    format!("{}{}", id_header, encoded)
}

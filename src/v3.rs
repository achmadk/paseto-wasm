//! # PASETO V3 WebAssembly Implementation
//!
//! PASETO Version 3 using P-384 (secp384r1) elliptic curve cryptography.
//!
//! ## Cryptographic Specifications
//!
//! | Property | Local | Public |
//! |----------|-------|--------|
//! | Algorithm | AES-256-CTR + HMAC-SHA384 | ECDSA P-384 |
//! | Key Size | 32 bytes | 48 bytes (secret), 49 bytes (public) |
//! | Signature | 48 bytes (MAC) | 96 bytes |
//!
//! ## Token Formats
//!
//! - Local: `v3.local.<nonce || ciphertext || mac>`
//! - Public: `v3.public.<message || signature>`
//!
//! ## PAE Order (Public Signatures)
//!
//! 1. Public key (49 bytes)
//! 2. Header ("v3.public.")
//! 3. Message
//! 4. Footer
//! 5. Implicit assertion
//!
//! ## PASERK Formats
//!
//! - `k3.local.*` - 32-byte symmetric key
//! - `k3.secret.*` - 48-byte secret key
//! - `k3.public.*` - 49-byte public key
//! - `k3.lid.*`, `k3.pid.*`, `k3.sid.*` - Key IDs

use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ctr::Ctr128BE;
use digest::KeyInit;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p384::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::Sha384;
use wasm_bindgen::prelude::*;

const V3_LOCAL_HEADER: &str = "v3.local.";
const V3_PUBLIC_HEADER: &str = "v3.public.";
const V3_AUTH_INFO: &[u8] = b"paseto-auth-key-for-aead";
const V3_ENC_INFO: &[u8] = b"paseto-encryption-key";
const SIG_SIZE: usize = 96;

type Aes256Ctr = Ctr128BE<Aes256>;
type HmacSha384 = Hmac<Sha384>;

fn hkdf_sha384(ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, JsValue> {
    let hk = Hkdf::<Sha384>::new(Some(&[]), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .map_err(|_| JsValue::from_str("HKDF expand failed"))?;
    Ok(okm)
}

fn v3_derive(
    key: &[u8],
    nonce: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), JsValue> {
    let mut ak_info = Vec::with_capacity(56);
    ak_info.extend_from_slice(V3_AUTH_INFO);
    ak_info.extend_from_slice(nonce);
    let mut ek_info = Vec::with_capacity(53);
    ek_info.extend_from_slice(V3_ENC_INFO);
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

fn v3_tag(auth_key: &[u8], pae: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut mac =
        HmacSha384::new_from_slice(auth_key).map_err(|_| JsValue::from_str("Invalid auth key"))?;
    mac.update(pae);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Generates a random 32-byte symmetric key for V3 local encryption.
///
/// @example
/// ```javascript
/// const key = paseto.generate_v3_local_key();
/// // Returns: "2a04316d13e1e479e288861df6eaec3b088ee33d..."
/// ```
///
/// @returns {string} 64-character hex string (32 bytes)
#[wasm_bindgen]
pub fn generate_v3_local_key() -> String {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("RNG failure");
    hex::encode(key)
}

/// Encrypts a message using V3 Local (AES-256-CTR + HMAC-SHA384).
///
/// @example
/// ```javascript
/// const key = paseto.generate_v3_local_key();
/// const token = paseto.encrypt_v3_local(key, { user: "123" }, null, null);
/// // Returns: "v3.local.eyJ1c2VyIjoiMTIzIn0..."
/// ```
///
/// @param {string} keyHex - 32-byte key as hex string
/// @param {string|object} message - Payload to encrypt
/// @param {string|null} footer - Optional footer
/// @param {string|null} implicitAssertion - Optional implicit assertion
/// @returns {string} Token: `v3.local.<ciphertext>`
#[wasm_bindgen]
pub fn encrypt_v3_local(
    key_hex: &str,
    message: JsValue,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    let message_str = crate::common::serialize_message(message)?;

    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;

    let (ak, ek, cn) = v3_derive(&key_vec, &nonce)?;
    let ciphertext = aes_ctr_crypt(&ek, &cn, message_str.as_bytes());

    let footer_str = footer.clone().unwrap_or_default();
    let implicit_str = implicit_assertion.clone().unwrap_or_default();
    let pae = crate::common::pae_encode(&[
        V3_LOCAL_HEADER.as_bytes(),
        &nonce,
        &ciphertext,
        footer_str.as_bytes(),
        implicit_str.as_bytes(),
    ]);
    let tag = v3_tag(&ak, &pae)?;

    let mut raw = Vec::with_capacity(80 + ciphertext.len());
    raw.extend_from_slice(&nonce);
    raw.extend_from_slice(&ciphertext);
    raw.extend_from_slice(&tag);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&raw);
    Ok(crate::common::format_token(
        V3_LOCAL_HEADER,
        &payload_b64,
        &footer,
    ))
}

/// Decrypts a V3 Local token.
///
/// @example
/// ```javascript
/// const decrypted = paseto.decrypt_v3_local(key, token, null, null);
/// // Returns: '{"user":"123"}'
/// ```
///
/// @param {string} keyHex - 32-byte key as hex string
/// @param {string} token - Encrypted token
/// @param {string|null} footer - Footer used during encryption
/// @param {string|null} implicitAssertion - Implicit assertion used during encryption
/// @returns {string} Decrypted message
#[wasm_bindgen]
pub fn decrypt_v3_local(
    key_hex: &str,
    token: &str,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    let raw = crate::common::parse_token(token, V3_LOCAL_HEADER, &footer)?;
    if raw.len() < 80 {
        return Err(JsValue::from_str("Token too short"));
    }
    let nonce = &raw[..32];
    let tag_start = raw.len() - 48;
    let ciphertext = &raw[32..tag_start];
    let tag = &raw[tag_start..];

    let (ak, ek, cn) = v3_derive(&key_vec, nonce)?;

    let footer_str = footer.clone().unwrap_or_default();
    let implicit_str = implicit_assertion.clone().unwrap_or_default();
    let pae = crate::common::pae_encode(&[
        V3_LOCAL_HEADER.as_bytes(),
        nonce,
        ciphertext,
        footer_str.as_bytes(),
        implicit_str.as_bytes(),
    ]);
    let expected_tag = v3_tag(&ak, &pae)?;
    if !crate::common::constant_time_eq(tag, &expected_tag) {
        return Err(JsValue::from_str("Decryption failed: invalid tag"));
    }

    let plaintext = aes_ctr_crypt(&ek, &cn, ciphertext);
    String::from_utf8(plaintext).map_err(|_| JsValue::from_str("Message is not valid UTF-8"))
}

/// V3 asymmetric key pair.
#[wasm_bindgen]
pub struct V3KeyPair {
    secret: String,
    public: String,
}

#[wasm_bindgen]
impl V3KeyPair {
    /// 48-byte secret key (96 hex chars).
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> String {
        self.secret.clone()
    }
    /// 49-byte public key in compressed format (98 hex chars).
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> String {
        self.public.clone()
    }
}

/// Generates an ECDSA P-384 key pair.
///
/// @example
/// ```javascript
/// const kp = paseto.generate_v3_public_key_pair();
/// console.log(kp.secret); // "8d849f0466aefa3560e76f444dd04eb4..."
/// console.log(kp.public); // "0279ebc6ef14966554668c483e3c52d2..."
/// ```
///
/// @returns {V3KeyPair} { secret: 96-hex, public: 98-hex }
#[wasm_bindgen]
pub fn generate_v3_public_key_pair() -> V3KeyPair {
    let mut secret = [0u8; 48];
    getrandom::fill(&mut secret).expect("RNG failure");
    let signing_key =
        SigningKey::from_slice(&secret).expect("RNG produced invalid key");
    let secret_bytes = signing_key.to_bytes();
    let verifying_key = VerifyingKey::from(&signing_key);
    let public_bytes = verifying_key.to_sec1_point(true);

    V3KeyPair {
        secret: hex::encode(secret_bytes),
        public: hex::encode(public_bytes.as_bytes()),
    }
}

/// Signs a message using V3 Public (ECDSA P-384).
///
/// @example
/// ```javascript
/// const kp = paseto.generate_v3_public_key_pair();
/// const token = paseto.sign_v3_public(kp.secret, { data: "test" }, null, null);
/// // Returns: "v3.public.eyJkYXRhIjoidGVzdCJ9..."
/// ```
///
/// @param {string} secretKeyHex - 48-byte secret key as hex
/// @param {string|object} message - Payload to sign
/// @param {string|null} footer - Optional footer
/// @param {string|null} implicitAssertion - Optional implicit assertion
/// @returns {string} Token: `v3.public.<message || signature>`
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
    let pk_bytes = verifying_key.to_sec1_point(true);
    let pk_slice = pk_bytes.as_bytes();

    let message_str = crate::common::serialize_message(message)?;

    let footer_str = footer.clone().unwrap_or_default();
    let implicit = implicit_assertion.clone().unwrap_or_default();

    let m2 = crate::common::pae_encode(&[
        pk_slice,
        V3_PUBLIC_HEADER.as_bytes(),
        message_str.as_bytes(),
        footer_str.as_bytes(),
        implicit.as_bytes(),
    ]);
    let signature: Signature = signing_key
        .sign(&m2);
    let sig_bytes = signature.to_bytes();

    let mut payload = Vec::with_capacity(message_str.len() + SIG_SIZE);
    payload.extend_from_slice(message_str.as_bytes());
    payload.extend_from_slice(&sig_bytes);

    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
    Ok(crate::common::format_token(
        V3_PUBLIC_HEADER,
        &payload_b64,
        &footer,
    ))
}

/// Verifies a V3 Public token (ECDSA P-384).
///
/// @example
/// ```javascript
/// const verified = paseto.verify_v3_public(kp.public, token, null, null);
/// // Returns: '{"data":"test"}'
/// ```
///
/// @param {string} publicKeyHex - 49-byte public key as hex
/// @param {string} token - Signed token
/// @param {string|null} footer - Footer used during signing
/// @param {string|null} implicitAssertion - Implicit assertion used during signing
/// @returns {string} Verified message
#[wasm_bindgen]
pub fn verify_v3_public(
    public_key_hex: &str,
    token: &str,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(public_key_hex, 49)?;

    let verifying_key = VerifyingKey::from_sec1_bytes(&key_vec)
        .map_err(|_| JsValue::from_str("Invalid public key"))?;

    let raw = crate::common::parse_token(token, V3_PUBLIC_HEADER, &footer)?;
    if raw.len() < SIG_SIZE {
        return Err(JsValue::from_str("Token too short"));
    }
    let message_len = raw.len() - SIG_SIZE;
    let message_bytes = &raw[..message_len];
    let sig_bytes = &raw[message_len..];

    let footer_str = footer.clone().unwrap_or_default();
    let implicit = implicit_assertion.clone().unwrap_or_default();

    let m2 = crate::common::pae_encode(&[
        &key_vec,
        V3_PUBLIC_HEADER.as_bytes(),
        message_bytes,
        footer_str.as_bytes(),
        implicit.as_bytes(),
    ]);
    let signature = Signature::from_slice(sig_bytes)
        .map_err(|_| JsValue::from_str("Invalid signature format"))?;

    verifying_key
        .verify(&m2, &signature)
        .map_err(|_| JsValue::from_str("Signature verification failed"))?;

    String::from_utf8(message_bytes.to_vec())
        .map_err(|_| JsValue::from_str("Message is not valid UTF-8"))
}

/// Converts a V3 local key to PASERK format.
///
/// @example
/// ```javascript
/// paseto.key_to_paserk_v3_local("2a04316d13e1e479...")
/// // Returns: "k3.local.VKBDGxE+4XmOKIhh3y6Ow4IP4jXQ..."
/// ```
///
/// @param {string} keyHex - 32-byte key as hex
/// @returns {string} PASERK: `k3.local.<base64>`
#[wasm_bindgen]
pub fn key_to_paserk_v3_local(key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(key_hex, 32, "k3.local.")
}

/// Converts a PASERK local key to hex format.
///
/// @example
/// ```javascript
/// paseto.paserk_v3_local_to_key("k3.local.VKBDGxE...")
/// // Returns: "2a04316d13e1e479e288861df6eaec3b..."
/// ```
///
/// @param {string} paserk - PASERK string starting with "k3.local."
/// @returns {string} 32-byte key as hex
#[wasm_bindgen]
pub fn paserk_v3_local_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k3.local.", 32)
}

/// Converts a V3 secret key to PASERK format.
///
/// @example
/// ```javascript
/// paseto.key_to_paserk_v3_secret("8d849f0466aefa356...")
/// // Returns: "k3.secret.g9hCOkJmrvNWAedGRN0E6009..."
/// ```
///
/// @param {string} secretKeyHex - 48-byte key as hex
/// @returns {string} PASERK: `k3.secret.<base64>`
#[wasm_bindgen]
pub fn key_to_paserk_v3_secret(secret_key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(secret_key_hex, 48, "k3.secret.")
}

/// Converts a PASERK secret key to hex format.
///
/// @example
/// ```javascript
/// paseto.paserk_v3_secret_to_key("k3.secret.g9hCOkJmrv...")
/// // Returns: "8d849f0466aefa3560e76f444dd04eb4..."
/// ```
///
/// @param {string} paserk - PASERK string starting with "k3.secret."
/// @returns {string} 48-byte key as hex
#[wasm_bindgen]
pub fn paserk_v3_secret_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k3.secret.", 48)
}

/// Converts a V3 public key to PASERK format.
///
/// @example
/// ```javascript
/// paseto.key_to_paserk_v3_public("0279ebc6ef149665...")
/// // Returns: "k3.public.Auecbv8UkmZVRojE48xSLQIB..."
/// ```
///
/// @param {string} publicKeyHex - 49-byte key as hex
/// @returns {string} PASERK: `k3.public.<base64>`
#[wasm_bindgen]
pub fn key_to_paserk_v3_public(public_key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(public_key_hex, 49, "k3.public.")
}

/// Converts a PASERK public key to hex format.
///
/// @example
/// ```javascript
/// paseto.paserk_v3_public_to_key("k3.public.Auecbv8Ukm...")
/// // Returns: "0279ebc6ef14966554668c483e3c52d2..."
/// ```
///
/// @param {string} paserk - PASERK string starting with "k3.public."
/// @returns {string} 49-byte key as hex
#[wasm_bindgen]
pub fn paserk_v3_public_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k3.public.", 49)
}

/// Generates a key ID for a V3 local key (k3.lid.*).
///
/// @example
/// ```javascript
/// paseto.get_v3_local_key_id("2a04316d13e1e479...")
/// // Returns: "k3.lid.V2JnQ4LmhP0fYh3T..."
/// ```
///
/// @param {string} keyHex - 32-byte key as hex
/// @returns {string} PASERK ID: `k3.lid.<base64>`
#[wasm_bindgen]
pub fn get_v3_local_key_id(key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    Ok(crate::common::paserk_id_from_bytes(
        &key_vec,
        "k3.local.",
        "k3.lid.",
    ))
}

/// Generates a key ID for a V3 public key (k3.pid.*).
///
/// @example
/// ```javascript
/// paseto.get_v3_public_key_id("0279ebc6ef149665...")
/// // Returns: "k3.pid.aG5hY2hxR3fN..."
/// ```
///
/// @param {string} publicKeyHex - 49-byte key as hex
/// @returns {string} PASERK ID: `k3.pid.<base64>`
#[wasm_bindgen]
pub fn get_v3_public_key_id(public_key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(public_key_hex, 49)?;
    Ok(crate::common::paserk_id_from_bytes(
        &key_vec,
        "k3.public.",
        "k3.pid.",
    ))
}

/// Generates a key ID for a V3 secret key (k3.sid.*).
///
/// @example
/// ```javascript
/// paseto.get_v3_secret_key_id("8d849f0466aefa356...")
/// // Returns: "k3.sid.mG5iZGln..."
/// ```
///
/// @param {string} secretKeyHex - 48-byte key as hex
/// @returns {string} PASERK ID: `k3.sid.<base64>`
#[wasm_bindgen]
pub fn get_v3_secret_key_id(secret_key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(secret_key_hex, 48)?;

    let signing_key =
        SigningKey::from_slice(&key_vec).map_err(|_| JsValue::from_str("Invalid secret key"))?;
    let verifying_key = VerifyingKey::from(&signing_key);
    let pk_bytes = verifying_key.to_sec1_point(true);
    let pk_slice = pk_bytes.as_bytes();

    Ok(crate::common::paserk_id_from_bytes(
        pk_slice, "k3.sid.", "k3.sid.",
    ))
}

//! # PASETO V6 WebAssembly Implementation
//!
//! PASETO Version 6 (draft) using keyed BLAKE2b + XChaCha20 (local) and
//! SLH-DSA-SHA256-128s (public, post-quantum), following the Version6
//! specification (`v6.local.` / `v6.public.`).
//!
//! ## Token Formats
//!
//! - Local: `v6.local.<nonce || ciphertext || tag>`
//! - Public: `v6.public.<message || signature>`
//!
//! ## PASERK Formats
//!
//! - `k6.local.*` - 32-byte symmetric key
//! - `k6.secret.*` - 64-byte secret key
//! - `k6.public.*` - 32-byte public key
//! - `k6.lid.*`, `k6.pid.*`, `k6.sid.*` - Key IDs

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use blake2::{
    digest::{
        consts::{U32, U56},
        FixedOutput, KeyInit, Update,
    },
    Blake2bMac,
};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    XChaCha20,
};
use slh_dsa::signature::{Keypair, Signer, Verifier};
use slh_dsa::{
    Sha2_128s, Signature as SlhSignature, SigningKey as SlhSigningKey,
    VerifyingKey as SlhVerifyingKey,
};
use wasm_bindgen::prelude::*;

const V6_LOCAL_HEADER: &str = "v6.local.";
const V6_PUBLIC_HEADER: &str = "v6.public.";
const V6_AUTH_INFO: &[u8] = b"paseto-auth-key-for-aead";
const V6_ENC_INFO: &[u8] = b"paseto-encryption-key";

fn v6_auth_key(key: &[u8; 32], nonce: &[u8; 32]) -> Result<[u8; 32], JsValue> {
    let mut info = Vec::with_capacity(56);
    info.extend_from_slice(V6_AUTH_INFO);
    info.extend_from_slice(nonce);
    let mut mac = Blake2bMac::<U32>::new_from_slice(key)
        .map_err(|_| JsValue::from_str("Invalid key"))?;
    mac.update(&info);
    let out = mac.finalize_fixed();
    let mut ak = [0u8; 32];
    ak.copy_from_slice(&out);
    Ok(ak)
}

fn v6_enc_parts(key: &[u8; 32], nonce: &[u8; 32]) -> Result<([u8; 32], [u8; 24]), JsValue> {
    let mut info = Vec::with_capacity(53);
    info.extend_from_slice(V6_ENC_INFO);
    info.extend_from_slice(nonce);
    let mut mac = Blake2bMac::<U56>::new_from_slice(key)
        .map_err(|_| JsValue::from_str("Invalid key"))?;
    mac.update(&info);
    let out = mac.finalize_fixed();
    let bytes = out.to_vec();
    let mut ek = [0u8; 32];
    let mut xn = [0u8; 24];
    ek.copy_from_slice(&bytes[..32]);
    xn.copy_from_slice(&bytes[32..56]);
    Ok((ek, xn))
}

fn v6_tag(auth_key: &[u8; 32], pae: &[u8]) -> Result<[u8; 32], JsValue> {
    let mut mac = Blake2bMac::<U32>::new_from_slice(auth_key)
        .map_err(|_| JsValue::from_str("Invalid auth key"))?;
    mac.update(pae);
    let out = mac.finalize_fixed();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    Ok(tag)
}

/// Generates a random 32-byte symmetric key for V6 local encryption.
///
/// @example
/// ```javascript
/// const key = paseto.generate_v6_local_key();
/// // Returns: "2a04316d13e1e479e288861df6eaec3b088ee33d..."
/// ```
///
/// @returns {string} 64-character hex string (32 bytes)
#[wasm_bindgen]
pub fn generate_v6_local_key() -> String {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("RNG failure");
    hex::encode(key)
}

/// Encrypts a message using V6 Local (XChaCha20 + keyed BLAKE2b).
///
/// @example
/// ```javascript
/// const key = paseto.generate_v6_local_key();
/// const token = paseto.encrypt_v6_local(key, { user: "123" }, null, null);
/// // Returns: "v6.local.eyJ1c2VyIjoiMTIzIn0..."
/// ```
///
/// @param {string} keyHex - 32-byte key as hex string
/// @param {string|object} message - Payload to encrypt
/// @param {string|null} footer - Optional footer
/// @param {string|null} implicitAssertion - Optional implicit assertion
/// @returns {string} Token: `v6.local.<ciphertext>`
#[wasm_bindgen]
pub fn encrypt_v6_local(
    key_hex: &str,
    message: JsValue,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_vec);

    let message_str = crate::common::serialize_message(message)?;

    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;

    let ak = v6_auth_key(&key, &nonce)?;
    let (ek, xn) = v6_enc_parts(&key, &nonce)?;

    let mut ciphertext = message_str.as_bytes().to_vec();
    let mut cipher = XChaCha20::new_from_slices(&ek, &xn)
        .map_err(|_| JsValue::from_str("Cipher init failed"))?;
    cipher.apply_keystream(&mut ciphertext);

    let footer_str = footer.clone().unwrap_or_default();
    let implicit_str = implicit_assertion.clone().unwrap_or_default();
    let pae = crate::common::pae_encode(&[
        V6_LOCAL_HEADER.as_bytes(),
        &nonce,
        &ciphertext,
        footer_str.as_bytes(),
        implicit_str.as_bytes(),
    ]);
    let tag = v6_tag(&ak, &pae)?;

    let mut raw = Vec::with_capacity(64 + ciphertext.len());
    raw.extend_from_slice(&nonce);
    raw.extend_from_slice(&ciphertext);
    raw.extend_from_slice(&tag);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&raw);
    Ok(crate::common::format_token(
        V6_LOCAL_HEADER,
        &payload_b64,
        &footer,
    ))
}

/// Decrypts a V6 Local token.
///
/// @example
/// ```javascript
/// const decrypted = paseto.decrypt_v6_local(key, token, null, null);
/// // Returns: '{"user":"123"}'
/// ```
///
/// @param {string} keyHex - 32-byte key as hex string
/// @param {string} token - Encrypted token
/// @param {string|null} footer - Footer used during encryption
/// @param {string|null} implicitAssertion - Implicit assertion used during encryption
/// @returns {string} Decrypted message
#[wasm_bindgen]
pub fn decrypt_v6_local(
    key_hex: &str,
    token: &str,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_vec);

    let raw = crate::common::parse_token(token, V6_LOCAL_HEADER, &footer)?;
    if raw.len() < 64 {
        return Err(JsValue::from_str("Token too short"));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&raw[..32]);
    let tag_start = raw.len() - 32;
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&raw[tag_start..]);
    let ciphertext = &raw[32..tag_start];

    let ak = v6_auth_key(&key, &nonce)?;
    let (ek, xn) = v6_enc_parts(&key, &nonce)?;

    let footer_str = footer.clone().unwrap_or_default();
    let implicit_str = implicit_assertion.clone().unwrap_or_default();
    let pae = crate::common::pae_encode(&[
        V6_LOCAL_HEADER.as_bytes(),
        &nonce,
        ciphertext,
        footer_str.as_bytes(),
        implicit_str.as_bytes(),
    ]);
    let expected_tag = v6_tag(&ak, &pae)?;
    if !crate::common::constant_time_eq(&tag, &expected_tag) {
        return Err(JsValue::from_str("Decryption failed: invalid tag"));
    }

    let mut plaintext = ciphertext.to_vec();
    let mut cipher = XChaCha20::new_from_slices(&ek, &xn)
        .map_err(|_| JsValue::from_str("Cipher init failed"))?;
    cipher.apply_keystream(&mut plaintext);
    String::from_utf8(plaintext).map_err(|_| JsValue::from_str("Message is not valid UTF-8"))
}

/// V6 asymmetric key pair (SLH-DSA-SHA256-128s).
///
/// Named `V6KeyPair` (rather than `KeyPair`) so the generated WASM binding
/// does not collide with the v4 `KeyPair` class when both features are on.
#[wasm_bindgen]
pub struct V6KeyPair {
    secret: String,
    public: String,
}

#[wasm_bindgen]
impl V6KeyPair {
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

fn v6_signing_key(secret_key_hex: &str) -> Result<SlhSigningKey<Sha2_128s>, JsValue> {
    let key_vec = crate::common::decode_hex_key(secret_key_hex, 64)?;
    SlhSigningKey::<Sha2_128s>::try_from(key_vec.as_slice())
        .map_err(|_| JsValue::from_str("Invalid secret key"))
}

fn v6_verifying_key(public_key_hex: &str) -> Result<SlhVerifyingKey<Sha2_128s>, JsValue> {
    let key_vec = crate::common::decode_hex_key(public_key_hex, 32)?;
    SlhVerifyingKey::<Sha2_128s>::try_from(key_vec.as_slice())
        .map_err(|_| JsValue::from_str("Invalid public key"))
}

/// Generates an SLH-DSA-SHA256-128s key pair for V6 public.
///
/// @example
/// ```javascript
/// const kp = paseto.generate_v6_public_key_pair();
/// console.log(kp.secret); // 128 hex chars (64 bytes)
/// console.log(kp.public); // 64 hex chars (32 bytes)
/// ```
///
/// @returns {V6KeyPair} { secret: 128-hex, public: 64-hex }
#[wasm_bindgen]
pub fn generate_v6_public_key_pair() -> V6KeyPair {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let signing_key = SlhSigningKey::<Sha2_128s>::new(&mut rng);
    let verifying_key: SlhVerifyingKey<Sha2_128s> = signing_key.verifying_key();

    V6KeyPair {
        secret: hex::encode(signing_key.to_bytes()),
        public: hex::encode(verifying_key.to_bytes()),
    }
}

/// Signs a message using V6 Public (SLH-DSA-SHA256-128s).
///
/// Note: signatures are 7856 bytes, so tokens are ~10KB or larger.
/// Avoid storing them in size-limited places such as cookies.
///
/// @example
/// ```javascript
/// const kp = paseto.generate_v6_public_key_pair();
/// const token = paseto.sign_v6_public(kp.secret, { data: "test" }, null, null);
/// // Returns: "v6.public.eyJkYXRhIjoidGVzdCJ9..." (~10KB)
/// ```
///
/// @param {string} secretKeyHex - 64-byte secret key as hex
/// @param {string|object} message - Payload to sign
/// @param {string|null} footer - Optional footer
/// @param {string|null} implicitAssertion - Optional implicit assertion
/// @returns {string} Token: `v6.public.<message || signature>`
#[wasm_bindgen]
pub fn sign_v6_public(
    secret_key_hex: &str,
    message: JsValue,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let signing_key = v6_signing_key(secret_key_hex)?;
    let public_key: SlhVerifyingKey<Sha2_128s> = signing_key.verifying_key();

    let message_str = crate::common::serialize_message(message)?;
    let footer_str = footer.clone().unwrap_or_default();
    let implicit_str = implicit_assertion.clone().unwrap_or_default();

    let pae = crate::common::pae_encode(&[
        public_key.to_bytes().as_slice(),
        V6_PUBLIC_HEADER.as_bytes(),
        message_str.as_bytes(),
        footer_str.as_bytes(),
        implicit_str.as_bytes(),
    ]);
    let signature: SlhSignature<Sha2_128s> = signing_key.sign(&pae);

    let mut raw = Vec::with_capacity(message_str.len() + 7856);
    raw.extend_from_slice(message_str.as_bytes());
    raw.extend_from_slice(signature.to_bytes().as_slice());
    let payload_b64 = URL_SAFE_NO_PAD.encode(&raw);
    Ok(crate::common::format_token(
        V6_PUBLIC_HEADER,
        &payload_b64,
        &footer,
    ))
}

/// Verifies a V6 Public token (SLH-DSA-SHA256-128s).
///
/// @example
/// ```javascript
/// const verified = paseto.verify_v6_public(kp.public, token, null, null);
/// // Returns: '{"data":"test"}'
/// ```
///
/// @param {string} publicKeyHex - 32-byte public key as hex
/// @param {string} token - Signed token
/// @param {string|null} footer - Footer used during signing
/// @param {string|null} implicitAssertion - Implicit assertion used during signing
/// @returns {string} Verified message
#[wasm_bindgen]
pub fn verify_v6_public(
    public_key_hex: &str,
    token: &str,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let verifying_key = v6_verifying_key(public_key_hex)?;

    let raw = crate::common::parse_token(token, V6_PUBLIC_HEADER, &footer)?;
    if raw.len() < 7856 {
        return Err(JsValue::from_str("Token too short"));
    }
    let msg_len = raw.len() - 7856;
    let msg_bytes = &raw[..msg_len];
    let sig_bytes = &raw[msg_len..];
    let signature = SlhSignature::<Sha2_128s>::try_from(sig_bytes)
        .map_err(|_| JsValue::from_str("Invalid signature"))?;

    let footer_str = footer.clone().unwrap_or_default();
    let implicit_str = implicit_assertion.clone().unwrap_or_default();
    let pae = crate::common::pae_encode(&[
        verifying_key.to_bytes().as_slice(),
        V6_PUBLIC_HEADER.as_bytes(),
        msg_bytes,
        footer_str.as_bytes(),
        implicit_str.as_bytes(),
    ]);
    verifying_key
        .verify(&pae, &signature)
        .map_err(|_| JsValue::from_str("Verification failed: invalid signature"))?;
    String::from_utf8(msg_bytes.to_vec()).map_err(|_| JsValue::from_str("Message is not valid UTF-8"))
}

/// Converts a V6 local key to PASERK format.
///
/// @example
/// ```javascript
/// paseto.key_to_paserk_v6_local("2a04316d13e1e479...")
/// // Returns: "k6.local.VKBDGxE+4XmOKIhh3y6Ow4IP4jXQ..."
/// ```
///
/// @param {string} keyHex - 32-byte key as hex
/// @returns {string} PASERK: `k6.local.<base64>`
#[wasm_bindgen]
pub fn key_to_paserk_v6_local(key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(key_hex, 32, "k6.local.")
}

/// Converts a PASERK local key to hex format.
///
/// @example
/// ```javascript
/// paseto.paserk_v6_local_to_key("k6.local.VKBDGxE...")
/// // Returns: "2a04316d13e1e479e288861df6eaec3b..."
/// ```
///
/// @param {string} paserk - PASERK string starting with "k6.local."
/// @returns {string} 32-byte key as hex
#[wasm_bindgen]
pub fn paserk_v6_local_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k6.local.", 32)
}

/// Converts a V6 secret key to PASERK format.
///
/// @example
/// ```javascript
/// paseto.key_to_paserk_v6_secret("48b5699fefd5be715...")
/// // Returns: "k6.secret.SYhZn+/VvnFc7auFW..."
/// ```
///
/// @param {string} secretKeyHex - 64-byte key as hex
/// @returns {string} PASERK: `k6.secret.<base64>`
#[wasm_bindgen]
pub fn key_to_paserk_v6_secret(secret_key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(secret_key_hex, 64, "k6.secret.")
}

/// Converts a PASERK secret key to hex format.
///
/// @example
/// ```javascript
/// paseto.paserk_v6_secret_to_key("k6.secret.SYhZn+/Vvn...")
/// // Returns: "48b5699fefd5be715cedab759c278e4cf..."
/// ```
///
/// @param {string} paserk - PASERK string starting with "k6.secret."
/// @returns {string} 64-byte key as hex
#[wasm_bindgen]
pub fn paserk_v6_secret_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k6.secret.", 64)
}

/// Converts a V6 public key to PASERK format.
///
/// @example
/// ```javascript
/// paseto.key_to_paserk_v6_public("d392fc09ebb0e479...")
/// // Returns: "k6.public.TZL8Ceuw5HncB85HszM4MAQGtfI1..."
/// ```
///
/// @param {string} publicKeyHex - 32-byte key as hex
/// @returns {string} PASERK: `k6.public.<base64>`
#[wasm_bindgen]
pub fn key_to_paserk_v6_public(public_key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(public_key_hex, 32, "k6.public.")
}

/// Converts a PASERK public key to hex format.
///
/// @example
/// ```javascript
/// paseto.paserk_v6_public_to_key("k6.public.TZL8Ceuw5Hnc...")
/// // Returns: "d392fc09ebb0e479d01ce793c33839004..."
/// ```
///
/// @param {string} paserk - PASERK string starting with "k6.public."
/// @returns {string} 32-byte key as hex
#[wasm_bindgen]
pub fn paserk_v6_public_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k6.public.", 32)
}

/// Generates a key ID for a V6 local key (k6.lid.*).
///
/// @example
/// ```javascript
/// paseto.get_v6_local_key_id("2a04316d13e1e479...")
/// // Returns: "k6.lid.V2JnQ4LmhP0fYh3T..."
/// ```
///
/// @param {string} keyHex - 32-byte key as hex
/// @returns {string} PASERK ID: `k6.lid.<base64>`
#[wasm_bindgen]
pub fn get_v6_local_key_id(key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, 32)?;
    Ok(crate::common::paserk_id_from_bytes(
        &key_vec,
        "k6.local.",
        "k6.lid.",
    ))
}

/// Generates a key ID for a V6 public key (k6.pid.*).
///
/// @example
/// ```javascript
/// paseto.get_v6_public_key_id("d392fc09ebb0e479...")
/// // Returns: "k6.pid.aG5hY2hxR3fN..."
/// ```
///
/// @param {string} publicKeyHex - 32-byte key as hex
/// @returns {string} PASERK ID: `k6.pid.<base64>`
#[wasm_bindgen]
pub fn get_v6_public_key_id(public_key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(public_key_hex, 32)?;
    Ok(crate::common::paserk_id_from_bytes(
        &key_vec,
        "k6.public.",
        "k6.pid.",
    ))
}

/// Generates a key ID for a V6 secret key (k6.sid.*).
///
/// @example
/// ```javascript
/// paseto.get_v6_secret_key_id("48b5699fefd5be715...")
/// // Returns: "k6.sid.mG5iZGln..."
/// ```
///
/// @param {string} secretKeyHex - 64-byte key as hex
/// @returns {string} PASERK ID: `k6.sid.<base64>`
#[wasm_bindgen]
pub fn get_v6_secret_key_id(secret_key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(secret_key_hex, 64)?;

    let public_key = &key_vec[32..64];

    Ok(crate::common::paserk_id_from_bytes(
        public_key, "k6.sid.", "k6.sid.",
    ))
}

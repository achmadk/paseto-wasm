//! # PASETO V4 WebAssembly Implementation
//!
//! PASETO Version 4 using Ed25519 for signatures and XChaCha20-Poly1305 for local encryption.
//!
//! ## Cryptographic Specifications
//!
//! | Property | Local | Public |
//! |----------|-------|--------|
//! | Algorithm | XChaCha20-Poly1305 | Ed25519 (EdDSA) |
//! | Key Size | 32 bytes | 32 bytes (public), 64 bytes (secret) |
//! | Nonce | 24 bytes | N/A |
//! | Tag | 16 bytes | 64 bytes (signature) |
//!
//! ## Token Formats
//!
//! - Local: `v4.local.<nonce || ciphertext || tag>`
//! - Public: `v4.public.<message || signature>`

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use blake2::digest::consts::{U32, U56};
use blake2::digest::{FixedOutput, KeyInit, Update};
use blake2::Blake2bMac;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::XChaCha20;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::convert::TryInto;
use subtle::ConstantTimeEq;
use wasm_bindgen::prelude::*;

const V4_LOCAL_HEADER: &str = "v4.local.";
const V4_PUBLIC_HEADER: &str = "v4.public.";
const NONCE_SIZE: usize = 32;
const TAG_SIZE: usize = 32;
const KEY_SIZE: usize = 32;
const AUTH_KEY_SEPARATOR: &[u8] = b"paseto-auth-key-for-aead";
const ENCRYPTION_KEY_SEPARATOR: &[u8] = b"paseto-encryption-key";

fn pae(pieces: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&(pieces.len() as u64).to_le_bytes());
    for piece in pieces {
        output.extend_from_slice(&(piece.len() as u64).to_le_bytes());
        output.extend_from_slice(piece);
    }
    output
}

fn keyed_mac(key: &[u8], data: &[u8], out_len: usize) -> Result<Vec<u8>, JsValue> {
    let mut mac = Blake2bMac::<U32>::new_from_slice(key)
        .map_err(|_| JsValue::from_str("MAC key error"))?;
    mac.update(data);
    let hash = mac.finalize_fixed();
    let mut out = hash.to_vec();
    out.truncate(out_len);
    Ok(out)
}

fn derive_key(
    key: &[u8],
    separator: &[u8],
    nonce: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, JsValue> {
    let mut context = Vec::with_capacity(separator.len() + nonce.len());
    context.extend_from_slice(separator);
    context.extend_from_slice(nonce);

    match out_len {
        // BLAKE2b's length parameter affects the output, so a 56-byte MAC must
        // use the native U56 output type, not a truncated U64.
        56 => {
            let mut mac = Blake2bMac::<U56>::new_from_slice(key)
                .map_err(|_| JsValue::from_str("MAC key error"))?;
            mac.update(&context);
            Ok(mac.finalize_fixed().to_vec())
        }
        _ => {
            let mut mac = Blake2bMac::<U32>::new_from_slice(key)
                .map_err(|_| JsValue::from_str("MAC key error"))?;
            mac.update(&context);
            Ok(mac.finalize_fixed().to_vec())
        }
    }
}

#[wasm_bindgen]
pub fn generate_v4_local_key() -> String {
    let mut key = [0u8; KEY_SIZE];
    getrandom::fill(&mut key).expect("RNG failure");
    hex::encode(key)
}

#[wasm_bindgen]
pub fn encrypt_v4_local(
    key_hex: &str,
    message: JsValue,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, KEY_SIZE)?;
    let key_arr: [u8; KEY_SIZE] = key_vec
        .clone()
        .try_into()
        .map_err(|_| JsValue::from_str("Key must be 32 bytes"))?;

    let message_str = crate::common::serialize_message(message)?;
    let message_bytes = message_str.as_bytes();

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;

    let footer_bytes = footer.as_deref().map(|s| s.as_bytes()).unwrap_or(&[]);
    let implicit_bytes = implicit_assertion
        .as_deref()
        .map(|s| s.as_bytes())
        .unwrap_or(&[]);

    // Nonce || key derivation per PASETO v4 spec: ek and n2 come from
    // BLAKE2b-MAC(key, ENCRYPTION_KEY_SEPARATOR || nonce); ak from
    // BLAKE2b-MAC(key, AUTH_KEY_SEPARATOR || nonce).
    let ek_n2 = derive_key(&key_arr, ENCRYPTION_KEY_SEPARATOR, &nonce_bytes, 56)?;
    let ek: [u8; 32] = ek_n2[..32]
        .try_into()
        .map_err(|_| JsValue::from_str("Key derive error"))?;
    let n2: [u8; 24] = ek_n2[32..56]
        .try_into()
        .map_err(|_| JsValue::from_str("Nonce derive error"))?;
    let ak = derive_key(&key_arr, AUTH_KEY_SEPARATOR, &nonce_bytes, 32)?;

    // XChaCha20 keystream applied to the message (no AEAD tag in the payload;
    // authenticity comes from the separate BLAKE2b-MAC tag computed below).
    let mut ciphertext = message_bytes.to_vec();
    let mut cipher = XChaCha20::new(&ek.into(), &n2.into());
    cipher.apply_keystream(&mut ciphertext);

    let pae_input = [
        b"v4.local.",
        &nonce_bytes[..],
        &ciphertext[..],
        footer_bytes,
        implicit_bytes,
    ];
    let pae_result = pae(&pae_input);

    let tag = keyed_mac(&ak, &pae_result, 32)?;

    let mut payload = nonce_bytes.to_vec();
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&tag);

    let token_payload = URL_SAFE_NO_PAD.encode(&payload);

    Ok(match footer {
        Some(f) => format!(
            "{}{}.{}",
            V4_LOCAL_HEADER,
            token_payload,
            URL_SAFE_NO_PAD.encode(f.as_bytes())
        ),
        None => format!("{}{}", V4_LOCAL_HEADER, token_payload),
    })
}

#[wasm_bindgen]
pub fn decrypt_v4_local(
    key_hex: &str,
    token: &str,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, KEY_SIZE)?;
    let key_arr: [u8; KEY_SIZE] = key_vec
        .try_into()
        .map_err(|_| JsValue::from_str("Key must be 32 bytes"))?;

    let parts: Vec<&str> = token.split('.').collect();
    if !(3..=4).contains(&parts.len()) {
        return Err(JsValue::from_str("Invalid token format"));
    }
    if parts[0] != "v4" || parts[1] != "local" {
        return Err(JsValue::from_str("Wrong header"));
    }

    let payload_b64 = parts[2];
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| JsValue::from_str("Invalid base64"))?;

    // V4 local payload: nonce || |ciphertext || tag (32 + 32 fixed).
    if payload.len() < NONCE_SIZE + TAG_SIZE {
        return Err(JsValue::from_str("Payload too short"));
    }

    let nonce_bytes: [u8; NONCE_SIZE] = payload[..NONCE_SIZE]
        .try_into()
        .map_err(|_| JsValue::from_str("Nonce error"))?;
    let ciphertext_len = payload.len() - NONCE_SIZE - TAG_SIZE;
    let ciphertext = &payload[NONCE_SIZE..NONCE_SIZE + ciphertext_len];
    let received_tag = &payload[NONCE_SIZE + ciphertext_len..];

    let footer_bytes = footer.as_deref().map(|s| s.as_bytes()).unwrap_or(&[]);
    let implicit_bytes = implicit_assertion
        .as_deref()
        .map(|s| s.as_bytes())
        .unwrap_or(&[]);

    let ek_n2 = derive_key(&key_arr, ENCRYPTION_KEY_SEPARATOR, &nonce_bytes, 56)?;
    let ek: [u8; 32] = ek_n2[..32]
        .try_into()
        .map_err(|_| JsValue::from_str("Key derive error"))?;
    let n2: [u8; 24] = ek_n2[32..56]
        .try_into()
        .map_err(|_| JsValue::from_str("Nonce derive error"))?;
    let ak = derive_key(&key_arr, AUTH_KEY_SEPARATOR, &nonce_bytes, 32)?;

    let pae_input = [
        b"v4.local.",
        &nonce_bytes[..],
        ciphertext,
        footer_bytes,
        implicit_bytes,
    ];
    let pae_result = pae(&pae_input);

    let computed_tag = keyed_mac(&ak, &pae_result, 32)?;

    if !bool::from(received_tag.ct_eq(&computed_tag[..])) {
        return Err(JsValue::from_str("Authentication failed"));
    }

    let mut plaintext = ciphertext.to_vec();
    let mut cipher = XChaCha20::new(&ek.into(), &n2.into());
    cipher.apply_keystream(&mut plaintext);

    String::from_utf8(plaintext).map_err(|_| JsValue::from_str("Invalid UTF-8"))
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

    let mut secret_64 = [0u8; 64];
    secret_64[..32].copy_from_slice(&signing_key.to_bytes());
    secret_64[32..].copy_from_slice(&verifying_key.to_bytes());

    KeyPair {
        secret: hex::encode(secret_64),
        public: hex::encode(verifying_key.to_bytes()),
    }
}

#[wasm_bindgen]
pub fn sign_v4_public(
    secret_key_hex: &str,
    message: JsValue,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(secret_key_hex, 64)?;
    let signing_key = SigningKey::from_keypair_bytes(
        key_vec
            .as_slice()
            .try_into()
            .map_err(|_| JsValue::from_str("Invalid key"))?,
    )
    .map_err(|_| JsValue::from_str("Invalid signing key"))?;

    let message_str = crate::common::serialize_message(message)?;

    let footer_bytes = footer.as_deref().map(|s| s.as_bytes()).unwrap_or(&[]);
    let implicit_bytes = implicit_assertion
        .as_deref()
        .map(|s| s.as_bytes())
        .unwrap_or(&[]);

    let pae_input = [
        b"v4.public.",
        message_str.as_bytes(),
        footer_bytes,
        implicit_bytes,
    ];
    let pae_result = pae(&pae_input);

    let signature = signing_key.sign(&pae_result);

    // Canonical v4.public payload: message bytes || 64-byte signature,
    // base64url-encoded once as a single segment.
    let mut raw_payload = Vec::with_capacity(message_str.len() + 64);
    raw_payload.extend_from_slice(message_str.as_bytes());
    raw_payload.extend_from_slice(&signature.to_bytes());

    let token_payload = URL_SAFE_NO_PAD.encode(&raw_payload);

    // Footer is appended as a separate dot-separated base64url segment.
    Ok(match footer {
        Some(f) => format!(
            "{}{}.{}",
            V4_PUBLIC_HEADER,
            token_payload,
            URL_SAFE_NO_PAD.encode(f.as_bytes())
        ),
        None => format!("{}{}", V4_PUBLIC_HEADER, token_payload),
    })
}

#[wasm_bindgen]
pub fn verify_v4_public(
    public_key_hex: &str,
    token: &str,
    footer: Option<String>,
    implicit_assertion: Option<String>,
) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(public_key_hex, KEY_SIZE)?;
    let verifying_key = VerifyingKey::from_bytes(
        key_vec
            .as_slice()
            .try_into()
            .map_err(|_| JsValue::from_str("Invalid public key"))?,
    )
    .map_err(|_| JsValue::from_str("Invalid verifying key"))?;

    let parts: Vec<&str> = token.split('.').collect();
    if !(3..=4).contains(&parts.len()) {
        return Err(JsValue::from_str("Invalid token format"));
    }

    let header = parts[0];
    if header != "v4" {
        return Err(JsValue::from_str("Wrong header"));
    }
    let purpose = parts[1];
    if purpose != "public" {
        return Err(JsValue::from_str("Wrong purpose"));
    }

    let payload_b64 = parts[2];

    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| JsValue::from_str("Invalid payload base64"))?;

    if payload.len() < 64 {
        return Err(JsValue::from_str("Payload too short"));
    }

    let message_len = payload.len() - 64;
    let message = &payload[..message_len];
    let signature_bytes = &payload[message_len..];

    let signature = Signature::try_from(signature_bytes)
        .map_err(|_| JsValue::from_str("Invalid signature"))?;

    let footer_bytes = footer.as_deref().map(|s| s.as_bytes()).unwrap_or(&[]);
    let implicit_bytes = implicit_assertion
        .as_deref()
        .map(|s| s.as_bytes())
        .unwrap_or(&[]);

    let pae_input = [b"v4.public.", message, footer_bytes, implicit_bytes];
    let pae_result = pae(&pae_input);

    verifying_key
        .verify_strict(&pae_result, &signature)
        .map_err(|_| JsValue::from_str("Verification failed"))?;

    String::from_utf8(message.to_vec()).map_err(|_| JsValue::from_str("Invalid UTF-8 in message"))
}

#[wasm_bindgen]
pub fn key_to_paserk_local(key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(key_hex, KEY_SIZE, "k4.local.")
}

#[wasm_bindgen]
pub fn paserk_local_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k4.local.", KEY_SIZE)
}

#[wasm_bindgen]
pub fn key_to_paserk_secret(secret_key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(secret_key_hex, 64, "k4.secret.")
}

#[wasm_bindgen]
pub fn paserk_secret_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k4.secret.", 64)
}

#[wasm_bindgen]
pub fn key_to_paserk_public(public_key_hex: &str) -> Result<String, JsValue> {
    crate::common::paserk_encode(public_key_hex, KEY_SIZE, "k4.public.")
}

#[wasm_bindgen]
pub fn paserk_public_to_key(paserk: &str) -> Result<String, JsValue> {
    crate::common::paserk_decode(paserk, "k4.public.", KEY_SIZE)
}

#[wasm_bindgen]
pub fn get_local_key_id(key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(key_hex, KEY_SIZE)?;
    Ok(crate::common::paserk_id_from_bytes(
        &key_vec,
        "k4.local.",
        "k4.lid.",
    ))
}

#[wasm_bindgen]
pub fn get_public_key_id(public_key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(public_key_hex, KEY_SIZE)?;
    Ok(crate::common::paserk_id_from_bytes(
        &key_vec,
        "k4.public.",
        "k4.pid.",
    ))
}

#[wasm_bindgen]
pub fn get_secret_key_id(secret_key_hex: &str) -> Result<String, JsValue> {
    let key_vec = crate::common::decode_hex_key(secret_key_hex, 64)?;
    let public_key = &key_vec[32..64];
    Ok(crate::common::paserk_id_from_bytes(
        public_key, "k4.sid.", "k4.sid.",
    ))
}

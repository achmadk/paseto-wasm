//! # paseto-wasm
//!
//! A WebAssembly (WASM) implementation of PASETO (Platform-Agnostic Security Tokens) for JavaScript/TypeScript environments.
//!
//! This crate provides PASETO v4 (default) and v3 (optional) implementations that can run in both
//! browser and Node.js environments via WebAssembly bindings.
//!
//! ## Features
//!
//! - **PASETO v4**: Modern PASETO version using XChaCha20-Poly1305 (local) and Ed25519 (public)
//!   - Enabled by default via the `v4` feature
//!   - Module: [`v4`]
//!
//! - **PASETO v3**: NIST-compliant PASETO version using AES-256-CTR + HMAC-SHA384 (local) and P-384 + ECDSA (public)
//!   - Optional feature: `v3`
//!   - Module: [`crate::v3`]
//!
//! ## Usage
//!
//! See the individual module documentation for detailed API usage.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Standard PASETO/JWT claims structure for structured payloads.
///
/// This struct provides a typed representation of common JWT/PASETO claims while allowing
/// flexibility through custom extra claims. When serializing, all fields are optional and
/// will only be included if they contain values.
///
/// # Standard Claims
///
/// | Field | Description | RFC 7519 Name |
/// |-------|-------------|---------------|
/// | `exp` | Expiration time (Unix timestamp) | Expiration Time |
/// | `iat` | Issued at time (Unix timestamp) | Issued At |
/// | `nbf` | Not before time (Unix timestamp) | Not Before |
/// | `aud` | Intended audience | Audience |
/// | `sub` | Subject of the token | Subject |
/// | `iss` | Issuer of the token | Issuer |
/// | `jti` | Unique identifier for the token | JWT ID |
///
/// # Example
///
/// ```rust,no_run
/// use paseto_wasm::PasetoClaims;
/// use serde_json::json;
///
/// let claims = PasetoClaims {
///     sub: Some("user123".to_string()),
///     iss: Some("my-app".to_string()),
///     exp: Some("1234567890".to_string()),
///     extra: Some(json!({"role": "admin"}).as_object().unwrap().clone()),
///     ..Default::default()
/// };
/// ```
#[derive(Serialize, Deserialize, Default)]
pub struct PasetoClaims {
    /// Expiration time as a Unix timestamp (seconds since epoch).
    /// When this time is reached, the token should no longer be accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,

    /// Issued at time as a Unix timestamp (seconds since epoch).
    /// Indicates when the token was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<String>,

    /// Not before time as a Unix timestamp (seconds since epoch).
    /// The token should not be accepted before this time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<String>,

    /// Audience - the intended recipient(s) of the token.
    /// Can be a single string or an array of strings (serialized as JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// Subject - the principal that is the subject of the token.
    /// Typically a user ID or similar identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Issuer - the entity that issued the token.
    /// Identifies the authentication server or application.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// JWT ID - a unique identifier for the token.
    /// Used to prevent token replay attacks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Additional custom claims that are not part of the standard set.
    /// These are flattened into the top level of the JSON payload.
    #[serde(flatten)]
    pub extra: Option<serde_json::Map<String, Value>>,
}

#[cfg(feature = "v4")]
pub mod v4;

#[cfg(feature = "v3")]
pub mod v3;

pub mod common;

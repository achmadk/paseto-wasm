use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Standard PASETO/JWT claims structure for structured payloads.
/// All fields are optional to allow flexible usage.
#[derive(Serialize, Deserialize, Default)]
pub struct PasetoClaims {
    /// Expiration time (NumericDate)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
    /// Issued at time (NumericDate)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<String>,
    /// Not before time (NumericDate)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<String>,
    /// Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Subject
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Additional custom claims (flattened into the payload)
    #[serde(flatten)]
    pub extra: Option<serde_json::Map<String, Value>>,
}

#[cfg(feature = "v4")]
pub mod v4;

#[cfg(feature = "v3")]
pub mod v3;

pub mod common;


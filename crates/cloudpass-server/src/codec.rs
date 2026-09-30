//! Base64 wire encoding and time helpers.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A byte string carried as base64 in JSON.
///
/// Every opaque blob in this API — envelopes, key wrappers, OPAQUE protocol
/// messages — travels as one of these. The server never looks inside one: it moves
/// bytes from a request body into a `BLOB` column and back out again, which is what
/// makes "the server cannot read your vault" a structural property rather than a
/// promise. A test asserts the round trip is byte-identical.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct B64(pub Vec<u8>);

impl B64 {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for B64 {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Serialize for B64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        STANDARD
            .decode(encoded.as_bytes())
            .map(Self)
            .map_err(|_| D::Error::custom("invalid base64"))
    }
}

/// Current Unix time in seconds.
///
/// Deliberately not used for the sync cursor: client clocks are untrusted, and a
/// monotonic server-side sequence is what makes "what changed since last time"
/// correct even when clocks disagree.
#[must_use]
pub fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Normalises an account identifier.
///
/// The OPAQUE credential identifier is derived from this value on both sides, so a
/// difference of one byte silently breaks an account. Normalising in exactly one
/// place is what keeps registration and login in agreement.
pub fn normalize_identifier(raw: &str) -> Option<String> {
    let trimmed = raw.trim().to_lowercase();
    if trimmed.len() < 3 || trimmed.len() > 254 {
        return None;
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_arbitrary_bytes() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let encoded = serde_json::to_string(&B64(bytes.clone())).expect("serialize");
        let decoded: B64 = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded.0, bytes);
    }

    #[test]
    fn invalid_base64_is_rejected() {
        let result: Result<B64, _> = serde_json::from_str(r#""not base64!!""#);
        assert!(result.is_err());
    }

    #[test]
    fn identifiers_are_normalised() {
        assert_eq!(
            normalize_identifier("  Alice@Example.COM ").unwrap(),
            "alice@example.com"
        );
    }

    #[test]
    fn unusable_identifiers_are_rejected() {
        assert!(normalize_identifier("ab").is_none());
        assert!(normalize_identifier("").is_none());
        assert!(normalize_identifier("bad\u{0}char").is_none());
        assert!(normalize_identifier(&"x".repeat(255)).is_none());
    }
}

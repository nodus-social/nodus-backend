//! Validation and limits for per-account client metadata keys.

use crate::limits::{
    CLIENT_METADATA_MAX_BYTES, CLIENT_METADATA_MAX_KEYS, CLIENT_METADATA_MAX_KEY_LEN,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientMetadataError {
    #[error("client metadata key must not be empty")]
    EmptyKey,
    #[error("client metadata key exceeds {CLIENT_METADATA_MAX_KEY_LEN} bytes")]
    KeyTooLong,
    #[error(
        "client metadata key contains invalid characters: only ASCII letters, digits, '-', '_', '.', and ':' are allowed, without '..'"
    )]
    InvalidKeyChars,
    #[error("client metadata exceeds maximum of {CLIENT_METADATA_MAX_KEYS} keys")]
    TooManyKeys,
    #[error("client metadata exceeds maximum of {CLIENT_METADATA_MAX_BYTES} bytes")]
    PayloadTooLarge,
}

/// Validates a fine-grained client metadata key.
pub fn validate_key(key: &str) -> Result<(), ClientMetadataError> {
    if key.is_empty() {
        return Err(ClientMetadataError::EmptyKey);
    }
    if key.len() > CLIENT_METADATA_MAX_KEY_LEN {
        return Err(ClientMetadataError::KeyTooLong);
    }
    if key == "." || key.contains("..") {
        return Err(ClientMetadataError::InvalidKeyChars);
    }
    if !key
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ClientMetadataError::InvalidKeyChars);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_client_metadata_keys() {
        for key in [
            "nodus-top-banner",
            "nodus-left-image",
            "nodus-right-image",
            "nodus-nav-layout",
            "com.example.client:theme_v2",
            "a",
        ] {
            assert_eq!(validate_key(key), Ok(()), "key={key}");
        }
    }

    #[test]
    fn rejects_invalid_client_metadata_keys() {
        assert_eq!(validate_key(""), Err(ClientMetadataError::EmptyKey));
        assert_eq!(
            validate_key(&"k".repeat(CLIENT_METADATA_MAX_KEY_LEN + 1)),
            Err(ClientMetadataError::KeyTooLong)
        );
        for bad in [".", "..", "a..b", "bad key", "a/b", "a?b", "a$b", "é"] {
            assert_eq!(
                validate_key(bad),
                Err(ClientMetadataError::InvalidKeyChars),
                "key={bad}"
            );
        }
    }
}

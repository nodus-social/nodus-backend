//! Capability tokens: round trip, tampering, expiry and the variant check.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use nodus_storage::{Capability, TokenError};

const SECRET: &[u8] = b"an instance's signing key";
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

#[tokio::test]
async fn a_minted_token_verifies_to_its_claims() {
    let expires = at(1_800_000_000);
    let token = Capability::mint(SECRET, DIGEST, "original", expires);
    let claims = Capability::verify(SECRET, &token, at(1_799_999_999)).unwrap();
    assert_eq!(claims.digest, DIGEST);
    assert_eq!(claims.variant, "original");
    assert_eq!(claims.expires_at, expires);
    assert!(claims.allows("original"));
    assert!(!claims.allows("preview"));
}

#[tokio::test]
async fn a_tampered_digest_does_not_verify() {
    let token = Capability::mint(SECRET, DIGEST, "original", at(1_800_000_000));
    let (payload, signature) = token.split_once('.').unwrap();
    assert!(token.starts_with(payload));
    // Re-encoding a different digest under the same signature is exactly the edit a
    // leaked URL invites, and it is the thing the signature exists to stop.
    let forged_payload = URL_SAFE_NO_PAD.encode(
        b"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210|original|1800000000",
    );
    let forged = format!("{forged_payload}.{signature}");
    assert_eq!(
        Capability::verify(SECRET, &forged, at(1_799_999_999)).unwrap_err(),
        TokenError::BadSignature
    );
    // The untouched token still verifies, so the edit was the only problem.
    assert!(Capability::verify(SECRET, &token, at(1_799_999_999)).is_ok());
}

#[tokio::test]
async fn one_second_past_expiry_is_expired() {
    let expires = at(1_800_000_000);
    let token = Capability::mint(SECRET, DIGEST, "original", expires);
    assert!(Capability::verify(SECRET, &token, expires).is_ok());
    assert_eq!(
        Capability::verify(SECRET, &token, expires + Duration::from_secs(1)).unwrap_err(),
        TokenError::Expired
    );
    // A caller that opts into skew tolerance is the only way past the strict check.
    assert!(Capability::verify_with_grace(
        SECRET,
        &token,
        expires + Duration::from_secs(1),
        nodus_storage::token::GRACE
    )
    .is_ok());
}

#[tokio::test]
async fn a_preview_token_does_not_verify_as_original() {
    let token = Capability::mint(SECRET, DIGEST, "preview", at(1_800_000_000));
    let claims = Capability::verify(SECRET, &token, at(1_799_999_999)).unwrap();
    assert_eq!(claims.variant, "preview");
    assert!(!claims.allows("original"));
}

#[tokio::test]
async fn a_token_signed_by_another_secret_is_refused() {
    let token = Capability::mint(b"another instance", DIGEST, "original", at(1_800_000_000));
    assert_eq!(
        Capability::verify(SECRET, &token, at(1_799_999_999)).unwrap_err(),
        TokenError::BadSignature
    );
}

#[tokio::test]
async fn rubbish_is_bad_format() {
    for token in ["", "no-dot", "a.b.c", ".", "!!!.???", "abc."] {
        assert_eq!(
            Capability::verify(SECRET, token, at(1_799_999_999)).unwrap_err(),
            TokenError::BadFormat,
            "{token:?} should be BadFormat"
        );
    }
}

//! Signed, short-lived permission to read one digest in one variant.
//!
//! A token is `base64url("digest|variant|unix_secs") . base64url(HMAC-SHA256(that text,
//! secret))`. It is not PASETO or JWT on purpose: there is no algorithm field to
//! confuse, no library to keep current, and the only claim that exists is the one the
//! media surface needs — which digest, which rendition, until when.
//!
//! The signature is over the encoded payload rather than the plaintext, so a verifier
//! compares exactly the bytes it will parse, and a token cannot be re-encoded into a
//! second spelling of the same claims.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

/// How much clock skew a caller may choose to forgive, in seconds.
///
/// [`Capability::verify`] is strict — a token is dead the second its expiry passes — so
/// that a one-second overshoot is refused. A caller that would rather not fail on a
/// slightly slow clock can pass this allowance to
/// [`Capability::verify_with_grace`] instead.
pub const GRACE: Duration = Duration::from_secs(60);

type HmacSha256 = Hmac<Sha256>;

/// Minting and checking tokens.
pub struct Capability;

/// What a verified token says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    /// The digest the token is good for, lowercase hex SHA-256.
    pub digest: String,
    /// The rendition the token is good for, e.g. `original` or `preview`.
    pub variant: String,
    /// The last instant the token is valid.
    pub expires_at: SystemTime,
}

impl Claims {
    /// Whether this token grants exactly `variant`.
    ///
    /// A `preview` token is not an `original` token: the variant is compared, not merely
    /// carried, so a cheap rendition's URL cannot be edited into the full-size one.
    #[must_use]
    pub fn allows(&self, variant: &str) -> bool {
        self.variant == variant
    }

    /// Whether the token has run out at `now`.
    #[must_use]
    pub fn is_expired(&self, now: SystemTime) -> bool {
        now > self.expires_at
    }
}

impl Capability {
    /// Signs a token for `digest` in `variant`, good until `expires_at`.
    ///
    /// `secret` is the instance's signing key; changing it invalidates every token
    /// already handed out, which is the intended revocation story for this phase.
    #[must_use]
    pub fn mint(secret: &[u8], digest: &str, variant: &str, expires_at: SystemTime) -> String {
        let seconds = expires_at
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let payload = format!("{digest}|{variant}|{seconds}");
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(sign(&encoded, secret));
        format!("{encoded}.{signature}")
    }

    /// Verifies `token` at `now`, strictly: one second past its expiry is `Expired`.
    pub fn verify(secret: &[u8], token: &str, now: SystemTime) -> Result<Claims, TokenError> {
        Self::verify_with_grace(secret, token, now, Duration::ZERO)
    }

    /// Verifies `token` at `now`, tolerating up to `grace` of clock skew past expiry.
    pub fn verify_with_grace(
        secret: &[u8],
        token: &str,
        now: SystemTime,
        grace: Duration,
    ) -> Result<Claims, TokenError> {
        let (encoded, signature) = token.split_once('.').ok_or(TokenError::BadFormat)?;
        if encoded.is_empty() || signature.is_empty() || signature.contains('.') {
            return Err(TokenError::BadFormat);
        }
        let presented = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| TokenError::BadFormat)?;
        // Constant-time check: `verify_slice` compares the whole tag without an early
        // exit, so a caller cannot learn a correct prefix from timing.
        let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| TokenError::BadFormat)?;
        mac.update(encoded.as_bytes());
        mac.verify_slice(&presented)
            .map_err(|_| TokenError::BadSignature)?;

        let payload = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| TokenError::BadFormat)?;
        let payload = String::from_utf8(payload).map_err(|_| TokenError::BadFormat)?;
        let mut fields = payload.splitn(3, '|');
        let digest = fields.next().ok_or(TokenError::BadFormat)?.to_owned();
        let variant = fields.next().ok_or(TokenError::BadFormat)?.to_owned();
        let seconds: u64 = fields
            .next()
            .ok_or(TokenError::BadFormat)?
            .parse()
            .map_err(|_| TokenError::BadFormat)?;
        let expires_at = UNIX_EPOCH + Duration::from_secs(seconds);
        let deadline = expires_at
            .checked_add(grace)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        if now > deadline {
            return Err(TokenError::Expired);
        }
        Ok(Claims {
            digest,
            variant,
            expires_at,
        })
    }
}

/// HMAC-SHA256 of `message` under `secret`.
fn sign(message: &str, secret: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts a key of any length");
    mac.update(message.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Why a token was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TokenError {
    /// Not `payload.signature` with two base64url parts.
    #[error("the token is not a capability this instance mints")]
    BadFormat,
    /// The signature does not cover this payload under this secret.
    #[error("the token's signature does not match its payload")]
    BadSignature,
    /// The signature is genuine, but the token has run out.
    #[error("the token has expired")]
    Expired,
}

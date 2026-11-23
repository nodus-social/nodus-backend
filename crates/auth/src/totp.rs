//! RFC 6238 time-based one-time passwords and the recovery codes that outlive them.
//!
//! The algorithm is HMAC-SHA1 over a 30-second counter, which is small enough to keep in
//! the tree rather than add a TOTP crate for. Everything here is pure: the handlers pass
//! in the current step so a test can pin the clock.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::RngCore as _;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// RFC 6238's default period, and the one every authenticator app assumes.
pub const STEP_SECONDS: u64 = 30;
/// Six digits is what the `otpauth` URI advertises and what users' apps display.
const DIGITS: u32 = 6;
/// Ten codes: enough to survive losing a phone for a week, few enough to print once.
pub const RECOVERY_CODES: usize = 10;

type HmacSha1 = Hmac<Sha1>;

/// The step number for a Unix timestamp.
#[must_use]
pub fn step_at(unix_seconds: i64) -> u64 {
    u64::try_from(unix_seconds / i64::try_from(STEP_SECONDS).unwrap_or(30)).unwrap_or(0)
}

/// A fresh 160-bit secret in the base32 form authenticator apps accept.
#[must_use]
pub fn generate_secret() -> String {
    let mut bytes = [0_u8; 20];
    rand::rng().fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes)
}

/// The six-digit code for `secret` at `step`, or `None` for a malformed secret.
#[must_use]
pub fn code_at(secret: &str, step: u64) -> Option<String> {
    let key = BASE32_NOPAD.decode(secret.as_bytes()).ok()?;
    let mut mac = HmacSha1::new_from_slice(&key).ok()?;
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    Some(format!("{:06}", binary % 10_u32.pow(DIGITS)))
}

/// Accepts a code from the current step or one either side, and refuses a step that has
/// already been spent.
///
/// The ±1 window is the tolerance clock drift needs; the `after_step` floor is what stops
/// a code observed in flight from being replayed inside its own window. Returns the step
/// to record as spent.
#[must_use]
pub fn verify(secret: &str, code: &str, current_step: u64, after_step: Option<i64>) -> Option<i64> {
    let code = code.trim();
    if code.len() != usize::try_from(DIGITS).unwrap_or(6) || !code.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    // Largest first: if the server clock lags the client, the later step is the honest
    // reading, and recording it also covers the window in between.
    for offset in [1_i64, 0, -1] {
        let step = i64::try_from(current_step).ok()? + offset;
        if step < 0 || after_step.is_some_and(|used| step <= used) {
            continue;
        }
        let Ok(step_number) = u64::try_from(step) else {
            continue;
        };
        if code_at(secret, step_number).as_deref() == Some(code) {
            return Some(step);
        }
    }
    None
}

/// The `otpauth://totp/...` URI an authenticator app scans.
#[must_use]
pub fn provisioning_uri(issuer: &str, account: &str, secret: &str) -> String {
    let label = format!("{issuer}:{account}");
    let encode = |value: &str| {
        url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
    };
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}",
        encode(&label),
        encode(secret),
        encode(issuer),
    )
}

/// A single-use recovery code, grouped for reading aloud and typing.
#[must_use]
pub fn generate_recovery_code() -> String {
    let mut bytes = [0_u8; 10];
    rand::rng().fill_bytes(&mut bytes);
    let raw = BASE32_NOPAD.encode(&bytes);
    raw.as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// Normalises a submitted recovery code so case and the grouping dashes do not matter.
#[must_use]
pub fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

/// The stored form of a recovery code. The code itself is 50 bits of randomness, so a
/// plain SHA-256 is enough; unlike a password there is nothing to guess.
#[must_use]
pub fn recovery_code_hash(code: &str) -> String {
    let digest = Sha256::digest(normalize_recovery_code(code).as_bytes());
    format!("{digest:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B's SHA-1 vector, truncated to the six digits we issue.
    #[test]
    fn rfc6238_vector_matches() {
        assert_eq!(step_at(59), 1);
        assert_eq!(code_at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1).as_deref(), Some("287082"));
    }

    #[test]
    fn a_code_is_accepted_one_step_either_side_and_never_twice() {
        let secret = generate_secret();
        let current = step_at(1_700_000_000);
        let code = code_at(&secret, current).expect("code");
        assert_eq!(verify(&secret, &code, current, None), Some(i64::try_from(current).unwrap()));
        assert_eq!(verify(&secret, &code, current, Some(i64::try_from(current).unwrap())), None);
        let next = code_at(&secret, current + 1).expect("next code");
        assert!(verify(&secret, &next, current, None).is_some());
        let previous = code_at(&secret, current - 1).expect("previous code");
        assert!(verify(&secret, &previous, current, None).is_some());
        let far = code_at(&secret, current + 2).expect("far code");
        assert_eq!(verify(&secret, &far, current, None), None);
    }

    #[test]
    fn recovery_codes_are_readable_and_compare_after_normalising() {
        let code = generate_recovery_code();
        assert_eq!(code.len(), 19, "four fours and three dashes");
        assert_eq!(
            recovery_code_hash(&code.to_lowercase().replace('-', " ")),
            recovery_code_hash(&code)
        );
        assert_ne!(recovery_code_hash(&code), recovery_code_hash(&generate_recovery_code()));
    }
}

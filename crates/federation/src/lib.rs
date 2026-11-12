//! ActivityPub signature verification.
//!
//! This module is deliberately small and total: it parses a `Signature` header, rebuilds
//! the signing string, and verifies an RSA signature. It never fetches an actor — the
//! caller owns the network and the cache policy, so a hostile server cannot make this
//! code fetch anything.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::{Digest as _, Sha256};

/// Tolerated clock skew, applied symmetrically.
pub const MAX_CLOCK_SKEW: Duration = Duration::minutes(12);

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("missing signature")]
    MissingSignature,
    #[error("the signature header is malformed: {0}")]
    Malformed(&'static str),
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("the request has no digest, so its body cannot be trusted")]
    MissingDigest,
    #[error("the digest does not match the body")]
    DigestMismatch,
    #[error("the date is missing or outside the accepted window")]
    StaleDate,
    #[error("the acting key is missing")]
    MissingKey,
    #[error("the signature does not verify")]
    BadSignature,
}

/// The fields of a draft-cavage `Signature` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureParams {
    pub key_id: String,
    pub algorithm: String,
    pub headers: Vec<String>,
    pub signature: Vec<u8>,
}

/// Parses `keyId="…",algorithm="…",headers="…",signature="…"`.
///
/// The header is a comma-separated list of `name="value"` pairs; values may not contain
/// quotes, which is exactly what the spec allows and what every implementation emits.
pub fn parse_header(raw: &str) -> Result<SignatureParams, VerifyError> {
    let mut key_id = None;
    let mut algorithm = None;
    let mut headers = None;
    let mut signature = None;

    for part in raw.split(',') {
        let part = part.trim();
        let (name, value) = part
            .split_once('=')
            .ok_or(VerifyError::Malformed("expected name=\"value\""))?;
        let value = value.trim().trim_matches('"');
        match name {
            "keyId" => key_id = Some(value.to_owned()),
            "algorithm" => algorithm = Some(value.to_owned()),
            "headers" => headers = Some(value.split_whitespace().map(str::to_owned).collect()),
            "signature" => {
                signature = Some(BASE64.decode(value).map_err(|_| VerifyError::Malformed("bad signature"))?);
            }
            // Unknown parameters are ignored: the spec requires forward compatibility and
            // instance software in the wild adds fields.
            _ => {}
        }
    }

    Ok(SignatureParams {
        key_id: key_id.ok_or(VerifyError::Malformed("no keyId"))?,
        algorithm: algorithm.unwrap_or_else(|| "rsa-sha256".to_owned()),
        headers: headers.unwrap_or_else(|| {
            vec![
                "(request-target)".to_owned(),
                "host".to_owned(),
                "date".to_owned(),
                "digest".to_owned(),
            ]
        }),
        signature: signature.ok_or(VerifyError::Malformed("no signature"))?,
    })
}

/// Rebuilds the signing string from the headers the signature names.
///
/// `lookup` returns the header value by lowercase name; `(request-target)` is answered
/// by this function from the method and path, because it is not a real header.
pub fn signing_string(
    params: &SignatureParams,
    method: &str,
    path: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<String, VerifyError> {
    let mut lines = Vec::with_capacity(params.headers.len());
    for name in &params.headers {
        let value = if name == "(request-target)" {
            format!("{} {}", method.to_lowercase(), path)
        } else if name == "(created)" || name == "(expires)" {
            // Mastodon sends these on outgoing requests and requires them on some
            // incoming ones; they arrive as headers with the parentheses stripped.
            lookup(name).ok_or(VerifyError::Malformed("missing signed header"))?
        } else {
            lookup(name).ok_or(VerifyError::Malformed("missing signed header"))?
        };
        lines.push(format!("{name}: {value}"));
    }
    Ok(lines.join("\n"))
}

/// `Digest: SHA-256=base64(sha256(body))`, compared in constant time.
pub fn verify_digest(body: &[u8], header: &str) -> Result<(), VerifyError> {
    let (alg, encoded) = header
        .split_once('=')
        .ok_or(VerifyError::Malformed("digest is not name=value"))?;
    if !alg.eq_ignore_ascii_case("sha-256") {
        return Err(VerifyError::UnsupportedAlgorithm(alg.to_owned()));
    }
    let expected = BASE64.decode(encoded.trim()).map_err(|_| VerifyError::Malformed("bad digest"))?;
    let actual = Sha256::digest(body);
    if expected.len() != actual.len() || !constant_time_eq(&expected, &actual) {
        return Err(VerifyError::DigestMismatch);
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Everything verification needs, already fetched by the caller.
pub struct SignedRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    /// PEM of the actor's public key, cached by the caller.
    pub actor_key_pem: &'a str,
    pub now: DateTime<Utc>,
}

/// Verifies digest, date window and signature in the order the failures matter:
/// a wrong digest means the body is not the one that was signed, so checking it first
/// keeps a forged body from ever reaching a signature check.
pub fn verify(request: &SignedRequest<'_>) -> Result<SignatureParams, VerifyError> {
    let header = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("signature"))
        .map(|(_, value)| value.clone())
        .ok_or(VerifyError::MissingSignature)?;
    let params = parse_header(&header)?;

    if params.algorithm != "rsa-sha256" {
        return Err(VerifyError::UnsupportedAlgorithm(params.algorithm));
    }

    let get = |name: &str| {
        request
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    };

    if let Some(digest) = get("digest") {
        verify_digest(request.body, &digest)?;
    } else if params.headers.iter().any(|name| name == "digest") {
        return Err(VerifyError::MissingDigest);
    }

    let date = get("date").ok_or(VerifyError::StaleDate)?;
    let signed_at = DateTime::parse_from_rfc2822(&date)
        .map_err(|_| VerifyError::StaleDate)?
        .with_timezone(&Utc);
    if (request.now - signed_at).num_seconds().abs() > MAX_CLOCK_SKEW.num_seconds() {
        return Err(VerifyError::StaleDate);
    }

    let key = RsaPublicKey::from_public_key_pem(request.actor_key_pem)
        .or_else(|_| rsa::pkcs1::DecodeRsaPublicKey::from_pkcs1_pem(request.actor_key_pem))
        .map_err(|_| VerifyError::MissingKey)?;
    let signing = signing_string(&params, request.method, request.path, get)?;
    let signature =
        Signature::try_from(params.signature.as_slice()).map_err(|_| VerifyError::BadSignature)?;
    VerifyingKey::<Sha256>::new(key)
        .verify(signing.as_bytes(), &signature)
        .map_err(|_| VerifyError::BadSignature)?;

    Ok(params)
}

/// `SHA-256=` + base64, for outgoing requests.
#[must_use]
pub fn digest_header(body: &[u8]) -> String {
    format!("SHA-256={}", BASE64.encode(Sha256::digest(body)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::{EncodePublicKey as _, LineEnding};
    use rsa::rand_core::OsRng;
    use rsa::signature::{SignatureEncoding as _, Signer as _};
    use rsa::RsaPrivateKey;

    /// 1024 bits keeps the debug-build tests fast; the verification path is identical.
    fn key_pair() -> (RsaPrivateKey, String) {
        let private = RsaPrivateKey::new(&mut OsRng, 1024).expect("key");
        let pem = RsaPublicKey::from(&private)
            .to_public_key_pem(LineEnding::LF)
            .expect("pem");
        (private, pem)
    }

    #[test]
    fn parses_a_header_and_defaults_the_signed_list() {
        let parsed = parse_header("keyId=\"https://a/b#main-key\",algorithm=\"rsa-sha256\",signature=\"AAAA\"")
            .expect("header");
        assert_eq!(parsed.key_id, "https://a/b#main-key");
        assert_eq!(parsed.algorithm, "rsa-sha256");
        assert_eq!(parsed.headers, vec!["(request-target)", "host", "date", "digest"]);
        assert_eq!(parsed.signature, vec![0, 0, 0]);
    }

    #[test]
    fn a_missing_key_id_is_rejected() {
        let error = parse_header("signature=\"AAAA\"").expect_err("should fail");
        assert!(matches!(error, VerifyError::Malformed("no keyId")));
    }

    #[test]
    fn the_signing_string_is_lowercased_method_and_space_separated() {
        let params = parse_header(
            "keyId=\"k\",headers=\"(request-target) host date\",signature=\"AAAA\"",
        )
        .expect("header");
        let signing = signing_string(&params, "POST", "/users/x/inbox", |name| match name {
            "host" => Some("example.test".to_owned()),
            "date" => Some("Sun, 06 Nov 1994 08:49:37 GMT".to_owned()),
            _ => None,
        })
        .expect("signing string");
        assert_eq!(
            signing,
            "(request-target): post /users/x/inbox\nhost: example.test\ndate: Sun, 06 Nov 1994 08:49:37 GMT"
        );
    }

    #[test]
    fn a_body_that_does_not_match_its_digest_is_refused_before_the_signature() {
        let header = digest_header(b"{\"a\":1}");
        assert!(verify_digest(b"{\"a\":1}", &header).is_ok());
        assert!(matches!(
            verify_digest(b"{\"a\":2}", &header),
            Err(VerifyError::DigestMismatch)
        ));
        assert!(matches!(
            verify_digest(b"x", "SHA-512=AAAA"),
            Err(VerifyError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn a_signature_from_a_real_key_verifies_and_a_tampered_body_does_not() {
        let (private, pem) = key_pair();
        let body = br#"{"type":"Follow"}"#;
        let digest = digest_header(body);
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let params = SignatureParams {
            key_id: "https://a/b#main-key".to_owned(),
            algorithm: "rsa-sha256".to_owned(),
            headers: vec![
                "(request-target)".to_owned(),
                "host".to_owned(),
                "date".to_owned(),
                "digest".to_owned(),
            ],
            signature: Vec::new(),
        };
        let headers = vec![
            ("host".to_owned(), "us.test".to_owned()),
            ("date".to_owned(), date.to_owned()),
            ("digest".to_owned(), digest.clone()),
        ];
        let signing = signing_string(&params, "POST", "/users/u/inbox", |name| {
            headers
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        })
        .expect("signing string");
        let signed = SigningKey::<Sha256>::new(private).sign(signing.as_bytes());
        let header = format!(
            "keyId=\"https://a/b#main-key\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\"{}\"",
            BASE64.encode(signed.to_bytes())
        );
        let request_headers = vec![
            ("host".to_owned(), "us.test".to_owned()),
            ("date".to_owned(), date.to_owned()),
            ("digest".to_owned(), digest),
            ("signature".to_owned(), header),
        ];
        let now = DateTime::parse_from_rfc2822(date).expect("date").with_timezone(&Utc);

        let request = SignedRequest {
            method: "POST",
            path: "/users/u/inbox",
            headers: &request_headers,
            body,
            actor_key_pem: &pem,
            now,
        };
        assert!(verify(&request).is_ok());

        let tampered = SignedRequest { body: br#"{"type":"Unfollow"}"#, ..request };
        assert!(matches!(verify(&tampered), Err(VerifyError::DigestMismatch)));
    }

    #[test]
    fn a_signature_older_than_the_window_is_refused() {
        let (_private, pem) = key_pair();
        let headers = vec![
            ("host".to_owned(), "us.test".to_owned()),
            ("date".to_owned(), "Sun, 06 Nov 1994 08:49:37 GMT".to_owned()),
            (
                "signature".to_owned(),
                "keyId=\"k\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"AAAA\""
                    .to_owned(),
            ),
        ];
        let request = SignedRequest {
            method: "GET",
            path: "/x",
            headers: &headers,
            body: b"",
            actor_key_pem: &pem,
            now: Utc::now(),
        };
        assert!(matches!(verify(&request), Err(VerifyError::StaleDate)));
    }
}

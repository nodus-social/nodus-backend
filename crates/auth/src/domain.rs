//! OAuth and session rules that do not depend on storage or HTTP.
//!
//! The auth service is deliberately small: it validates one authorization request,
//! checks a password, issues an opaque token and renders the pages around those steps.
//! Everything that can be decided without I/O lives here so it can be tested without a
//! database or a browser.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore as _;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

/// The only grant type this service issues.
pub const AUTHORIZATION_CODE: &str = "authorization_code";
/// The only PKCE method accepted.
pub const S256: &str = "S256";
/// Cookie holding the per-browser CSRF nonce.
pub const CSRF_COOKIE: &str = "nodus_csrf";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("redirect_uri is not registered for this client")]
    RedirectUri,
    #[error("response_type must be code")]
    ResponseType,
    #[error("code_challenge_method must be S256")]
    PkceMethod,
    #[error("code_verifier does not match the challenge")]
    Pkce,
    #[error("a required parameter is missing: {0}")]
    Missing(&'static str),
}

/// A validated `/oauth/authorize` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub code_challenge: String,
}

impl AuthorizeRequest {
    pub fn parse(query: &[(String, String)]) -> Result<Self, Error> {
        let get = |name: &str| {
            query
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        let client_id = get("client_id").ok_or(Error::Missing("client_id"))?;
        let redirect_uri = get("redirect_uri").ok_or(Error::Missing("redirect_uri"))?;
        let response_type = get("response_type").ok_or(Error::Missing("response_type"))?;
        if response_type != "code" {
            return Err(Error::ResponseType);
        }
        let code_challenge = get("code_challenge").ok_or(Error::Missing("code_challenge"))?;
        if get("code_challenge_method").as_deref() != Some(S256) {
            return Err(Error::PkceMethod);
        }
        Ok(Self {
            client_id,
            redirect_uri,
            response_type,
            scopes: get("scope").map_or_else(
                || vec!["read".to_owned()],
                |scope| scope.split_whitespace().map(str::to_owned).collect(),
            ),
            state: get("state"),
            code_challenge,
        })
    }
}

/// Checks a registered redirect against the exact URI the client asked for.
pub fn redirect_allowed(registered: &[String], requested: &str) -> bool {
    is_safe_redirect_uri(requested) && registered.iter().any(|uri| uri == requested)
}

/// Whether `uri` is a safe OAuth redirect URI.
///
/// Three shapes are accepted, because three shapes are in use: `http`/`https` with a
/// host (web clients), `urn:` identifiers (the OOB flow and Assa's `ugc` variant that
/// Mastodon also accepts), and an app's own custom scheme such as
/// `org.joinmastodon.android:`. Schemes that hand code to a document rather than to an
/// app — `javascript`, `data`, `vbscript`, `file`, `about` — are refused: a redirect is
/// a place to deliver a code, not a program to run.
#[must_use]
pub fn is_safe_redirect_uri(uri: &str) -> bool {
    if is_safe_http_url(uri) {
        return true;
    }
    let Some((scheme, rest)) = uri.split_once(':') else {
        return false;
    };
    let scheme = scheme.to_ascii_lowercase();
    if matches!(
        scheme.as_str(),
        "javascript" | "data" | "vbscript" | "file" | "about" | "blob"
    ) {
        return false;
    }
    if !rest.is_empty() && scheme == "urn" {
        return rest.split(':').filter(|part| !part.is_empty()).count() >= 2;
    }
    // A custom scheme: a valid scheme name followed by anything at all, since the shape
    // of an app URI is the app's business.
    !scheme.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && !rest.is_empty()
}

/// Whether `uri` is an `http` or `https` URL with a host.
#[must_use]
pub fn is_safe_http_url(uri: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https") && url.has_host()
}

/// Whether `scope` grants or refers to administrator privileges.
#[must_use]
pub fn is_admin_scope(scope: &str) -> bool {
    scope == "admin" || scope.starts_with("admin:")
}

/// Whether `scope` is a syntactically valid Mastodon OAuth scope.
#[must_use]
pub fn is_valid_scope(scope: &str) -> bool {
    if matches!(
        scope,
        "read" | "write" | "follow" | "push" | "admin" | "admin:read" | "admin:write"
    ) {
        return true;
    }
    let Some(rest) = scope
        .strip_prefix("admin:read:")
        .or_else(|| scope.strip_prefix("admin:write:"))
        .or_else(|| scope.strip_prefix("read:"))
        .or_else(|| scope.strip_prefix("write:"))
    else {
        return false;
    };
    !rest.is_empty()
        && rest.split(':').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

/// Appends `code`/`state` (or an OAuth error) to the client's redirect URI.
pub fn redirect_with(uri: &str, code: &str, state: Option<&str>) -> Result<String, Error> {
    if !is_safe_redirect_uri(uri) {
        return Err(Error::RedirectUri);
    }
    let mut url = Url::parse(uri).map_err(|_| Error::RedirectUri)?;
    if url.cannot_be_a_base() {
        // A `urn:` identifier has no query to set, so the parameters go on the end of
        // the identifier itself — which is how Mastodon's OOB flow hands back a code.
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("code", code);
        if let Some(state) = state {
            query.append_pair("state", state);
        }
        let base = uri.split(['?', '#']).next().unwrap_or(uri);
        return Ok(format!("{base}?{}", query.finish()));
    }
    url.query_pairs_mut().append_pair("code", code);
    if let Some(state) = state {
        url.query_pairs_mut().append_pair("state", state);
    }
    Ok(url.into())
}

/// Constant-time byte slice comparison.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Derives the expected CSRF form token for `nonce` and an optional authenticated session secret.
#[must_use]
pub fn csrf_token(nonce: &str, session_secret: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"nodus-csrf-v1:");
    if let Some(secret) = session_secret {
        hasher.update(secret.as_bytes());
    }
    hasher.update(b":");
    hasher.update(nonce.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Verifies a submitted CSRF form token against the `nodus_csrf` cookie and optional session secret.
#[must_use]
pub fn verify_csrf(
    cookie_nonce: Option<&str>,
    submitted_token: Option<&str>,
    session_secret: Option<&str>,
) -> bool {
    let (Some(nonce), Some(submitted)) = (cookie_nonce, submitted_token) else {
        return false;
    };
    if nonce.is_empty() || submitted.is_empty() {
        return false;
    }
    let expected = csrf_token(nonce, session_secret);
    constant_time_eq(expected.as_bytes(), submitted.as_bytes())
}

/// A random, URL-safe opaque token. Only its hash is stored.
#[must_use]
pub fn opaque_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[must_use]
pub fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    format!("{digest:x}")
}

/// Verifies an RFC 7636 `S256` challenge.
pub fn verify_pkce(verifier: &str, challenge: &str) -> Result<(), Error> {
    let digest = Sha256::digest(verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(digest);
    if computed == challenge {
        Ok(())
    } else {
        Err(Error::Pkce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_accepts_the_matching_verifier_and_rejects_another() {
        let verifier = "a".repeat(43);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert!(verify_pkce(&verifier, &challenge).is_ok());
        assert_eq!(verify_pkce(&"b".repeat(43), &challenge), Err(Error::Pkce));
    }

    #[test]
    fn an_authorize_request_requires_s256_and_code() {
        let query = vec![
            ("client_id".to_owned(), "app".to_owned()),
            (
                "redirect_uri".to_owned(),
                "https://client.test/cb".to_owned(),
            ),
            ("response_type".to_owned(), "token".to_owned()),
            ("code_challenge".to_owned(), "x".to_owned()),
            ("code_challenge_method".to_owned(), "S256".to_owned()),
        ];
        assert_eq!(AuthorizeRequest::parse(&query), Err(Error::ResponseType));
    }

    #[test]
    fn redirects_must_match_exactly() {
        assert!(redirect_allowed(
            &["https://client.test/cb".to_owned()],
            "https://client.test/cb"
        ));
        assert!(!redirect_allowed(
            &["https://client.test/cb".to_owned()],
            "https://client.test/cb/extra"
        ));
    }

    #[test]
    fn redirect_uris_cover_the_shapes_clients_register() {
        // Web clients.
        assert!(is_safe_redirect_uri("https://client.test/cb"));
        assert!(is_safe_redirect_uri("http://localhost:5173/cb"));
        // The OOB flow, and the `ugc` variant Mastodon also accepts.
        assert!(is_safe_redirect_uri("urn:ietf:wg:oauth:2.0:oob"));
        assert!(is_safe_redirect_uri("urn:ietf:wg:oauth:2.0:ugc"));
        // An app's own scheme.
        assert!(is_safe_redirect_uri(
            "org.joinmastodon.android:/oauth2redirect"
        ));
        assert!(is_safe_redirect_uri("nodus://callback"));
        // A redirect is a place to deliver a code, not a program to run.
        assert!(!is_safe_redirect_uri("javascript:alert(1)"));
        assert!(!is_safe_redirect_uri("data:text/html,<script>"));
        assert!(!is_safe_redirect_uri("vbscript:msgbox"));
        assert!(!is_safe_redirect_uri("file:///etc/passwd"));
        // Nothing at all, and a relative path.
        assert!(!is_safe_redirect_uri(""));
        assert!(!is_safe_redirect_uri("callback"));
        assert!(!is_safe_redirect_uri("urn:"));
    }

    #[test]
    fn a_urn_redirect_carries_the_code_on_the_identifier() {
        let redirect = redirect_with("urn:ietf:wg:oauth:2.0:ugc", "abc123", Some("st"))
            .expect("a urn redirect is allowed");
        assert_eq!(redirect, "urn:ietf:wg:oauth:2.0:ugc?code=abc123&state=st");

        let redirect = redirect_with("https://client.test/cb", "abc123", None)
            .expect("an https redirect is allowed");
        assert_eq!(redirect, "https://client.test/cb?code=abc123");
    }
}

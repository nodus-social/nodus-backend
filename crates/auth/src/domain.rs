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
    registered.iter().any(|uri| uri == requested)
}

/// Appends `code`/`state` (or an OAuth error) to the client's redirect URI.
pub fn redirect_with(uri: &str, code: &str, state: Option<&str>) -> Result<String, Error> {
    let mut url = Url::parse(uri).map_err(|_| Error::RedirectUri)?;
    url.query_pairs_mut().append_pair("code", code);
    if let Some(state) = state {
        url.query_pairs_mut().append_pair("state", state);
    }
    Ok(url.into())
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
}

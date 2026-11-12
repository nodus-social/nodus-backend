//! Bearer authentication as an extractor.
//!
//! A handler that takes `Auth` cannot forget to check the token, and a handler that
//! does not take it cannot accidentally require one. The extractor resolves the token
//! once per request and hands the handler the account and its scopes.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use sha2::{Digest, Sha256};

use nodus_server_store::accounts::{verify_token, Authenticated};

use crate::error::ApiError;
use crate::state::AppState;

/// The authenticated account for this request.
#[derive(Debug, Clone)]
pub struct Auth(pub Authenticated);

impl Auth {
    /// Fails with `403` when the token lacks the scope, naming it — a client that gets
    /// a bare 403 cannot tell whether to re-authorise or give up.
    pub fn require_scope(&self, scope: &str) -> Result<(), ApiError> {
        if self.0.allows(scope) {
            Ok(())
        } else {
            Err(ApiError::forbidden(format!("This action requires the {scope} scope")))
        }
    }
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let raw = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| ApiError::unauthorized("The access token is invalid"))?;
        let token = raw
            .strip_prefix("Bearer ")
            .or_else(|| raw.strip_prefix("bearer "))
            .ok_or_else(|| ApiError::unauthorized("The access token is invalid"))?;
        if token.is_empty() {
            return Err(ApiError::unauthorized("The access token is invalid"));
        }
        let digest = hex_lower(&Sha256::digest(token.as_bytes()));
        let account = verify_token(state.store().pool(), &digest).await?;
        account
            .map(Self)
            .ok_or_else(|| ApiError::unauthorized("The access token is invalid"))
    }
}

/// Lowercase hex, without pulling a crate in for sixteen lines.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing into a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_is_lowercase_hex_of_the_raw_bytes() {
        // "abc" → ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            hex_lower(&Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

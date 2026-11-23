//! Bearer authentication as an extractor.
//!
//! A handler that takes `Auth` cannot forget to check the token, and a handler that
//! does not take it cannot accidentally require one. The extractor resolves the token
//! once per request and hands the handler the account and its scopes.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use sha2::{Digest, Sha256};

use nodus_server_store::accounts::{verify_token, verify_token_any_state, Authenticated};
use nodus_server_store::ip_block;

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
            Err(ApiError::forbidden(format!(
                "This action requires the {scope} scope"
            )))
        }
    }

    /// Requires a staff account — moderator or administrator — holding the given scope.
    ///
    /// The role decides which routes a staff member reaches; the scope decides what this
    /// particular token may do once they are there. A moderator token carries
    /// `admin:read`/`admin:write` exactly like an administrator's, so this check alone
    /// never tells the two apart.
    pub fn require_admin(&self, scope: &str) -> Result<(), ApiError> {
        if self.0.account.staff_role == "none" {
            return Err(ApiError::forbidden("Administrator access is required"));
        }
        self.require_scope(scope)
    }

    /// Requires an administrator, not merely a moderator, holding the given scope.
    ///
    /// This is the second door: a role grant, a scanner, or an email-domain block is not
    /// moderation work, and a moderator who reaches it is told so rather than silently
    /// allowed through.
    pub fn require_administrator(&self, scope: &str) -> Result<(), ApiError> {
        if self.0.account.staff_role != "admin" {
            return Err(ApiError::forbidden(
                "Administrator access is required for this action",
            ));
        }
        self.require_scope(scope)
    }
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts)?;
        let digest = hex_lower(&Sha256::digest(token.as_bytes()));
        let account = verify_token(state.store().pool(), &digest).await?;
        let Some(account) = account else {
            return Err(ApiError::unauthorized("The access token is invalid"));
        };
        // A `no_access` block follows the address, not the token: the address is what the
        // block was written for, and a token issued before the block must stop working the
        // same moment a fresh login would be refused.
        if let Some(ConnectInfo(peer)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() {
            let prefix = nodus_auth::network_prefix(peer.ip());
            if ip_block::no_access(state.store().pool(), &prefix).await? {
                return Err(ApiError::forbidden(
                    "This network is not permitted to use this instance",
                ));
            }
        }
        Ok(Self(account))
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

/// The store's lookup key for a bearer token: lowercase hex of its SHA-256.
///
/// Shared with secure mode, which must recognise our own sessions without rejecting
/// the request the way [`Auth`] does.
pub(crate) fn token_digest(token: &str) -> String {
    hex_lower(&Sha256::digest(token.as_bytes()))
}

/// Resolves one token to an account, for the handler that cannot use the [`Auth`]
/// extractor: `GET /api/v1/streaming` reads `access_token` from the query string because
/// `EventSource` cannot set an `Authorization` header.
///
/// The rules are exactly the extractor's, including refusing a restricted account and
/// answering `401` for anything that does not resolve.
pub(crate) async fn authenticate(state: &AppState, token: &str) -> Result<Authenticated, ApiError> {
    if token.is_empty() {
        return Err(ApiError::unauthorized("The access token is invalid"));
    }
    let digest = token_digest(token);
    verify_token(state.store().pool(), &digest)
        .await?
        .ok_or_else(|| ApiError::unauthorized("The access token is invalid"))
}

/// Refuses posting and following until the account's address is confirmed.
///
/// The switch is off by default and checked before the database: an instance that has
/// not opted in pays nothing. A local account always has a credential row; a missing one
/// (bootstrap, or a remote actor) has no address to confirm, so it is not refused.
pub(crate) async fn require_confirmed_email(
    state: &AppState,
    account_id: &str,
) -> Result<(), ApiError> {
    if !state.require_email_confirmation() {
        return Ok(());
    }
    let confirmed: Option<bool> = sqlx::query_scalar(
        "SELECT confirmed_at IS NOT NULL FROM account_credential WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(state.store().pool())
    .await?;
    if matches!(confirmed, Some(false)) {
        return Err(ApiError::forbidden(
            "Confirm your email address before posting or following. \
             Open the confirmation link in the message we sent you.",
        ));
    }
    Ok(())
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

/// Authentication that is optional: public endpoints use it to personalise a response
/// without rejecting anonymous readers.
#[derive(Debug, Clone)]
pub struct MaybeAuth(pub Option<Auth>);

impl FromRequestParts<AppState> for MaybeAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if parts.headers.get(AUTHORIZATION).is_none() {
            return Ok(Self(None));
        }
        Auth::from_request_parts(parts, state)
            .await
            .map(|auth| Self(Some(auth)))
    }
}

/// Authentication that still resolves when the account is restricted.
///
/// Every other route resolves its token through [`Auth`], whose store predicate refuses
/// a suspended or refused account. That is the correct default, but it would also deny
/// the one person who needs to speak: a suspended person must be able to read their own
/// notifications and answer their own appeal. Only the appeal handlers and the notification
/// list use this extractor; the other notification writes keep the stricter [`Auth`].
#[derive(Debug, Clone)]
pub struct AppealAuth(pub Auth);

impl FromRequestParts<AppState> for AppealAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts)?;
        let digest = hex_lower(&Sha256::digest(token.as_bytes()));
        verify_token_any_state(state.store().pool(), &digest)
            .await?
            .map(|authenticated| Self(Auth(authenticated)))
            .ok_or_else(|| ApiError::unauthorized("The access token is invalid"))
    }
}

/// Authentication for undoing a deletion: alive tokens only, deletion not disqualifying.
///
/// `Auth` refuses a deleted account, which is exactly right everywhere else and useless
/// here: the whole point of the grace window is that a person who proved their identity
/// again can reclaim the account. Tokens revoked by the deletion stay dead, so the old
/// bearer cannot reverse what a thief used it to do; only a token minted afterwards works.
#[derive(Debug, Clone)]
pub struct RecoveryAuth(pub Auth);

impl FromRequestParts<AppState> for RecoveryAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts)?;
        let digest = hex_lower(&Sha256::digest(token.as_bytes()));
        verify_token_any_state(state.store().pool(), &digest)
            .await?
            .map(|authenticated| Self(Auth(authenticated)))
            .ok_or_else(|| ApiError::unauthorized("The access token is invalid"))
    }
}

/// The bearer value from the `Authorization` header, or the one `401` these routes share.
fn bearer(parts: &Parts) -> Result<&str, ApiError> {
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
    Ok(token)
}

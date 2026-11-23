//! Password reset: one endpoint that must not say who has an account, one that spends a
//! single-use link.
//!
//! The request answer is assembled from constants rather than from the lookup result, so
//! a known and an unknown address are byte-identical. The limiter is keyed by the
//! submitted address for the same reason: refusing only real accounts would turn a
//! protective control into the oracle.

use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::domain::{opaque_token, token_hash};
use crate::outbox::Confirmation;
use crate::password_reset_mail::reset_message;
use crate::password_reset_pages::{gone_page, notice_page, request_form, reset_form};
use crate::store::AuthStore;
use crate::{
    csrf_cookie, ensure_csrf, has_valid_csrf, hash_password, issue_session, validated_password,
    AppState, Peer,
};

/// Long enough to survive a slow mail queue, short enough that a link found in an old
/// mailbox is not a standing key. Shorter than the confirmation window because this link
/// changes a credential.
const RESET_MINUTES: i64 = 60;

/// The request answer, shown for every well-formed request.
///
/// It is a constant on purpose: the handler must not build this text from whether the
/// address exists.
const SENT: &str = "If that address has a login, a reset link is on its way. The link is \
                    valid for one hour and can be used once.";

const LIMITED: &str = "Too many reset requests for that address. Try again later.";

#[derive(Debug, Deserialize)]
pub struct ResetRequestForm {
    email: String,
    #[serde(default)]
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetForm {
    password: String,
    password_confirmation: String,
    #[serde(default)]
    csrf_token: String,
}

pub async fn request_page<S: AuthStore>(
    State(state): State<AppState<S>>,
    jar: CookieJar,
) -> (CookieJar, Html<String>) {
    let (jar, csrf_token) = ensure_csrf(jar, None, state.config.secure_cookies);
    (jar, Html(request_form(&csrf_token)))
}

/// Answers every request with the same page, whether or not the address has a login.
pub async fn request_submit<S: AuthStore>(
    State(state): State<AppState<S>>,
    jar: CookieJar,
    Form(form): Form<ResetRequestForm>,
) -> Response {
    if !has_valid_csrf(&jar, Some(form.csrf_token.as_str()), None) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    let email = form.email.trim();
    let allowed = state
        .store
        .allow_password_reset_request(email)
        .await
        .unwrap_or_else(|error| {
            tracing::error!(%error, "password reset limiter failed");
            false
        });
    if !allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html(notice_page("Too many requests · Nodus", LIMITED)),
        )
            .into_response();
    }

    // The lookup and the enqueue happen only on the existing-account path, but nothing
    // about their outcome changes the answer below. A failed queue write is logged and
    // still answered as sent: telling the caller the mail failed would confirm existence.
    match state.store.credential_by_email(email).await {
        Ok(Some(credential)) => {
            if state.email_confirmation.is_some() {
                let token = opaque_token();
                let reset = Confirmation {
                    token_hash: token_hash(&token),
                    expires_at: Utc::now() + Duration::minutes(RESET_MINUTES),
                    message: reset_message(&state, &credential.username, &credential.email, &token),
                };
                if let Err(error) = state
                    .store
                    .enqueue_password_reset(&credential.account_id, reset)
                    .await
                {
                    tracing::error!(%error, "password reset mail was not queued");
                }
            }
        }
        Ok(None) => {}
        Err(error) => tracing::error!(%error, "password reset lookup failed"),
    }

    (
        StatusCode::OK,
        Html(notice_page("Check your mail · Nodus", SENT)),
    )
        .into_response()
}

pub async fn form_page<S: AuthStore>(
    State(state): State<AppState<S>>,
    Path(token): Path<String>,
    jar: CookieJar,
) -> Response {
    if state
        .store
        .password_reset_account(&token_hash(&token))
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return gone_page();
    }
    let (jar, csrf_token) = ensure_csrf(jar, None, state.config.secure_cookies);
    (jar, Html(reset_form(&token, &csrf_token, None))).into_response()
}

pub async fn form_submit<S: AuthStore>(
    State(state): State<AppState<S>>,
    Path(token): Path<String>,
    jar: CookieJar,
    headers: HeaderMap,
    peer: Peer,
    Form(form): Form<ResetForm>,
) -> Response {
    if !has_valid_csrf(&jar, Some(form.csrf_token.as_str()), None) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    let token_hash = token_hash(&token);
    // Check the link before the password so an expired link says "expired" rather than
    // handing back a form whose only possible next attempt will also expire.
    if state
        .store
        .password_reset_account(&token_hash)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return gone_page();
    }
    if let Err(message) = validated_password(&form.password, &form.password_confirmation) {
        let (jar, csrf_token) = ensure_csrf(jar, None, state.config.secure_cookies);
        return (jar, Html(reset_form(&token, &csrf_token, Some(message)))).into_response();
    }
    let Ok(password_hash) = hash_password(&form.password) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "password could not be hashed",
        )
            .into_response();
    };
    let Some(account_id) = state
        .store
        .complete_password_reset(&token_hash, &password_hash)
        .await
        .ok()
        .flatten()
    else {
        return gone_page();
    };
    // Every session was deleted in the same transaction. The one minted here is therefore
    // the only surviving session for the account; if minting fails, the account is left
    // signed out everywhere, which is the safe side of that failure.
    let Ok(cookie) = issue_session(&state, &account_id, &headers, peer).await else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "password changed, but a new session could not be stored",
        )
            .into_response();
    };
    let rotated_csrf = csrf_cookie(opaque_token(), state.config.secure_cookies);
    (jar.add(cookie).add(rotated_csrf), Redirect::to("/")).into_response()
}

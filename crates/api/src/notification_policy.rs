//! `GET|PUT /api/v2/notifications/policy` — the Notifications tab's policy.
//!
//! The body is Mastodon's flat map of kind to answer: `mention`, `favourite`, `reblog`,
//! `follow`, `follow_request`, `report`, `pending_request`, `status`, each one of
//! `accept`, `filter` or `drop`. A PUT names only the kinds it changes, so a client editing
//! one switch does not have to send the rest back.
//!
//! The policy is enforced where the notification row is written, not where it is read: a
//! `drop` writes nothing, a `filter` writes a row marked `filtered`, and the ordinary inbox
//! excludes that flag (`?filtered=true` shows it).

use std::collections::BTreeMap;

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use nodus_server_store::notification_policy::{self, KINDS, VALUES};

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// `GET /api/v2/notifications/policy`
///
/// Answers every known kind, including the ones this account has never changed, so a client
/// draws the whole tab from one answer.
pub async fn show(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<BTreeMap<String, String>>> {
    auth.require_scope("read:notifications")?;
    let policy = notification_policy::load(state.store().pool(), &auth.0.account.id).await?;
    Ok(Json(policy))
}

/// `PUT /api/v2/notifications/policy`
///
/// An unknown kind or an unknown answer is a `422` naming it: silently ignoring either would
/// leave the reader believing a switch took effect when it did not.
pub async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Json(body): Json<BTreeMap<String, Value>>,
) -> ApiResult<Json<Value>> {
    auth.require_scope("write:notifications")?;
    let mut changes = BTreeMap::new();
    for (kind, value) in body {
        if !KINDS.contains(&kind.as_str()) {
            return Err(ApiError::unprocessable(format!(
                "unknown notification type: {kind}"
            )));
        }
        let Some(policy) = value.as_str() else {
            return Err(ApiError::unprocessable(format!(
                "unknown policy for {kind}: {value}; allowed values are accept, filter and drop"
            )));
        };
        if !VALUES.contains(&policy) {
            return Err(ApiError::unprocessable(format!(
                "unknown policy for {kind}: {policy}; allowed values are accept, filter and drop"
            )));
        }
        changes.insert(kind, policy.to_owned());
    }
    notification_policy::save(state.store().pool(), &auth.0.account.id, &changes).await?;
    Ok(Json(json!({})))
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::get;
    axum::Router::new().route("/api/v2/notifications/policy", get(show).put(update))
}

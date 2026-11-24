//! `POST|GET|PUT|DELETE /api/v1/push/subscription` — the browser's Web Push registration.
//!
//! This is slice 1 of Web Push: the store and its API. Delivering a notification and
//! encrypting its payload are slice 2; nothing here sends anything.
//!
//! Shape, read from Mastodon 4.6's REST serializer: the subscription entity is
//! `{"id", "endpoint", "server_key", "alerts"}`, and `alerts` is an **object** of booleans
//! keyed by notification kind (`{"mention": true, "admin.sign_up": false, …}`), not a
//! bitmask. Upstream stores the alert names as an array internally but serializes the
//! object a client draws checkboxes from, so this instance stores and returns the object
//! verbatim. `server_key` is deliberately absent: this slice has no VAPID public key to
//! send, and inventing one would be worse than omitting a field slice 2 will add with the
//! key itself.
//!
//! The request body is the same nesting Mastodon's form parameters use:
//! `subscription[endpoint]`, `subscription[keys][p256dh]`, `subscription[keys][auth]`,
//! `data[alerts][mention]`. `JsonOrForm<T>` cannot express nested keys, so the body is read
//! by hand: `application/x-www-form-urlencoded` is parsed key-by-key, everything else is
//! JSON with the identical nesting (`{"subscription": {"endpoint": …, "keys": {…}},
//! "data": {"alerts": {…}}}`).
//!
//! One subscription per (account, endpoint): a second POST to the same endpoint is
//! idempotent, updating the keys in place (browsers rotate keys under a stable endpoint).
//! `GET` answers the newest row or Mastodon's `404 {"error":"Record not found"}`; `PUT`
//! changes alerts only; `DELETE` is `204` whether or not a row was there.

use std::collections::BTreeMap;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::{body::Bytes, Json};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use nodus_server_store::push;

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// The alert kinds in Mastodon's `Web::PushSubscription::ALERTS`.
///
/// `admin.sign_up` and `admin.report` keep their dots because that is the key Mastodon's
/// serializer emits and its clients send; the rest are lower snake case.
pub const ALERTS: [&str; 10] = [
    "mention",
    "reblog",
    "follow",
    "follow_request",
    "favourite",
    "poll",
    "status",
    "update",
    "admin.sign_up",
    "admin.report",
];

/// The entity a client reads back.
#[derive(Debug, Serialize)]
pub struct SubscriptionDto {
    pub id: String,
    pub endpoint: String,
    pub alerts: Value,
}

impl From<push::SubscriptionRow> for SubscriptionDto {
    fn from(row: push::SubscriptionRow) -> Self {
        Self {
            id: row.id,
            endpoint: row.endpoint,
            alerts: row.alerts,
        }
    }
}

/// The Mastodon-shaped request body, used for JSON and filled field-by-field from a form.
#[derive(Debug, Default, Deserialize)]
struct SubscriptionBody {
    #[serde(default)]
    subscription: SubscriptionPart,
    #[serde(default)]
    data: DataPart,
}

#[derive(Debug, Default, Deserialize)]
struct SubscriptionPart {
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    keys: KeysPart,
}

#[derive(Debug, Default, Deserialize)]
struct KeysPart {
    #[serde(default)]
    p256dh: String,
    #[serde(default)]
    auth: String,
}

#[derive(Debug, Default, Deserialize)]
struct DataPart {
    #[serde(default)]
    alerts: BTreeMap<String, Value>,
}

/// `POST /api/v1/push/subscription`
///
/// Idempotent on the endpoint: the second POST of the same endpoint answers the same `id`
/// with the new keys and alerts. Both key columns are required, because a subscription
/// without them can never be encrypted to.
pub async fn create(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<SubscriptionDto>> {
    auth.require_scope("push")?;
    let input = parse_body(&headers, &body)?;
    let endpoint = required(&input.subscription.endpoint, "subscription[endpoint]")?;
    let p256dh = required(
        &input.subscription.keys.p256dh,
        "subscription[keys][p256dh]",
    )?;
    let auth_key = required(&input.subscription.keys.auth, "subscription[keys][auth]")?;
    let alerts = resolve_alerts(&input.data.alerts, None)?;
    let user_agent = user_agent(&headers);

    let row = push::upsert(
        state.store().pool(),
        &auth.0.account.id,
        endpoint,
        p256dh,
        auth_key,
        &alerts,
        user_agent.as_deref(),
    )
    .await?;
    Ok(Json(row.into()))
}

/// `GET /api/v1/push/subscription` — the newest subscription, or Mastodon's 404.
pub async fn show(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<SubscriptionDto>> {
    auth.require_scope("push")?;
    let row = push::get(state.store().pool(), &auth.0.account.id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    Ok(Json(row.into()))
}

/// `PUT /api/v1/push/subscription` — alerts only; keys and endpoint are untouched.
///
/// A kind the body omits keeps its stored answer, so a client editing one switch does not
/// silently disable every other kind.
pub async fn update(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<SubscriptionDto>> {
    auth.require_scope("push")?;
    let input = parse_body(&headers, &body)?;
    let current = push::get(state.store().pool(), &auth.0.account.id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let alerts = resolve_alerts(&input.data.alerts, Some(&current.alerts))?;
    let row = push::update_alerts(state.store().pool(), &auth.0.account.id, &alerts)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    Ok(Json(row.into()))
}

/// `DELETE /api/v1/push/subscription` — `204` even when there was nothing to remove.
pub async fn destroy(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    auth.require_scope("push")?;
    let input = parse_body(&headers, &body)?;
    let endpoint = required(&input.subscription.endpoint, "subscription[endpoint]")?;
    push::delete(state.store().pool(), &auth.0.account.id, endpoint).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::get;
    axum::Router::new().route(
        "/api/v1/push/subscription",
        get(show).post(create).put(update).delete(destroy),
    )
}

fn parse_body(headers: &HeaderMap, body: &Bytes) -> ApiResult<SubscriptionBody> {
    let form_encoded = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("application/x-www-form-urlencoded")
        });
    if !form_encoded {
        if body.is_empty() {
            return Ok(SubscriptionBody::default());
        }
        return serde_json::from_slice(body)
            .map_err(|error| ApiError::unprocessable(format!("invalid request body: {error}")));
    }

    let mut input = SubscriptionBody::default();
    for (key, value) in url::form_urlencoded::parse(body) {
        match key.as_ref() {
            "subscription[endpoint]" => input.subscription.endpoint = value.into_owned(),
            "subscription[keys][p256dh]" => input.subscription.keys.p256dh = value.into_owned(),
            "subscription[keys][auth]" => input.subscription.keys.auth = value.into_owned(),
            name if name.starts_with("data[alerts][") && name.ends_with(']') => {
                let kind = &name["data[alerts][".len()..name.len() - 1];
                input
                    .data
                    .alerts
                    .insert(kind.to_owned(), Value::Bool(truthy(&value)));
            }
            _ => {}
        }
    }
    Ok(input)
}

fn required<'a>(value: &'a str, field: &str) -> ApiResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::unprocessable(format!("{field} is required")));
    }
    Ok(trimmed)
}

/// Merges the sent alert flags over the base map (all-enabled for a POST, the stored map for
/// a PUT). An unknown kind or a non-boolean answer is a `422` naming it: silently dropping
/// either would leave a reader believing a switch took effect when it did not.
fn resolve_alerts(given: &BTreeMap<String, Value>, base: Option<&Value>) -> ApiResult<Value> {
    let mut resolved = Map::new();
    if let Some(Value::Object(stored)) = base {
        for (kind, value) in stored {
            resolved.insert(kind.clone(), value.clone());
        }
    } else {
        for kind in ALERTS {
            resolved.insert(kind.to_owned(), Value::Bool(true));
        }
    }
    for (kind, value) in given {
        if !ALERTS.contains(&kind.as_str()) {
            return Err(ApiError::unprocessable(format!(
                "unknown alert kind: {kind}"
            )));
        }
        let Some(flag) = value.as_bool() else {
            return Err(ApiError::unprocessable(format!(
                "alert {kind} must be true or false"
            )));
        };
        resolved.insert(kind.clone(), Value::Bool(flag));
    }
    Ok(Value::Object(resolved))
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(512).collect())
}

fn truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "on"
    )
}

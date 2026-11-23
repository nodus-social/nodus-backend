//! Per-account posting and reading preferences.
//!
//! Mastodon returns a flat object of `key: value` pairs. We answer the nine keys this
//! instance knows: the six posting/reading switches it always answered, the notification
//! switches stored only for round-tripping, and v4.6.3's `posting:default:quote_policy`.
//! A client that PUTs the map it read must not get a `422` because the server skipped a
//! key, so unknown keys are refused but every key a supported client sends is known.
//!
//! `PUT` accepts a partial body: a client editing one switch does not send the other
//! eight back. The reply is the whole map, whether the request changed one key or all of
//! them, so the caller never has to merge its own request into a remembered copy.

use std::collections::BTreeMap;

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use nodus_server_store::preferences::{
    is_language_code, Preferences, EXPAND_MEDIA, QUOTE_POLICIES, VISIBILITIES,
};

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// `GET /api/v1/preferences`
pub async fn show(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Value>> {
    auth.require_scope("read:accounts")?;
    let preferences = state.store().preferences(&auth.0.account.id).await?;
    Ok(Json(wire(&preferences)))
}

/// `PUT /api/v1/preferences`
///
/// An unknown key or an invalid value is a `422` naming it: silently ignoring either would
/// leave the reader believing a switch took effect when it did not.
pub async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Json(body): Json<BTreeMap<String, Value>>,
) -> ApiResult<Json<Value>> {
    auth.require_scope("write:accounts")?;
    let mut preferences = state.store().preferences(&auth.0.account.id).await?;
    for (key, value) in &body {
        apply(&mut preferences, key, value)?;
    }
    state
        .store()
        .save_preferences(&auth.0.account.id, &preferences)
        .await?;
    Ok(Json(wire(&preferences)))
}

/// The flat document Mastodon and the settings shell read.
fn wire(preferences: &Preferences) -> Value {
    json!({
        "posting:default:visibility": preferences.visibility,
        "posting:default:sensitive": preferences.sensitive,
        "posting:default:language": preferences.language,
        "posting:default:quote_policy": preferences.quote_policy,
        "reading:expand:media": preferences.expand_media,
        "reading:expand:spoilers": preferences.expand_spoilers,
        "reading:autoplay:gifs": preferences.autoplay_gifs,
        "notification:email": preferences.notification_email,
        "notification:report": preferences.notification_report,
    })
}

/// Applies one requested key, or refuses it by name.
fn apply(preferences: &mut Preferences, key: &str, value: &Value) -> Result<(), ApiError> {
    match key {
        "posting:default:visibility" => {
            let Some(visibility) = value.as_str() else {
                return Err(invalid(key, value, "public, unlisted, private and direct"));
            };
            if !VISIBILITIES.contains(&visibility) {
                return Err(invalid(key, value, "public, unlisted, private and direct"));
            }
            visibility.clone_into(&mut preferences.visibility);
        }
        "posting:default:sensitive" => preferences.sensitive = boolean(key, value)?,
        "posting:default:language" => {
            preferences.language = match value {
                Value::Null => None,
                Value::String(code) if is_language_code(code) => Some(code.clone()),
                _ => {
                    return Err(invalid(
                        key,
                        value,
                        "null or an ISO 639 code such as en or zh-CN",
                    ));
                }
            };
        }
        "posting:default:quote_policy" => {
            let Some(quote_policy) = value.as_str() else {
                return Err(invalid(key, value, "public, followers and nobody"));
            };
            if !QUOTE_POLICIES.contains(&quote_policy) {
                return Err(invalid(key, value, "public, followers and nobody"));
            }
            quote_policy.clone_into(&mut preferences.quote_policy);
        }
        "reading:expand:media" => {
            let Some(expand_media) = value.as_str() else {
                return Err(invalid(key, value, "default, show_all and hide_all"));
            };
            if !EXPAND_MEDIA.contains(&expand_media) {
                return Err(invalid(key, value, "default, show_all and hide_all"));
            }
            expand_media.clone_into(&mut preferences.expand_media);
        }
        "reading:expand:spoilers" => preferences.expand_spoilers = boolean(key, value)?,
        "reading:autoplay:gifs" => preferences.autoplay_gifs = boolean(key, value)?,
        "notification:email" => preferences.notification_email = boolean(key, value)?,
        "notification:report" => preferences.notification_report = boolean(key, value)?,
        _ => {
            return Err(ApiError::unprocessable(format!(
                "unknown preference: {key}"
            )))
        }
    }
    Ok(())
}

fn boolean(key: &str, value: &Value) -> Result<bool, ApiError> {
    value
        .as_bool()
        .ok_or_else(|| invalid(key, value, "true and false"))
}

fn invalid(key: &str, value: &Value, allowed: &str) -> ApiError {
    ApiError::unprocessable(format!(
        "invalid value for {key}: {value}; allowed values are {allowed}"
    ))
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::get;
    axum::Router::new().route("/api/v1/preferences", get(show).put(update))
}

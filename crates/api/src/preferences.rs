//! Per-account posting preferences.
//!
//! Mastodon returns a flat object of `key: value` pairs. We answer with defaults an
//! account has not overridden — the alternative, storing nothing and returning `{}`,
//! makes every client pick its own fallbacks, which is how clients drift from each other.

use axum::extract::State;
use axum::Json;
use serde_json::json;

use crate::auth::Auth;
use crate::error::ApiResult;
use crate::state::AppState;

/// `GET /api/v1/preferences`
pub async fn show(
    State(_state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_scope("read:accounts")?;
    // `Default` values are Mastodon's own: new posts are public, languages are never
    // auto-filled, and boosts are visible on the profile.
    Ok(Json(json!({
        "posting:default:visibility": "public",
        "posting:default:sensitive": false,
        "posting:default:language": serde_json::Value::Null,
        "reading:expand:media": "default",
        "reading:expand:spoilers": false,
        "reading:autoplay:gifs": false,
    })))
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::get;
    axum::Router::new().route("/api/v1/preferences", get(show))
}

//! Who to follow next, for `GET /api/v2/suggestions`.
//!
//! Mastodon's recommender is an optional integration; this server answers from its own
//! rows so the screen is never a 404 when the recommender is absent or slow. The query
//! is deliberately simple — recently active local accounts by follower count — and the
//! doc on the store function says why that is preferable to leaving the route unserved.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use nodus_server_core::limits::PAGE_MAX_ACCOUNTS;
use nodus_server_core::PageSize;

use crate::auth::Auth;
use crate::dto::{accounts_with_pictures, AccountDto};
use crate::error::ApiResult;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct SuggestionDto {
    pub account: AccountDto,
    /// Mastodon's most specific reason for the suggestion.
    pub source: String,
    pub sources: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SuggestionQuery {
    #[serde(default)]
    pub limit: Option<u32>,
}

/// `GET /api/v2/suggestions`
pub async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<SuggestionQuery>,
) -> ApiResult<Json<Vec<SuggestionDto>>> {
    auth.require_scope("read:accounts")?;
    let size = PageSize::clamp(query.limit, PAGE_MAX_ACCOUNTS);
    let rows = nodus_server_store::accounts::suggestions(
        state.store().pool(),
        &auth.0.account.id,
        i64::from(size.get()),
    )
    .await?;
    let ids: Vec<String> = rows.iter().map(|row| row.id.clone()).collect();
    let pictures = state.store().batch().profile_pictures(&ids).run().await?;
    Ok(Json(
        accounts_with_pictures(&rows, &pictures, state.instance())
            .into_iter()
            .map(|account| SuggestionDto {
                account,
                source: "recent_activity".to_owned(),
                sources: vec!["recent_activity".to_owned()],
            })
            .collect(),
    ))
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    axum::Router::new().route("/api/v2/suggestions", axum::routing::get(list))
}

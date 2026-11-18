//! Follow requests, for accounts that require approval.
//!
//! A locked account keeps an incoming follow `pending` instead of `accepted`; this module
//! is the reader's view of those pending rows and the two decisions they can make. The
//! state machine lives in the store (`social::accept_follow` / `reject_follow`), which is
//! also what federation calls when a remote instance answers a request for us.

use axum::extract::{Path, State};
use axum::Json;

use nodus_server_core::limits::PAGE_MAX;
use nodus_server_core::pagination::PageSize;

use crate::auth::Auth;
use crate::dto::AccountDto;
use crate::error::ApiResult;
use crate::state::AppState;

/// `GET /api/v1/follow_requests`
pub async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<AccountDto>>> {
    auth.require_scope("read:follows")?;
    let rows = nodus_server_store::social::follow_requests(
        state.store().pool(),
        &auth.0.account.id,
        i64::from(PageSize::clamp(None, PAGE_MAX).get()),
    )
    .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        if let Some(account) =
            nodus_server_store::accounts::by_id(state.store().pool(), &row.account_id).await?
        {
            items.push(AccountDto::from_row(&account, state.instance()));
        }
    }
    Ok(Json(items))
}

/// `POST /api/v1/follow_requests/{id}/authorize`
pub async fn authorize(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_scope("write:follows")?;
    let accepted =
        nodus_server_store::social::accept_follow(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    if accepted {
        crate::outbox::deliver_follow_response(&state, &auth.0.account.id, &id, true, None).await;
    }
    Ok(Json(serde_json::json!({})))
}

/// `POST /api/v1/follow_requests/{id}/reject`
pub async fn reject(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_scope("write:follows")?;
    let rejected =
        nodus_server_store::social::reject_follow(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    if rejected {
        crate::outbox::deliver_follow_response(&state, &auth.0.account.id, &id, false, None).await;
    }
    Ok(Json(serde_json::json!({})))
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/api/v1/follow_requests", get(list))
        .route("/api/v1/follow_requests/{id}/authorize", post(authorize))
        .route("/api/v1/follow_requests/{id}/reject", post(reject))
}

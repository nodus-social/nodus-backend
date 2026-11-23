//! Per-account domain blocks: hiding a host from one reader's timelines.
//!
//! The v1 shape is a bare list of hosts. The v2 shape carries the flags Mastodon's v2
//! payload names (`reject_media`, `reject_reports`) and a `digest`, so a client that asks
//! for v2 never receives bare strings and a v1 client never receives objects.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use nodus_server_store::account_blocks::{self, BlockOptions};
use nodus_server_store::blocks::bare_host;

use crate::auth::Auth;
use crate::body::JsonOrForm;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Mastodon's v2 domain-block object.
#[derive(Debug, Serialize)]
struct DomainBlockDto {
    domain: String,
    /// A stable, opaque identifier for the host, so a client can key on it.
    digest: String,
    reject_media: bool,
    reject_reports: bool,
}

#[derive(Debug, Deserialize)]
struct BlockForm {
    domain: String,
    #[serde(default)]
    reject_media: bool,
    #[serde(default)]
    reject_reports: bool,
}

#[derive(Debug, Deserialize)]
struct UnblockQuery {
    domain: String,
}

/// Refuses anything that is not a bare host name, and the host this instance runs on.
///
/// The normalised form comes from the store's helper, so the route and the store agree on
/// what `Example.Test.` means rather than each lowercasing by hand.
fn normalise_domain(state: &AppState, raw: &str) -> ApiResult<String> {
    let host = bare_host(raw).ok_or_else(|| {
        ApiError::unprocessable(
            "domain must be a bare host name like example.com \
             (no scheme, path, port or user)",
        )
    })?;
    let own = bare_host(&state.instance().domain)
        .unwrap_or_else(|| state.instance().domain.trim().to_ascii_lowercase());
    if host == own {
        return Err(ApiError::unprocessable(
            "you cannot block your own instance's domain",
        ));
    }
    Ok(host)
}

fn digest(host: &str) -> String {
    format!("{:x}", Sha256::digest(host.as_bytes()))
}

/// `GET /api/v1/domain_blocks`: the hosts this token's account blocked.
async fn index_v1(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<String>>> {
    auth.require_scope("read:blocks")?;
    let rows = account_blocks::list(state.store().pool(), &auth.0.account.id).await?;
    Ok(Json(rows.into_iter().map(|row| row.host).collect()))
}

/// `GET /api/v2/domain_blocks`: the same list as objects with the v2 flags.
async fn index_v2(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<Vec<DomainBlockDto>>> {
    auth.require_scope("read:blocks")?;
    let rows = account_blocks::list(state.store().pool(), &auth.0.account.id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| DomainBlockDto {
                digest: digest(&row.host),
                domain: row.host,
                reject_media: row.reject_media,
                reject_reports: row.reject_reports,
            })
            .collect(),
    ))
}

/// `POST /api/v1/domain_blocks` and `/api/v2/domain_blocks`: add a host.
///
/// A repeated add is idempotent and updates the flags; Mastodon answers 200 with an empty
/// body, so this does too.
async fn create(
    State(state): State<AppState>,
    auth: Auth,
    JsonOrForm(form): JsonOrForm<BlockForm>,
) -> ApiResult<StatusCode> {
    auth.require_scope("write:blocks")?;
    let host = normalise_domain(&state, &form.domain)?;
    account_blocks::add(
        state.store().pool(),
        &auth.0.account.id,
        &host,
        BlockOptions {
            reject_media: form.reject_media,
            reject_reports: form.reject_reports,
        },
    )
    .await?;
    Ok(StatusCode::OK)
}

/// `DELETE /api/v1/domain_blocks?domain=...` and the v2 path: remove a host.
///
/// Upstream answers 200 whether or not a row existed, so a client retrying a delete does
/// not have to distinguish the two.
async fn destroy(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<UnblockQuery>,
) -> ApiResult<StatusCode> {
    auth.require_scope("write:blocks")?;
    let host = normalise_domain(&state, &query.domain)?;
    account_blocks::remove(state.store().pool(), &auth.0.account.id, &host).await?;
    Ok(StatusCode::OK)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/domain_blocks",
            get(index_v1).post(create).delete(destroy),
        )
        .route(
            "/api/v2/domain_blocks",
            get(index_v2).post(create).delete(destroy),
        )
}

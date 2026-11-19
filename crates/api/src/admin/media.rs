//! Federated media a content set has acted on, and the decision a moderator makes about it.
//!
//! Ingest hides a matched attachment on its own (see `crate::guard`), which is what stops a
//! hostile picture being visible before anyone looked. It cannot make the judgement call:
//! that is this screen's job. Releasing puts the post back where it was and says so in the
//! audit log; deleting removes the attachment and closes the report as handled. Both are
//! recorded, because the interesting question after one is not "what happened" but "who
//! decided, and why".

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use nodus_server_store::{media, moderation, statuses};

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

use super::{audit_write_detail, page, Body};

/// One attachment a set matched.
#[derive(Debug, Serialize)]
pub struct QuarantinedMediaDto {
    pub id: String,
    pub status_id: Option<String>,
    pub account_id: String,
    pub content_type: String,
    pub url: Option<String>,
    /// The set that matched, which is the name a moderator acts on.
    pub set: Option<String>,
    pub content_hash: Option<String>,
    pub perceptual_hash: Option<String>,
    /// 'quarantined' or 'released'.
    pub state: String,
    pub created_at: DateTime<Utc>,
}

impl From<media::MediaRow> for QuarantinedMediaDto {
    fn from(row: media::MediaRow) -> Self {
        Self {
            id: row.id,
            status_id: row.status_id,
            account_id: row.account_id,
            content_type: row.content_type,
            url: row.remote_url,
            set: row.quarantine_set,
            content_hash: row.content_hash,
            perceptual_hash: row.perceptual_hash,
            state: row.quarantine_state,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LimitQuery {
    limit: Option<i64>,
}

/// `GET /api/v1/admin/media/quarantined` — what the sets have caught, newest first.
async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<LimitQuery>,
) -> ApiResult<Json<Vec<QuarantinedMediaDto>>> {
    auth.require_admin("admin:read")?;
    let rows = media::quarantined(state.store().pool(), page(query.limit)).await?;
    Ok(Json(
        rows.into_iter().map(QuarantinedMediaDto::from).collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct DecisionBody {
    /// `true` puts the post back; `false` removes the attachment.
    release: bool,
    /// Why. Free text, recorded in the audit row and on the report.
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Serialize)]
pub struct DecisionDto {
    pub id: String,
    pub released: bool,
    pub deleted: bool,
    /// The post the attachment belonged to, when it was attached to one.
    pub status_id: Option<String>,
    pub reports_resolved: u64,
}

/// `POST /api/v1/admin/media/{id}/quarantine` — clear a match, one way or the other.
async fn decide(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Body(body): Body<DecisionBody>,
) -> ApiResult<Json<DecisionDto>> {
    auth.require_admin("admin:write")?;
    let pool = state.store().pool();
    let row = media::by_id(pool, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that attachment does not exist"))?;
    if row.quarantine_state == "none" {
        return Err(ApiError::unprocessable(
            "that attachment was not quarantined, so there is nothing to clear",
        ));
    }
    // The decision text travels into the audit row and the report, so it is the moderator's
    // words or a plain statement that there were none — never a silent action.
    let reason = body.reason.trim();
    let note = if reason.is_empty() {
        "Quarantine cleared without a note.".to_owned()
    } else {
        reason.to_owned()
    };

    if body.release {
        media::release_quarantine(pool, &id).await?;
    } else {
        media::delete(pool, &id).await?;
    }

    let mut reports_resolved = 0;
    if let Some(status_id) = row.status_id.as_deref() {
        // The post goes back into the timelines only when nothing else on it is hidden:
        // one cleared picture does not make a post with another quarantined one visible.
        if media::quarantined_count(pool, status_id).await? == 0 {
            statuses::release_quarantine(pool, status_id).await?;
        }
        // Releasing means the post was fine, so the report is dismissed; deleting means it
        // was not, so the report keeps `action_taken`. Either way one report, one decision.
        reports_resolved = moderation::resolve_reports_for_status(
            pool,
            status_id,
            &auth.0.account.id,
            &note,
            !body.release,
        )
        .await?;
    }

    audit_write_detail(
        &state,
        &auth,
        if body.release {
            "release_media_quarantine"
        } else {
            "delete_media_quarantine"
        },
        "media",
        &id,
        json!({
            "status_id": row.status_id,
            "set": row.quarantine_set,
            "reason": reason,
            "reports_resolved": reports_resolved,
        }),
    )
    .await?;

    Ok(Json(DecisionDto {
        id,
        released: body.release,
        deleted: !body.release,
        status_id: row.status_id,
        reports_resolved,
    }))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/media/quarantined", get(list))
        .route("/api/v1/admin/media/{id}/quarantine", post(decide))
}

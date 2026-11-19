//! How moderation is actually performing, in one document.
//!
//! The console polls this while it is open, so the answer is cached for a minute per
//! range. Every section is at most one query: the counts are honest about an instance
//! with no history (`null` median, zero counts) rather than refusing to render.

use axum::extract::{Query, State};
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use nodus_server_store::stats;

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
pub struct StatsQuery {
    /// `7d`, `30d` or `90d`; anything else is a `422` rather than a silently different
    /// window.
    pub range: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportSection {
    pub opened: i64,
    pub resolved: i64,
    pub reopened: i64,
    pub pending: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecisionSection {
    pub approve: i64,
    pub reject: i64,
    pub silence: i64,
    pub suspend: i64,
    pub enable: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReporterEntry {
    pub account_id: String,
    pub username: String,
    pub domain: Option<String>,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainEntry {
    pub domain: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScannerSection {
    pub queued: i64,
    pub flagged: i64,
    pub quarantined: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsDto {
    pub signups: i64,
    pub active_accounts: i64,
    pub posts: i64,
    pub reports: ReportSection,
    pub decisions_by_action: DecisionSection,
    /// `null`, not `0`, when the window holds no decision: there is no median of nothing.
    pub median_time_to_decision_seconds: Option<f64>,
    pub top_reporters: Vec<ReporterEntry>,
    pub top_reported_domains: Vec<DomainEntry>,
    pub scanners: ScannerSection,
}

/// `GET /api/v1/admin/stats?range=7d|30d|90d`
pub async fn stats(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<StatsQuery>,
) -> ApiResult<Json<StatsDto>> {
    auth.require_admin("admin:read")?;
    let (range, days) = match query.range.as_deref().map(str::trim) {
        None | Some("") | Some("30d") => ("30d", 30),
        Some("7d") => ("7d", 7),
        Some("90d") => ("90d", 90),
        Some(_) => {
            return Err(ApiError::unprocessable(
                "Validation failed: range must be 7d, 30d or 90d",
            ))
        }
    };
    // The console refreshes on a timer; a minute of staleness keeps a poll from becoming
    // seven aggregate queries against the same tables the request path is using.
    if let Some(cached) = state.cached_stats(range) {
        return Ok(Json(cached));
    }

    let until = Utc::now();
    let since = until - Duration::days(days);
    let activity = stats::activity(state.store().pool(), since, until).await?;
    let reports = stats::reports(state.store().pool(), since, until).await?;
    let decisions = stats::decisions(state.store().pool(), since, until).await?;
    let median = stats::median_time_to_decision(state.store().pool(), since, until).await?;
    let reporters = stats::top_reporters(state.store().pool(), since, until).await?;
    let domains = stats::top_reported_domains(state.store().pool(), since, until).await?;
    let scanners = stats::scanners(state.store().pool()).await?;

    let value = StatsDto {
        signups: activity.signups,
        active_accounts: activity.active_accounts,
        posts: activity.posts,
        reports: ReportSection {
            opened: reports.opened,
            resolved: reports.resolved,
            reopened: reports.reopened,
            pending: reports.pending,
        },
        decisions_by_action: DecisionSection {
            approve: decisions.approve,
            reject: decisions.reject,
            silence: decisions.silence,
            suspend: decisions.suspend,
            enable: decisions.enable,
        },
        median_time_to_decision_seconds: median,
        top_reporters: reporters
            .into_iter()
            .map(|row| ReporterEntry {
                account_id: row.account_id,
                username: row.username,
                domain: row.domain,
                count: row.count,
            })
            .collect(),
        top_reported_domains: domains
            .into_iter()
            .map(|row| DomainEntry {
                domain: row.domain,
                count: row.count,
            })
            .collect(),
        scanners: ScannerSection {
            queued: scanners.queued,
            flagged: scanners.flagged,
            quarantined: scanners.quarantined,
        },
    };
    state.cache_stats(range, value.clone());
    Ok(Json(value))
}

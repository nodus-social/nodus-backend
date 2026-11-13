//! Reports, audit history, domain policy and account enforcement.
//!
//! Moderation is a server concern: clients read and write it through the Mastodon
//! admin API, but the invariants (who may act, what an action changes, what is
//! recorded) live here so every protocol surface gets the same answer.

use chrono::{DateTime, NaiveDate, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};

use nodus_server_core::Id;

use crate::accounts::AccountRow;

#[derive(Debug, Clone, FromRow)]
pub struct ReportRow {
    pub id: String,
    pub account_id: String,
    pub target_account_id: String,
    pub status_ids: Vec<String>,
    pub category: String,
    pub comment: String,
    pub state: String,
    pub action_taken: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewReport<'a> {
    pub account_id: &'a str,
    pub target_account_id: &'a str,
    pub status_ids: &'a [String],
    pub category: &'a str,
    pub comment: &'a str,
}

pub async fn create_report(pool: &PgPool, new: &NewReport<'_>) -> Result<ReportRow, sqlx::Error> {
    sqlx::query_as(
        "INSERT INTO report (id, account_id, target_account_id, status_ids, category, comment) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, account_id, target_account_id, status_ids, category, comment, state, \
             action_taken, created_at",
    )
    .bind(Id::new().to_string())
    .bind(new.account_id)
    .bind(new.target_account_id)
    .bind(new.status_ids)
    .bind(new.category)
    .bind(new.comment)
    .fetch_one(pool)
    .await
}

pub async fn reports(
    pool: &PgPool,
    state: &str,
    limit: i64,
) -> Result<Vec<ReportRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, account_id, target_account_id, status_ids, category, comment, state, \
             action_taken, created_at \
         FROM report WHERE state = $1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(state)
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn set_report_state(
    pool: &PgPool,
    id: &str,
    state: &str,
) -> Result<Option<ReportRow>, sqlx::Error> {
    sqlx::query_as(
        "UPDATE report SET state = $2, action_taken = ($2 = 'resolved'), updated_at = now() \
         WHERE id = $1 \
         RETURNING id, account_id, target_account_id, status_ids, category, comment, state, \
             action_taken, created_at",
    )
    .bind(id)
    .bind(state)
    .fetch_optional(pool)
    .await
}

pub async fn audit(
    pool: &PgPool,
    actor_id: &str,
    action: &str,
    target_type: &str,
    target_id: Option<&str>,
    detail: &Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (id, actor_id, action, target_type, target_id, detail) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Id::new().to_string())
    .bind(actor_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(detail)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, FromRow)]
pub struct AuditRow {
    pub id: String,
    pub actor_id: Option<String>,
    pub action: String,
    pub target_type: String,
    pub target_id: Option<String>,
    pub detail: Value,
    pub created_at: DateTime<Utc>,
}

pub async fn audit_page(pool: &PgPool, limit: i64) -> Result<Vec<AuditRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, actor_id, action, target_type, target_id, detail, created_at \
         FROM audit_log ORDER BY created_at DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

#[derive(Debug, Clone, FromRow)]
pub struct DomainBlockRow {
    pub id: String,
    pub domain: String,
    pub severity: String,
    pub reject_media: bool,
    pub reject_reports: bool,
    pub obfuscate: bool,
    pub public_comment: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewDomainBlock<'a> {
    pub domain: &'a str,
    pub severity: &'a str,
    pub reject_media: bool,
    pub reject_reports: bool,
    pub obfuscate: bool,
    pub public_comment: &'a str,
}

pub async fn blocks(pool: &PgPool, limit: i64) -> Result<Vec<DomainBlockRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, domain::text AS domain, severity, reject_media, reject_reports, obfuscate, \
             public_comment, created_at \
         FROM instance_block ORDER BY created_at DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn create_block(
    pool: &PgPool,
    new: &NewDomainBlock<'_>,
) -> Result<DomainBlockRow, sqlx::Error> {
    sqlx::query_as(
        "INSERT INTO instance_block (id, domain, severity, reject_media, reject_reports, obfuscate, \
             public_comment) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (domain) DO UPDATE SET severity = EXCLUDED.severity, \
             reject_media = EXCLUDED.reject_media, reject_reports = EXCLUDED.reject_reports, \
             obfuscate = EXCLUDED.obfuscate, public_comment = EXCLUDED.public_comment \
         RETURNING id, domain::text AS domain, severity, reject_media, reject_reports, obfuscate, \
             public_comment, created_at",
    )
    .bind(Id::new().to_string())
    .bind(new.domain)
    .bind(new.severity)
    .bind(new.reject_media)
    .bind(new.reject_reports)
    .bind(new.obfuscate)
    .bind(new.public_comment)
    .fetch_one(pool)
    .await
}

pub async fn delete_block(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM instance_block WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected()
        == 1)
}

pub async fn blocked_domain(
    pool: &PgPool,
    domain: &str,
) -> Result<Option<DomainBlockRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, domain::text AS domain, severity, reject_media, reject_reports, obfuscate, \
             public_comment, created_at \
         FROM instance_block WHERE domain = $1",
    )
    .bind(domain)
    .fetch_optional(pool)
    .await
}

#[derive(Debug, Clone, FromRow)]
pub struct DomainAllowRow {
    pub id: String,
    pub domain: String,
    pub created_at: DateTime<Utc>,
}

pub async fn allows(pool: &PgPool, limit: i64) -> Result<Vec<DomainAllowRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, domain::text AS domain, created_at FROM instance_allow \
         ORDER BY created_at DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn create_allow(pool: &PgPool, domain: &str) -> Result<DomainAllowRow, sqlx::Error> {
    sqlx::query_as(
        "INSERT INTO instance_allow (id, domain) VALUES ($1, $2) \
         ON CONFLICT (domain) DO UPDATE SET domain = EXCLUDED.domain \
         RETURNING id, domain::text AS domain, created_at",
    )
    .bind(Id::new().to_string())
    .bind(domain)
    .fetch_one(pool)
    .await
}

pub async fn delete_allow(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM instance_allow WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected()
        == 1)
}

#[derive(Debug, Clone, FromRow)]
pub struct AdminAccountRow {
    #[sqlx(flatten)]
    pub account: AccountRow,
    pub email: Option<String>,
}

pub async fn admin_accounts(
    pool: &PgPool,
    local: bool,
    pending: bool,
    limit: i64,
) -> Result<Vec<AdminAccountRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.*, c.email::text AS email FROM account a \
         LEFT JOIN account_credential c ON c.account_id = a.id \
         WHERE ($1 = false OR a.local) AND ($2 = false OR (a.local AND NOT a.approved)) \
         ORDER BY a.created_at DESC LIMIT $3",
    )
    .bind(local)
    .bind(pending)
    .bind(limit)
    .fetch_all(pool)
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Approve,
    Reject,
    Silence,
    Suspend,
    Enable,
}

impl Action {
    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "approve" => Self::Approve,
            "reject" | "disable" => Self::Reject,
            "silence" => Self::Silence,
            "suspend" => Self::Suspend,
            "enable" | "unsuspend" | "unsilence" => Self::Enable,
            _ => return None,
        })
    }
}

pub async fn apply_action(
    pool: &PgPool,
    account_id: &str,
    action: Action,
) -> Result<Option<AccountRow>, sqlx::Error> {
    let sql = match action {
        Action::Approve | Action::Enable => {
            "UPDATE account SET approved = true, silenced_at = NULL, suspended_at = NULL \
             WHERE id = $1 RETURNING *"
        }
        Action::Reject => "UPDATE account SET approved = false WHERE id = $1 RETURNING *",
        Action::Silence => {
            "UPDATE account SET silenced_at = now(), suspended_at = NULL \
             WHERE id = $1 RETURNING *"
        }
        Action::Suspend => "UPDATE account SET suspended_at = now() WHERE id = $1 RETURNING *",
    };
    sqlx::query_as::<_, AccountRow>(sql)
        .bind(account_id)
        .fetch_optional(pool)
        .await
}

#[derive(Debug, Clone, FromRow)]
pub struct MeasureRow {
    pub date: NaiveDate,
    pub value: i64,
}

pub async fn measure(
    pool: &PgPool,
    key: &str,
    start: NaiveDate,
    end: NaiveDate,
) -> Result<Vec<MeasureRow>, sqlx::Error> {
    let sql = match key {
        "new_users" => {
            "SELECT d::date AS date, count(a.id)::bigint AS value \
             FROM generate_series($1::date, $2::date, '1 day') d \
             LEFT JOIN account a ON a.local AND a.created_at::date = d::date \
             GROUP BY d ORDER BY d"
        }
        "statuses" => {
            "SELECT d::date AS date, count(s.id)::bigint AS value \
             FROM generate_series($1::date, $2::date, '1 day') d \
             LEFT JOIN status s ON s.created_at::date = d::date AND s.deleted_at IS NULL \
             GROUP BY d ORDER BY d"
        }
        "interactions" => {
            "SELECT d::date AS date, ((SELECT count(*) FROM favourite f WHERE f.created_at::date = d::date) + (SELECT count(*) FROM bookmark b WHERE b.created_at::date = d::date))::bigint AS value \
             FROM generate_series($1::date, $2::date, '1 day') d \
             GROUP BY d ORDER BY d"
        }
        "reports" => {
            "SELECT d::date AS date, count(r.id)::bigint AS value \
             FROM generate_series($1::date, $2::date, '1 day') d \
             LEFT JOIN report r ON r.created_at::date = d::date \
             GROUP BY d ORDER BY d"
        }
        _ => return Ok(Vec::new()),
    };
    sqlx::query_as::<_, MeasureRow>(sql)
        .bind(start)
        .bind(end)
        .fetch_all(pool)
        .await
}

#[cfg(test)]
mod tests {
    use super::Action;

    #[test]
    fn action_aliases_map_to_the_same_policy() {
        assert_eq!(Action::parse("disable"), Some(Action::Reject));
        assert_eq!(Action::parse("unsuspend"), Some(Action::Enable));
        assert_eq!(Action::parse("unsilence"), Some(Action::Enable));
        assert_eq!(Action::parse("explode"), None);
    }
}

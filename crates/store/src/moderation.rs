//! Reports, audit history, domain policy, account enforcement and the private record
//! moderators keep about an account.
//!
//! Moderation is a server concern: clients read and write it through the Mastodon
//! admin API, but the invariants (who may act, what an action changes, what is
//! recorded) live here so every protocol surface gets the same answer.

use chrono::{DateTime, NaiveDate, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgConnection, PgPool};

use nodus_server_core::Id;

use crate::accounts::{AccountRow, ACCOUNT_COLUMNS, ACCOUNT_COLUMNS_ALIASED};

const REPORT_COLUMNS: &str = "id, account_id, target_account_id, status_ids, category, comment, \
     state, action_taken, action_taken_note, assigned_account_id, action_taken_by_account_id, \
     action_taken_at, rule_ids, created_at, updated_at";

#[derive(Debug, Clone, FromRow)]
pub struct ReportRow {
    pub id: String,
    /// The account that filed the report.
    pub account_id: String,
    /// The account the report is about.
    pub target_account_id: String,
    pub status_ids: Vec<String>,
    pub category: String,
    pub comment: String,
    pub state: String,
    pub action_taken: bool,
    pub action_taken_note: String,
    pub assigned_account_id: Option<String>,
    pub action_taken_by_account_id: Option<String>,
    pub action_taken_at: Option<DateTime<Utc>>,
    pub rule_ids: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewReport<'a> {
    pub account_id: &'a str,
    pub target_account_id: &'a str,
    pub status_ids: &'a [String],
    pub category: &'a str,
    pub comment: &'a str,
    pub rule_ids: &'a [String],
    /// Set when a peer's activity opened the report, so its retry finds the row.
    pub activity_uri: Option<&'a str>,
}

pub async fn create_report(pool: &PgPool, new: &NewReport<'_>) -> Result<ReportRow, sqlx::Error> {
    let sql = format!(
        "INSERT INTO report (id, account_id, target_account_id, status_ids, category, comment, \
             rule_ids, activity_uri) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING {REPORT_COLUMNS}"
    );
    sqlx::query_as(&sql)
        .bind(Id::new().to_string())
        .bind(new.account_id)
        .bind(new.target_account_id)
        .bind(new.status_ids)
        .bind(new.category)
        .bind(new.comment)
        .bind(new.rule_ids)
        .bind(new.activity_uri)
        .fetch_one(pool)
        .await
}

/// The report an activity already opened, so a replayed activity does not open another.
pub async fn report_for_activity(
    pool: &PgPool,
    activity_uri: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM report WHERE activity_uri = $1")
        .bind(activity_uri)
        .fetch_optional(pool)
        .await
}

/// What a moderator is looking at: any combination of state, reporter, subject and
/// owner. Every field is optional so one query serves the queue, an account's history
/// and "what is still unclaimed".
#[derive(Debug, Clone, Default)]
pub struct ReportFilter<'a> {
    pub state: Option<&'a str>,
    pub category: Option<&'a str>,
    pub target_account_id: Option<&'a str>,
    pub reporter_account_id: Option<&'a str>,
    pub assigned_account_id: Option<&'a str>,
    pub unassigned: bool,
    pub limit: i64,
    pub offset: i64,
}

pub async fn reports(
    pool: &PgPool,
    filter: &ReportFilter<'_>,
) -> Result<Vec<ReportRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {REPORT_COLUMNS} FROM report \
         WHERE ($1::text IS NULL OR state = $1) \
             AND ($2::text IS NULL OR category = $2) \
             AND ($3::text IS NULL OR target_account_id = $3) \
             AND ($4::text IS NULL OR account_id = $4) \
             AND ($5::text IS NULL OR assigned_account_id = $5) \
             AND ($6::boolean = false OR assigned_account_id IS NULL) \
         ORDER BY created_at DESC LIMIT $7 OFFSET $8"
    );
    sqlx::query_as(&sql)
        .bind(filter.state)
        .bind(filter.category)
        .bind(filter.target_account_id)
        .bind(filter.reporter_account_id)
        .bind(filter.assigned_account_id)
        .bind(filter.unassigned)
        .bind(filter.limit)
        .bind(filter.offset)
        .fetch_all(pool)
        .await
}

pub async fn report(pool: &PgPool, id: &str) -> Result<Option<ReportRow>, sqlx::Error> {
    let sql = format!("SELECT {REPORT_COLUMNS} FROM report WHERE id = $1");
    sqlx::query_as(&sql).bind(id).fetch_optional(pool).await
}

/// Claims a report (`Some`) or releases it (`None`). Assigning twice is not an error:
/// the last moderator to claim it owns it.
pub async fn assign_report(
    pool: &PgPool,
    id: &str,
    account_id: Option<&str>,
) -> Result<Option<ReportRow>, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    assign_report_in(&mut conn, id, account_id).await
}

/// The same assignment on a caller-owned connection, so a batch can share a transaction.
pub async fn assign_report_in(
    conn: &mut PgConnection,
    id: &str,
    account_id: Option<&str>,
) -> Result<Option<ReportRow>, sqlx::Error> {
    let sql = format!(
        "UPDATE report SET assigned_account_id = $2, updated_at = now() WHERE id = $1 \
         RETURNING {REPORT_COLUMNS}"
    );
    sqlx::query_as(&sql)
        .bind(id)
        .bind(account_id)
        .fetch_optional(conn)
        .await
}

/// Closes a report as actioned, recording who decided and why.
pub async fn resolve_report(
    pool: &PgPool,
    id: &str,
    actor_id: &str,
    note: &str,
) -> Result<Option<ReportRow>, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    resolve_report_in(&mut conn, id, actor_id, note).await
}

/// The same resolution on a caller-owned connection, so a batch can share a transaction.
pub async fn resolve_report_in(
    conn: &mut PgConnection,
    id: &str,
    actor_id: &str,
    note: &str,
) -> Result<Option<ReportRow>, sqlx::Error> {
    let sql = format!(
        "UPDATE report SET state = 'resolved', action_taken = true, action_taken_note = $3, \
             action_taken_by_account_id = $2, action_taken_at = now(), updated_at = now() \
         WHERE id = $1 RETURNING {REPORT_COLUMNS}"
    );
    sqlx::query_as(&sql)
        .bind(id)
        .bind(actor_id)
        .bind(note)
        .fetch_optional(conn)
        .await
}

/// Reopens a closed report and clears the decision it recorded, so the queue never
/// shows a resolved decision on an open case.
pub async fn reopen_report(pool: &PgPool, id: &str) -> Result<Option<ReportRow>, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    reopen_report_in(&mut conn, id).await
}

/// The same reopen on a caller-owned connection, so a batch can share a transaction.
pub async fn reopen_report_in(
    conn: &mut PgConnection,
    id: &str,
) -> Result<Option<ReportRow>, sqlx::Error> {
    let sql = format!(
        "UPDATE report SET state = 'open', action_taken = false, action_taken_note = '', \
             action_taken_by_account_id = NULL, action_taken_at = NULL, updated_at = now() \
         WHERE id = $1 RETURNING {REPORT_COLUMNS}"
    );
    sqlx::query_as(&sql).bind(id).fetch_optional(conn).await
}

pub async fn audit(
    pool: &PgPool,
    actor_id: &str,
    action: &str,
    target_type: &str,
    target_id: Option<&str>,
    detail: &Value,
) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    audit_in(&mut conn, actor_id, action, target_type, target_id, detail).await
}

/// The same audit row on a caller-owned connection, so an action and its entry commit
/// or roll back together.
pub async fn audit_in(
    conn: &mut PgConnection,
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
    .execute(conn)
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

#[derive(Debug, Clone, Default)]
pub struct AuditFilter<'a> {
    pub action: Option<&'a str>,
    pub target_type: Option<&'a str>,
    pub actor_id: Option<&'a str>,
    /// Inclusive lower bound on `created_at`, for the export window.
    pub since: Option<DateTime<Utc>>,
    /// Inclusive upper bound on `created_at`.
    pub until: Option<DateTime<Utc>>,
    pub limit: i64,
    pub offset: i64,
}

pub async fn audit_page(
    pool: &PgPool,
    filter: &AuditFilter<'_>,
) -> Result<Vec<AuditRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, actor_id, action, target_type, target_id, detail, created_at \
         FROM audit_log \
         WHERE ($1::text IS NULL OR action = $1) \
             AND ($2::text IS NULL OR target_type = $2) \
             AND ($3::text IS NULL OR actor_id = $3) \
             AND ($4::timestamptz IS NULL OR created_at >= $4) \
             AND ($5::timestamptz IS NULL OR created_at <= $5) \
         ORDER BY created_at DESC, id DESC LIMIT $6 OFFSET $7",
    )
    .bind(filter.action)
    .bind(filter.target_type)
    .bind(filter.actor_id)
    .bind(filter.since)
    .bind(filter.until)
    .bind(filter.limit)
    .bind(filter.offset)
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

const DOMAIN_BLOCK_COLUMNS: &str = "id, domain::text AS domain, severity, reject_media, \
     reject_reports, obfuscate, public_comment, created_at";

#[derive(Debug, Clone, Default)]
pub struct DomainBlockFilter<'a> {
    pub severity: Option<&'a str>,
    pub domain: Option<&'a str>,
    pub limit: i64,
    pub offset: i64,
}

pub async fn blocks(
    pool: &PgPool,
    filter: &DomainBlockFilter<'_>,
) -> Result<Vec<DomainBlockRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {DOMAIN_BLOCK_COLUMNS} FROM instance_block \
         WHERE ($1::text IS NULL OR severity = $1) \
             AND ($2::text IS NULL OR domain::text ILIKE '%' || $2 || '%') \
         ORDER BY created_at DESC LIMIT $3 OFFSET $4"
    );
    sqlx::query_as(&sql)
        .bind(filter.severity)
        .bind(filter.domain)
        .bind(filter.limit)
        .bind(filter.offset)
        .fetch_all(pool)
        .await
}

pub async fn block(pool: &PgPool, id: &str) -> Result<Option<DomainBlockRow>, sqlx::Error> {
    let sql = format!("SELECT {DOMAIN_BLOCK_COLUMNS} FROM instance_block WHERE id = $1");
    sqlx::query_as(&sql).bind(id).fetch_optional(pool).await
}

pub async fn create_block(
    pool: &PgPool,
    new: &NewDomainBlock<'_>,
) -> Result<DomainBlockRow, sqlx::Error> {
    let sql = format!(
        "INSERT INTO instance_block (id, domain, severity, reject_media, reject_reports, obfuscate, \
             public_comment) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (domain) DO UPDATE SET severity = EXCLUDED.severity, \
             reject_media = EXCLUDED.reject_media, reject_reports = EXCLUDED.reject_reports, \
             obfuscate = EXCLUDED.obfuscate, public_comment = EXCLUDED.public_comment \
         RETURNING {DOMAIN_BLOCK_COLUMNS}"
    );
    sqlx::query_as(&sql)
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

pub async fn update_block(
    pool: &PgPool,
    id: &str,
    new: &NewDomainBlock<'_>,
) -> Result<Option<DomainBlockRow>, sqlx::Error> {
    let sql = format!(
        "UPDATE instance_block SET severity = $2, reject_media = $3, reject_reports = $4, \
             obfuscate = $5, public_comment = $6 \
         WHERE id = $1 RETURNING {DOMAIN_BLOCK_COLUMNS}"
    );
    sqlx::query_as(&sql)
        .bind(id)
        .bind(new.severity)
        .bind(new.reject_media)
        .bind(new.reject_reports)
        .bind(new.obfuscate)
        .bind(new.public_comment)
        .fetch_optional(pool)
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
    let sql = format!("SELECT {DOMAIN_BLOCK_COLUMNS} FROM instance_block WHERE domain = $1");
    sqlx::query_as(&sql).bind(domain).fetch_optional(pool).await
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
    /// Open reports about this account.
    pub open_reports: i64,
    /// Private moderator notes on this account.
    pub notes: i64,
}

/// The account list, narrowed by anything the console can show: origin, standing,
/// a username/email fragment, or whether the account is staff.
#[derive(Debug, Clone, Default)]
pub struct AccountFilter<'a> {
    /// `Some(true)` local only, `Some(false)` remote only, `None` both.
    pub local: Option<bool>,
    pub status: Option<&'a str>,
    pub username: Option<&'a str>,
    pub display_name: Option<&'a str>,
    pub email: Option<&'a str>,
    pub by_domain: Option<&'a str>,
    pub staff: bool,
    pub limit: i64,
    pub offset: i64,
}

impl AccountFilter<'_> {
    /// Everything, which is what "no filter chosen yet" means in the console.
    #[must_use]
    pub fn all(limit: i64) -> Self {
        Self {
            local: None,
            status: None,
            username: None,
            display_name: None,
            email: None,
            by_domain: None,
            staff: false,
            limit,
            offset: 0,
        }
    }

    /// The pending-registration view: local accounts that were never approved.
    #[must_use]
    pub fn pending(limit: i64) -> Self {
        Self {
            local: Some(true),
            status: Some("pending"),
            limit,
            ..Self::default()
        }
    }
}

pub async fn admin_accounts(
    pool: &PgPool,
    filter: &AccountFilter<'_>,
) -> Result<Vec<AdminAccountRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {ACCOUNT_COLUMNS_ALIASED}, c.email::text AS email, \
             (SELECT count(*) FROM report r \
                 WHERE r.target_account_id = a.id AND r.state = 'open')::bigint AS open_reports, \
             (SELECT count(*) FROM moderator_note n WHERE n.account_id = a.id)::bigint AS notes \
         FROM account a \
         LEFT JOIN account_credential c ON c.account_id = a.id \
         WHERE ($1::boolean IS NULL OR a.local = $1) \
             AND ($2::text IS NULL OR CASE $2 \
                 WHEN 'active' THEN a.approved AND a.silenced_at IS NULL \
                     AND a.suspended_at IS NULL \
                 WHEN 'pending' THEN NOT a.approved \
                 WHEN 'disabled' THEN NOT a.approved \
                 WHEN 'silenced' THEN a.silenced_at IS NOT NULL \
                 WHEN 'suspended' THEN a.suspended_at IS NOT NULL \
                 ELSE true END) \
             AND ($3::text IS NULL OR a.username ILIKE '%' || $3 || '%') \
             AND ($4::text IS NULL OR a.display_name ILIKE '%' || $4 || '%') \
             AND ($5::text IS NULL OR c.email::text ILIKE '%' || $5 || '%') \
             AND ($6::text IS NULL OR a.domain = $6) \
             AND ($7::boolean = false OR a.admin) \
         ORDER BY a.created_at DESC LIMIT $8 OFFSET $9"
    );
    sqlx::query_as(&sql)
        .bind(filter.local)
        .bind(filter.status)
        .bind(filter.username)
        .bind(filter.display_name)
        .bind(filter.email)
        .bind(filter.by_domain)
        .bind(filter.staff)
        .bind(filter.limit)
        .bind(filter.offset)
        .fetch_all(pool)
        .await
}

pub async fn admin_account(
    pool: &PgPool,
    id: &str,
) -> Result<Option<AdminAccountRow>, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    admin_account_in(&mut conn, id).await
}

/// The same lookup on a caller-owned connection, so a batch can read inside its transaction.
pub async fn admin_account_in(
    conn: &mut PgConnection,
    id: &str,
) -> Result<Option<AdminAccountRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {ACCOUNT_COLUMNS_ALIASED}, c.email::text AS email, \
             (SELECT count(*) FROM report r \
                 WHERE r.target_account_id = a.id AND r.state = 'open')::bigint AS open_reports, \
             (SELECT count(*) FROM moderator_note n WHERE n.account_id = a.id)::bigint AS notes \
         FROM account a \
         LEFT JOIN account_credential c ON c.account_id = a.id \
         WHERE a.id = $1"
    );
    sqlx::query_as(&sql).bind(id).fetch_optional(conn).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Approve,
    Reject,
    Silence,
    Suspend,
    Enable,
    Unsilence,
    Unsuspend,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Silence => "silence",
            Self::Suspend => "suspend",
            Self::Enable => "enable",
            Self::Unsilence => "unsilence",
            Self::Unsuspend => "unsuspend",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "approve" => Self::Approve,
            "reject" | "disable" => Self::Reject,
            "silence" => Self::Silence,
            "suspend" => Self::Suspend,
            "enable" => Self::Enable,
            "unsilence" => Self::Unsilence,
            "unsuspend" => Self::Unsuspend,
            _ => return None,
        })
    }
}

pub async fn apply_action(
    pool: &PgPool,
    account_id: &str,
    action: Action,
) -> Result<Option<AccountRow>, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    apply_action_in(&mut conn, account_id, action).await
}

/// The same enforcement on a caller-owned connection, so a batch can share a transaction.
pub async fn apply_action_in(
    conn: &mut PgConnection,
    account_id: &str,
    action: Action,
) -> Result<Option<AccountRow>, sqlx::Error> {
    let set_clause = match action {
        Action::Approve | Action::Enable => {
            "approved = true, silenced_at = NULL, suspended_at = NULL"
        }
        Action::Reject => "approved = false",
        Action::Silence => "silenced_at = now(), suspended_at = NULL",
        Action::Suspend => "suspended_at = now()",
        Action::Unsilence => "silenced_at = NULL",
        Action::Unsuspend => "suspended_at = NULL",
    };
    let sql = format!("UPDATE account SET {set_clause} WHERE id = $1 RETURNING {ACCOUNT_COLUMNS}");
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(account_id)
        .fetch_optional(conn)
        .await
}

/// Grants or revokes the staff flag. Kept apart from [`apply_action`] because it is the
/// one account change that can lock the console's own operators out.
pub async fn set_staff(pool: &PgPool, account_id: &str, staff: bool) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE account SET admin = $2, \
             staff_role = CASE WHEN $2 THEN 'admin' ELSE 'none' END \
         WHERE id = $1",
    )
    .bind(account_id)
    .bind(staff)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

/// Returns the credential email for an account, if it has a local login.
pub async fn account_email(pool: &PgPool, account_id: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT email::text FROM account_credential WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await
}

#[derive(Debug, Clone, FromRow)]
pub struct NoteRow {
    pub id: String,
    pub account_id: String,
    pub author_id: String,
    pub author_username: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
}

pub async fn notes(pool: &PgPool, account_id: &str) -> Result<Vec<NoteRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT n.id, n.account_id, n.author_id, a.username::text AS author_username, n.body, \
             n.created_at \
         FROM moderator_note n JOIN account a ON a.id = n.author_id \
         WHERE n.account_id = $1 ORDER BY n.created_at DESC LIMIT 200",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
}

pub async fn add_note(
    pool: &PgPool,
    account_id: &str,
    author_id: &str,
    body: &str,
) -> Result<NoteRow, sqlx::Error> {
    sqlx::query_as(
        "WITH inserted AS ( \
             INSERT INTO moderator_note (id, account_id, author_id, body) VALUES ($1, $2, $3, $4) \
             RETURNING id, account_id, author_id, body, created_at \
         ) \
         SELECT i.id, i.account_id, i.author_id, a.username::text AS author_username, i.body, \
             i.created_at \
         FROM inserted i JOIN account a ON a.id = i.author_id",
    )
    .bind(Id::new().to_string())
    .bind(account_id)
    .bind(author_id)
    .bind(body)
    .fetch_one(pool)
    .await
}

pub async fn delete_note(
    pool: &PgPool,
    account_id: &str,
    note_id: &str,
) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query("DELETE FROM moderator_note WHERE id = $1 AND account_id = $2")
            .bind(note_id)
            .bind(account_id)
            .execute(pool)
            .await?
            .rows_affected()
            == 1,
    )
}

#[derive(Debug, Clone, FromRow)]
pub struct WarningPresetRow {
    pub id: String,
    pub title: String,
    pub text: String,
    pub created_at: DateTime<Utc>,
}

pub async fn warning_presets(pool: &PgPool) -> Result<Vec<WarningPresetRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, title, text, created_at FROM warning_preset ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(pool)
    .await
}

pub async fn create_warning_preset(
    pool: &PgPool,
    title: &str,
    text: &str,
) -> Result<WarningPresetRow, sqlx::Error> {
    sqlx::query_as(
        "INSERT INTO warning_preset (id, title, text) VALUES ($1, $2, $3) \
         RETURNING id, title, text, created_at",
    )
    .bind(Id::new().to_string())
    .bind(title)
    .bind(text)
    .fetch_one(pool)
    .await
}

pub async fn update_warning_preset(
    pool: &PgPool,
    id: &str,
    title: &str,
    text: &str,
) -> Result<Option<WarningPresetRow>, sqlx::Error> {
    sqlx::query_as(
        "UPDATE warning_preset SET title = $2, text = $3 WHERE id = $1 \
         RETURNING id, title, text, created_at",
    )
    .bind(id)
    .bind(title)
    .bind(text)
    .fetch_optional(pool)
    .await
}

pub async fn delete_warning_preset(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM warning_preset WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected()
        == 1)
}

#[derive(Debug, Clone, FromRow)]
pub struct EmailDomainBlockRow {
    pub id: String,
    pub domain: String,
    pub allow_registration: bool,
    pub created_at: DateTime<Utc>,
}

const EMAIL_DOMAIN_COLUMNS: &str = "id, domain::text AS domain, allow_registration, created_at";

pub async fn email_domain_blocks(
    pool: &PgPool,
    domain: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<EmailDomainBlockRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {EMAIL_DOMAIN_COLUMNS} FROM email_domain_block \
         WHERE ($1::text IS NULL OR domain::text ILIKE '%' || $1 || '%') \
         ORDER BY created_at DESC LIMIT $2 OFFSET $3"
    );
    sqlx::query_as(&sql)
        .bind(domain)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
}

pub async fn email_domain_block(
    pool: &PgPool,
    id: &str,
) -> Result<Option<EmailDomainBlockRow>, sqlx::Error> {
    let sql = format!("SELECT {EMAIL_DOMAIN_COLUMNS} FROM email_domain_block WHERE id = $1");
    sqlx::query_as(&sql).bind(id).fetch_optional(pool).await
}

pub async fn create_email_domain_block(
    pool: &PgPool,
    domain: &str,
    allow_registration: bool,
) -> Result<EmailDomainBlockRow, sqlx::Error> {
    let sql = format!(
        "INSERT INTO email_domain_block (id, domain, allow_registration) VALUES ($1, $2, $3) \
         ON CONFLICT (domain) DO UPDATE SET allow_registration = EXCLUDED.allow_registration \
         RETURNING {EMAIL_DOMAIN_COLUMNS}"
    );
    sqlx::query_as(&sql)
        .bind(Id::new().to_string())
        .bind(domain)
        .bind(allow_registration)
        .fetch_one(pool)
        .await
}

pub async fn delete_email_domain_block(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM email_domain_block WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected()
        == 1)
}

/// The most specific rule covering `domain`, so `example.com` can be blocked while
/// `friends.example.com` stays allowed.
pub async fn email_domain_policy(
    pool: &PgPool,
    domain: &str,
) -> Result<Option<EmailDomainBlockRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {EMAIL_DOMAIN_COLUMNS} FROM email_domain_block \
         WHERE $1::citext = domain OR $1::citext LIKE '%%.' || domain::text \
         ORDER BY length(domain::text) DESC LIMIT 1"
    );
    sqlx::query_as(&sql).bind(domain).fetch_optional(pool).await
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
        "reports" | "opened_reports" => {
            "SELECT d::date AS date, count(r.id)::bigint AS value \
             FROM generate_series($1::date, $2::date, '1 day') d \
             LEFT JOIN report r ON r.created_at::date = d::date \
             GROUP BY d ORDER BY d"
        }
        "resolved_reports" => {
            "SELECT d::date AS date, count(r.id)::bigint AS value \
             FROM generate_series($1::date, $2::date, '1 day') d \
             LEFT JOIN report r ON r.action_taken_at::date = d::date AND r.state = 'resolved' \
             GROUP BY d ORDER BY d"
        }
        "active_user_count" => {
            "SELECT d::date AS date, count(DISTINCT s.account_id)::bigint AS value \
             FROM generate_series($1::date, $2::date, '1 day') d \
             LEFT JOIN status s ON s.created_at::date = d::date AND s.deleted_at IS NULL \
             GROUP BY d ORDER BY d"
        }
        "open_reports" => {
            "SELECT d::date AS date, \
                 (SELECT count(*) FROM report r WHERE r.created_at::date <= d::date \
                     AND (r.state = 'open' OR r.updated_at::date > d::date))::bigint AS value \
             FROM generate_series($1::date, $2::date, '1 day') d \
             ORDER BY d"
        }
        _ => return Ok(Vec::new()),
    };
    sqlx::query_as::<_, MeasureRow>(sql)
        .bind(start)
        .bind(end)
        .fetch_all(pool)
        .await
}

/// Instance-wide counts the console shows above the fold.
#[derive(Debug, Clone, FromRow)]
pub struct OverviewRow {
    pub accounts: i64,
    pub local_accounts: i64,
    pub active_accounts: i64,
    pub statuses: i64,
    pub open_reports: i64,
    pub resolved_reports: i64,
    pub unassigned_reports: i64,
    pub pending_accounts: i64,
    pub silences: i64,
    pub suspensions: i64,
    pub domain_blocks: i64,
    pub email_domain_blocks: i64,
    pub staff: i64,
}

pub async fn overview(pool: &PgPool) -> Result<OverviewRow, sqlx::Error> {
    sqlx::query_as(
        "SELECT \
             (SELECT count(*) FROM account)::bigint AS accounts, \
             (SELECT count(*) FROM account WHERE local)::bigint AS local_accounts, \
             (SELECT count(*) FROM account a WHERE a.local AND a.approved \
                 AND a.silenced_at IS NULL AND a.suspended_at IS NULL \
                 AND EXISTS (SELECT 1 FROM status s WHERE s.account_id = a.id \
                     AND s.deleted_at IS NULL AND s.created_at > now() - interval '30 days')) \
                 ::bigint AS active_accounts, \
             (SELECT count(*) FROM status WHERE deleted_at IS NULL)::bigint AS statuses, \
             (SELECT count(*) FROM report WHERE state = 'open')::bigint AS open_reports, \
             (SELECT count(*) FROM report WHERE state = 'resolved')::bigint AS resolved_reports, \
             (SELECT count(*) FROM report WHERE state = 'open' \
                 AND assigned_account_id IS NULL)::bigint AS unassigned_reports, \
             (SELECT count(*) FROM account WHERE local AND NOT approved)::bigint \
                 AS pending_accounts, \
             (SELECT count(*) FROM account WHERE silenced_at IS NOT NULL)::bigint AS silences, \
             (SELECT count(*) FROM account WHERE suspended_at IS NOT NULL)::bigint \
                 AS suspensions, \
             (SELECT count(*) FROM instance_block)::bigint AS domain_blocks, \
             (SELECT count(*) FROM email_domain_block)::bigint AS email_domain_blocks, \
             (SELECT count(*) FROM account WHERE admin)::bigint AS staff",
    )
    .fetch_one(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::Action;

    #[test]
    fn action_aliases_map_to_the_same_policy() {
        assert_eq!(Action::parse("disable"), Some(Action::Reject));
        assert_eq!(Action::parse("unsuspend"), Some(Action::Unsuspend));
        assert_eq!(Action::parse("unsilence"), Some(Action::Unsilence));
        assert_eq!(Action::parse("explode"), None);
    }
}

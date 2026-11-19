//! Appeals: a restricted account asking a person to look again.
//!
//! The person's side opens and reads; the moderator's side lists the queue and decides.
//! A decision and the lift it implies commit together with their audit row, so the record
//! can never say "accepted" while the restriction is still in force.

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{FromRow, PgPool};

use crate::moderation::{self, Action};

const APPEAL_COLUMNS: &str = "id::text AS id, account_id, action, reason, status, \
     decision_note, decided_by, created_at, decided_at";

/// One appeal, in the shape both sides read.
#[derive(Debug, Clone, FromRow)]
pub struct AppealRow {
    pub id: String,
    pub account_id: String,
    pub action: String,
    pub reason: String,
    pub status: String,
    pub decision_note: Option<String>,
    pub decided_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
}

/// The restriction an account is under, in the precedence a pending appeal records it.
///
/// Suspension outranks silence, which outranks the unapproved flag: a suspended account
/// that was also silenced is appealing the suspension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restriction {
    Suspend,
    Silence,
    Reject,
}

impl Restriction {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Suspend => "suspend",
            Self::Silence => "silence",
            Self::Reject => "reject",
        }
    }
}

#[derive(Debug, Clone, FromRow)]
struct RestrictionRow {
    suspended: bool,
    silenced: bool,
    approved: bool,
}

impl RestrictionRow {
    fn restriction(&self) -> Option<Restriction> {
        if self.suspended {
            Some(Restriction::Suspend)
        } else if self.silenced {
            Some(Restriction::Silence)
        } else if !self.approved {
            Some(Restriction::Reject)
        } else {
            None
        }
    }
}

/// The restriction in force for an account, or `None` when it may post freely.
pub async fn restriction(
    pool: &PgPool,
    account_id: &str,
) -> Result<Option<Restriction>, sqlx::Error> {
    let row = sqlx::query_as::<_, RestrictionRow>(
        "SELECT suspended_at IS NOT NULL AS suspended, \
                silenced_at IS NOT NULL AS silenced, approved \
           FROM account WHERE id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|row| row.restriction()))
}

/// What opening an appeal did.
#[derive(Debug)]
pub enum OpenOutcome {
    Opened(AppealRow),
    NotRestricted,
    /// The account already has an appeal waiting; the row is the one that is open.
    AlreadyPending(AppealRow),
}

/// Opens an appeal for the account's current restriction.
pub async fn open(
    pool: &PgPool,
    account_id: &str,
    reason: &str,
) -> Result<OpenOutcome, sqlx::Error> {
    let Some(restriction) = restriction(pool, account_id).await? else {
        return Ok(OpenOutcome::NotRestricted);
    };
    let row = sqlx::query_as::<_, AppealRow>(&format!(
        "INSERT INTO appeal (account_id, action, reason) VALUES ($1, $2, $3) \
         ON CONFLICT (account_id) WHERE status = 'pending' DO NOTHING \
         RETURNING {APPEAL_COLUMNS}"
    ))
    .bind(account_id)
    .bind(restriction.as_str())
    .bind(reason)
    .fetch_optional(pool)
    .await?;
    if let Some(row) = row {
        return Ok(OpenOutcome::Opened(row));
    }
    // The insert lost the race to an already-pending appeal, or the account was
    // restricted by one in the same instant; either way the open row is the answer.
    let pending = sqlx::query_as::<_, AppealRow>(&format!(
        "SELECT {APPEAL_COLUMNS} FROM appeal WHERE account_id = $1 AND status = 'pending'"
    ))
    .bind(account_id)
    .fetch_optional(pool)
    .await?;
    match pending {
        Some(row) => Ok(OpenOutcome::AlreadyPending(row)),
        // Nothing pending and nothing inserted: the restriction was lifted between the
        // two statements.
        None => Ok(OpenOutcome::NotRestricted),
    }
}

/// The account's own appeals, newest first.
pub async fn mine(pool: &PgPool, account_id: &str) -> Result<Vec<AppealRow>, sqlx::Error> {
    sqlx::query_as::<_, AppealRow>(&format!(
        "SELECT {APPEAL_COLUMNS} FROM appeal \
          WHERE account_id = $1 ORDER BY created_at DESC, id DESC"
    ))
    .bind(account_id)
    .fetch_all(pool)
    .await
}

/// The appeal the account is waiting on, if one is open.
///
/// A pending appeal is not a private moderator concern: the person who filed it needs to
/// see that it is waiting and not lost, so the notification reader asks for it directly
/// rather than scanning [`mine`] and hoping the newest row is still open.
pub async fn pending(pool: &PgPool, account_id: &str) -> Result<Option<AppealRow>, sqlx::Error> {
    sqlx::query_as::<_, AppealRow>(&format!(
        "SELECT {APPEAL_COLUMNS} FROM appeal \
          WHERE account_id = $1 AND status = 'pending' \
          ORDER BY created_at DESC, id DESC LIMIT 1"
    ))
    .bind(account_id)
    .fetch_optional(pool)
    .await
}

/// One row of the moderator's queue, with the account and the restriction in force.
#[derive(Debug, Clone, FromRow)]
pub struct AdminAppealRow {
    pub id: String,
    pub account_id: String,
    pub username: String,
    pub domain: Option<String>,
    pub action: String,
    pub reason: String,
    pub status: String,
    pub decision_note: Option<String>,
    pub decided_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub suspended: bool,
    pub silenced: bool,
    pub approved: bool,
}

impl AdminAppealRow {
    /// The restriction the account is under *now*, which may differ from the one appealed.
    #[must_use]
    pub fn restriction(&self) -> Option<Restriction> {
        if self.suspended {
            Some(Restriction::Suspend)
        } else if self.silenced {
            Some(Restriction::Silence)
        } else if !self.approved {
            Some(Restriction::Reject)
        } else {
            None
        }
    }
}

/// The queue, filtered by state, newest first.
pub async fn admin_list(
    pool: &PgPool,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<AdminAppealRow>, sqlx::Error> {
    sqlx::query_as::<_, AdminAppealRow>(
        "SELECT ap.id::text AS id, ap.account_id, a.username::text AS username, \
                a.domain::text AS domain, ap.action, ap.reason, ap.status, \
                ap.decision_note, ap.decided_by, ap.created_at, ap.decided_at, \
                a.suspended_at IS NOT NULL AS suspended, \
                a.silenced_at IS NOT NULL AS silenced, a.approved \
           FROM appeal ap JOIN account a ON a.id = ap.account_id \
          WHERE ($1::text IS NULL OR ap.status = $1) \
          ORDER BY ap.created_at DESC, ap.id DESC LIMIT $2 OFFSET $3",
    )
    .bind(status)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

/// One queue row by id, joined the same way the list is.
pub async fn admin_row(pool: &PgPool, id: &str) -> Result<Option<AdminAppealRow>, sqlx::Error> {
    sqlx::query_as::<_, AdminAppealRow>(
        "SELECT ap.id::text AS id, ap.account_id, a.username::text AS username, \
                a.domain::text AS domain, ap.action, ap.reason, ap.status, \
                ap.decision_note, ap.decided_by, ap.created_at, ap.decided_at, \
                a.suspended_at IS NOT NULL AS suspended, \
                a.silenced_at IS NOT NULL AS silenced, a.approved \
           FROM appeal ap JOIN account a ON a.id = ap.account_id \
          WHERE ap.id::text = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// What deciding an appeal did.
#[derive(Debug)]
pub enum DecideOutcome {
    Decided(AppealRow),
    /// Somebody already closed this appeal; nothing was touched.
    AlreadyDecided,
    NotFound,
}

/// Decides a pending appeal: the status, the note, the audit row and — on acceptance —
/// the lift all commit together.
pub async fn decide(
    pool: &PgPool,
    id: &str,
    accept: bool,
    note: Option<&str>,
    decided_by: &str,
) -> Result<DecideOutcome, sqlx::Error> {
    let status = if accept { "accepted" } else { "rejected" };
    let mut tx = pool.begin().await?;
    let row = sqlx::query_as::<_, AppealRow>(&format!(
        "UPDATE appeal SET status = $2, decision_note = $3, decided_by = $4, \
                decided_at = now() \
          WHERE id::text = $1 AND status = 'pending' \
          RETURNING {APPEAL_COLUMNS}"
    ))
    .bind(id)
    .bind(status)
    .bind(note)
    .bind(decided_by)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        let existing: Option<String> =
            sqlx::query_scalar("SELECT status FROM appeal WHERE id::text = $1")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        return Ok(match existing {
            None => DecideOutcome::NotFound,
            Some(_) => DecideOutcome::AlreadyDecided,
        });
    };
    if accept {
        // The existing lifting code, chosen by what the person was appealing: an accepted
        // suspension is lifted by `unsuspend`, a silence by `unsilence`, a refusal of the
        // account by `approve`.
        let lift = match row.action.as_str() {
            "silence" => Action::Unsilence,
            "reject" => Action::Approve,
            _ => Action::Unsuspend,
        };
        moderation::apply_action_noted_in(
            &mut tx,
            &row.account_id,
            lift,
            // Lifting a restriction is its own decision and gets its own sentence
            // ("Your silence was lifted") rather than editing the one that imposed it;
            // the moderator's decision note, when there is one, is the reason.
            &moderation::Notice {
                reason: note.unwrap_or_default(),
                rule: None,
                rule_id: None,
                actor_id: Some(decided_by),
                expires_at: None,
                strike: None,
            },
        )
        .await?;
    }
    moderation::audit_in(
        &mut tx,
        decided_by,
        if accept {
            "appeal_accept"
        } else {
            "appeal_reject"
        },
        "appeal",
        Some(&row.id),
        &json!({
            "account_id": row.account_id,
            "action": row.action,
            "note": note,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(DecideOutcome::Decided(row))
}

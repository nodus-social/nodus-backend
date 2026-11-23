//! What an account wants done with each kind of notification.
//!
//! Mastodon's notification policy is per account and per kind: `accept` (deliver it),
//! `filter` (keep it out of the inbox but admit it exists) or `drop` (discard it). The
//! stored row is only an override: a missing row means [`DEFAULT`] for that kind, so an
//! account that has never opened the tab reads as all-default and needs no backfill.
//!
//! The API answers `GET|PUT /api/v2/notifications/policy` from here, and [`policy_kind_for`]
//! is the mapping the write path joins against: a `drop` means no row is written, a
//! `filter` means the row is written with `filtered = true`.

use std::collections::BTreeMap;

use sqlx::PgPool;

/// The notification kinds Mastodon's policy speaks about, in the order its document lists
/// them.
pub const KINDS: [&str; 8] = [
    "mention",
    "favourite",
    "reblog",
    "follow",
    "follow_request",
    "report",
    "pending_request",
    "status",
];

/// The three answers a kind may carry.
pub const VALUES: [&str; 3] = ["accept", "filter", "drop"];

/// What a kind answers when the account has no row for it: every notification arrives.
pub const DEFAULT: &str = "accept";

/// The policy entry that governs a notification row kind, when there is one.
///
/// `poll` has no entry in Mastodon's policy map, and `appeal`/`moderation` are this
/// instance's own safety notices, so those three are always delivered. `follow_request`,
/// `report` and `pending_request` map here but no write path creates those rows yet.
pub fn policy_kind_for(kind: &str) -> Option<&'static str> {
    match kind {
        "mention" => Some("mention"),
        "favourite" => Some("favourite"),
        "reblog" => Some("reblog"),
        "follow" => Some("follow"),
        "follow_request" => Some("follow_request"),
        "report" => Some("report"),
        "pending_request" => Some("pending_request"),
        "status" => Some("status"),
        _ => None,
    }
}

/// Every kind's current answer for one account, defaults filled in.
///
/// One statement, whatever the number of stored overrides: the request's kinds are unnested
/// and left-joined to the rows, so the settings page pays one query rather than one per
/// notification kind.
pub async fn load(
    pool: &PgPool,
    account_id: &str,
) -> Result<BTreeMap<String, String>, sqlx::Error> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT k.kind, COALESCE(p.policy, $3) \
           FROM unnest($2::text[]) AS k(kind) \
           LEFT JOIN notification_policy p \
             ON p.account_id = $1 AND p.kind = k.kind",
    )
    .bind(account_id)
    .bind(&KINDS[..])
    .bind(DEFAULT)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().collect())
}

/// Stores the answers a request names, leaving every other kind as it was.
///
/// The caller has already refused unknown kinds and values; this writes them in one
/// statement. A kind set back to [`DEFAULT`] keeps its row rather than deleting it, which
/// costs one row and makes "explicitly accepted" distinguishable from "never opened".
pub async fn save(
    pool: &PgPool,
    account_id: &str,
    changes: &BTreeMap<String, String>,
) -> Result<(), sqlx::Error> {
    let kinds: Vec<&str> = changes.keys().map(String::as_str).collect();
    let policies: Vec<&str> = changes.values().map(String::as_str).collect();
    sqlx::query(
        "INSERT INTO notification_policy (account_id, kind, policy) \
         SELECT $1, k.kind, k.policy \
           FROM unnest($2::text[], $3::text[]) AS k(kind, policy) \
         ON CONFLICT (account_id, kind) DO UPDATE \
            SET policy = EXCLUDED.policy, updated_at = now()",
    )
    .bind(account_id)
    .bind(&kinds)
    .bind(&policies)
    .execute(pool)
    .await?;
    Ok(())
}

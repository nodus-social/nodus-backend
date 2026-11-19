//! Which media nodes are alive, and where to reach them.
//!
//! Membership is a table, not a config file: a node records itself on a heartbeat, and
//! every read is filtered by the age of that heartbeat. A node that is restarted on a new
//! address therefore replaces its own row instead of needing the operator to edit a list,
//! and a node that vanishes simply stops being a placement target once its heartbeat is
//! older than the caller's window.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// One media node the instance knows about.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct MediaNode {
    pub name: String,
    pub endpoint: String,
    pub capacity_bytes: Option<i64>,
    pub heartbeat_at: DateTime<Utc>,
}

/// Records that `name` is alive at `endpoint`, replacing its previous address.
///
/// The upsert is keyed on the name so a restarted node does not accumulate rows: the
/// membership table is the current view, not a history of every address ever used.
pub async fn heartbeat(pool: &PgPool, name: &str, endpoint: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO media_node (name, endpoint, heartbeat_at) \
         VALUES ($1, $2, now()) \
         ON CONFLICT (name) DO UPDATE \
            SET endpoint = EXCLUDED.endpoint, heartbeat_at = EXCLUDED.heartbeat_at",
    )
    .bind(name)
    .bind(endpoint)
    .execute(pool)
    .await?;
    Ok(())
}

/// Nodes heard from within `max_age`, ordered by name.
///
/// The order is part of the contract: placement breaks score ties by name, so every
/// process must see the same list in the same order for a cluster to agree.
pub async fn members(pool: &PgPool, max_age: Duration) -> Result<Vec<MediaNode>, sqlx::Error> {
    sqlx::query_as(
        "SELECT name, endpoint, capacity_bytes, heartbeat_at FROM media_node \
          WHERE heartbeat_at > now() - make_interval(secs => $1) \
          ORDER BY name",
    )
    .bind(max_age.as_secs_f64())
    .fetch_all(pool)
    .await
}

/// Deletes nodes whose last heartbeat is older than `older_than`, returning how many.
///
/// Forgotten rows are not a correctness problem — [`members`] already filters them out —
/// but they would otherwise accumulate for every address the instance ever ran on.
pub async fn forget_stale(pool: &PgPool, older_than: Duration) -> Result<u64, sqlx::Error> {
    let deleted = sqlx::query(
        "DELETE FROM media_node WHERE heartbeat_at < now() - make_interval(secs => $1)",
    )
    .bind(older_than.as_secs_f64())
    .execute(pool)
    .await?;
    Ok(deleted.rows_affected())
}

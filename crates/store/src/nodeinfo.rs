//! The usage counts behind `/nodeinfo/2.0`.
//!
//! All four numbers are subqueries of one statement: a directory crawler polls this
//! document on its own schedule, and an instance that answered by walking its accounts
//! would pay the crawler's polling rate in round trips.
//!
//! There is no sign-in timestamp in this schema, so "active" here means "posted inside
//! the window" — the same measure the moderation dashboard uses — rather than a number
//! derived from a column that does not exist.

use sqlx::FromRow;

use crate::Store;

/// The counts `NodeInfo` 2.0 publishes under `usage`.
#[derive(Debug, Clone, FromRow)]
pub struct Usage {
    pub users_total: i64,
    pub users_active_month: i64,
    pub users_active_halfyear: i64,
    pub local_posts: i64,
}

impl Store {
    /// The counts behind `/nodeinfo/2.0`, in one statement.
    ///
    /// Users are local accounts that are not deletion tombstones; a suspended account
    /// still exists, so it still counts. Posts are this instance's own, non-deleted ones.
    pub async fn nodeinfo_usage(&self) -> Result<Usage, sqlx::Error> {
        sqlx::query_as(
            "SELECT \
                 (SELECT count(*) FROM account a \
                   WHERE a.local AND a.deleted_at IS NULL)::bigint AS users_total, \
                 (SELECT count(*) FROM account a \
                   WHERE a.local AND a.deleted_at IS NULL \
                     AND EXISTS (SELECT 1 FROM status s WHERE s.account_id = a.id \
                         AND s.deleted_at IS NULL \
                         AND s.created_at > now() - interval '30 days'))::bigint \
                     AS users_active_month, \
                 (SELECT count(*) FROM account a \
                   WHERE a.local AND a.deleted_at IS NULL \
                     AND EXISTS (SELECT 1 FROM status s WHERE s.account_id = a.id \
                         AND s.deleted_at IS NULL \
                         AND s.created_at > now() - interval '180 days'))::bigint \
                     AS users_active_halfyear, \
                 (SELECT count(*) FROM status s \
                   WHERE s.local AND s.deleted_at IS NULL)::bigint AS local_posts",
        )
        .fetch_one(&self.pool)
        .await
    }
}

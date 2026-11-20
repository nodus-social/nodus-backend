//! Tags: one lookup, and one subscription per reader.
//!
//! There is no `tag` table. A tag exists because a post carried it, so a tag page counts
//! the rows in `status_tag`; a subscription in `tag_follow` only remembers a reader's
//! interest in a name. That is also why an unused, unfollowed tag has no object to serve:
//! inventing one would make every typo look like a real tag with an empty history.

use sqlx::PgPool;

use crate::discovery::TagCount;

/// One tag with its use counts, or `None` when no live post carries it.
pub async fn tag(pool: &PgPool, name: &str) -> Result<Option<TagCount>, sqlx::Error> {
    sqlx::query_as(
        "SELECT t.tag::text AS name, COUNT(*)::bigint AS uses, \
                COUNT(DISTINCT s.account_id)::bigint AS accounts \
           FROM status_tag t JOIN status s ON s.id = t.status_id \
          WHERE s.deleted_at IS NULL AND t.tag = $1::citext \
          GROUP BY t.tag",
    )
    .bind(name)
    .fetch_optional(pool)
    .await
}

/// Whether `account_id` follows `name`.
pub async fn followed(pool: &PgPool, account_id: &str, name: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM tag_follow WHERE account_id = $1 AND tag = $2::citext)",
    )
    .bind(account_id)
    .bind(name)
    .fetch_one(pool)
    .await
}

/// Subscribes an account to a tag. A repeat follow is a no-op, not a duplicate row.
pub async fn follow(pool: &PgPool, account_id: &str, name: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO tag_follow (account_id, tag) VALUES ($1, $2::citext) \
         ON CONFLICT (account_id, tag) DO NOTHING",
    )
    .bind(account_id)
    .bind(name)
    .execute(pool)
    .await?;
    Ok(())
}

/// Removes a subscription. Unfollowing a tag one does not follow is a no-op.
pub async fn unfollow(pool: &PgPool, account_id: &str, name: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM tag_follow WHERE account_id = $1 AND tag = $2::citext")
        .bind(account_id)
        .bind(name)
        .execute(pool)
        .await?;
    Ok(())
}

//! Dialect-specific external identifiers.
//!
//! A local row keeps its ULID as the primary key. Misskey clients need a
//! ten-character `aid`, so the mapping lives here rather than in `status.id`:
//! changing the encoding later must not rewrite every timeline row.

use sqlx::PgPool;

/// Resolves a dialect id to the local row id.
pub async fn resolve(
    pool: &PgPool,
    kind: &str,
    external_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT local_id FROM external_id WHERE kind = $1 AND external_id = $2",
    )
    .bind(kind)
    .bind(external_id)
    .fetch_optional(pool)
    .await
}

/// Returns the dialect id for a local row, creating one with `candidate` if needed.
///
/// A candidate that collides with another row is ignored; the caller retries with a
/// fresh candidate. The insert never overwrites an existing mapping.
pub async fn get_or_create(
    pool: &PgPool,
    kind: &str,
    local_id: &str,
    candidate: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query(
        "INSERT INTO external_id (kind, local_id, external_id) VALUES ($1, $2, $3) \
         ON CONFLICT DO NOTHING",
    )
    .bind(kind)
    .bind(local_id)
    .bind(candidate)
    .execute(pool)
    .await?;
    sqlx::query_scalar::<_, String>(
        "SELECT external_id FROM external_id WHERE kind = $1 AND local_id = $2",
    )
    .bind(kind)
    .bind(local_id)
    .fetch_optional(pool)
    .await
}

/// The dialect id already assigned to a local row, if any.
pub async fn by_local(
    pool: &PgPool,
    kind: &str,
    local_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT external_id FROM external_id WHERE kind = $1 AND local_id = $2",
    )
    .bind(kind)
    .bind(local_id)
    .fetch_optional(pool)
    .await
}

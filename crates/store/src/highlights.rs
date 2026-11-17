//! Tags a profile highlights, the rules an instance publishes, and the languages it has
//! seen.
//!
//! All three are small read-mostly lists that clients put on a profile or an about page.

use sqlx::{FromRow, PgPool};

/// One featured tag as stored.
#[derive(Debug, Clone, FromRow)]
pub struct FeaturedTagRow {
    pub id: String,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// One instance rule as stored.
#[derive(Debug, Clone, FromRow)]
pub struct RuleRow {
    pub id: String,
    pub text: String,
    pub hint: Option<String>,
}

/// One language the instance has seen posts in.
#[derive(Debug, Clone, FromRow)]
pub struct LanguageRow {
    pub code: String,
    pub uses: i64,
}

pub async fn featured_tags(
    pool: &PgPool,
    account_id: &str,
) -> Result<Vec<FeaturedTagRow>, sqlx::Error> {
    sqlx::query_as::<_, FeaturedTagRow>(
        "SELECT id, name, created_at FROM featured_tag \
          WHERE account_id = $1 ORDER BY created_at DESC, id DESC",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
}

/// Highlights a tag, or returns the one already highlighted — a second click on the same
/// tag is not an error.
pub async fn feature_tag(
    pool: &PgPool,
    id: &str,
    account_id: &str,
    name: &str,
) -> Result<FeaturedTagRow, sqlx::Error> {
    sqlx::query_as::<_, FeaturedTagRow>(
        "INSERT INTO featured_tag (id, account_id, name) VALUES ($1, $2, $3) \
         ON CONFLICT (account_id, name) DO UPDATE SET name = featured_tag.name \
         RETURNING id, name, created_at",
    )
    .bind(id)
    .bind(account_id)
    .bind(name)
    .fetch_one(pool)
    .await
}

pub async fn unfeature_tag(pool: &PgPool, account_id: &str, id: &str) -> Result<bool, sqlx::Error> {
    let done = sqlx::query("DELETE FROM featured_tag WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(account_id)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

pub async fn rules(pool: &PgPool) -> Result<Vec<RuleRow>, sqlx::Error> {
    sqlx::query_as::<_, RuleRow>(
        "SELECT id, text, hint FROM instance_rule ORDER BY ord ASC, id ASC",
    )
    .fetch_all(pool)
    .await
}

/// The languages posts on this instance are written in, most used first.
pub async fn languages(pool: &PgPool) -> Result<Vec<LanguageRow>, sqlx::Error> {
    sqlx::query_as::<_, LanguageRow>(
        "SELECT language AS code, COUNT(*)::bigint AS uses FROM status \
          WHERE deleted_at IS NULL AND language IS NOT NULL AND language <> '' \
          GROUP BY language ORDER BY uses DESC LIMIT 20",
    )
    .fetch_all(pool)
    .await
}

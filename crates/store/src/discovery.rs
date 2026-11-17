//! Search and trends.
//!
//! Search here is deliberately local: it reads the instance's own rows, with `ILIKE`
//! rather than a text index, because the corpus a single instance accumulates is small
//! enough that a sequential scan is the cheap answer. Federation lookups are the
//! caller's job — a `resolve=true` search that finds nothing local must not pretend it
//! found something.

use sqlx::{FromRow, PgPool};

use crate::accounts::AccountRow;
use crate::statuses::{StatusRow, STATUS_COLUMNS};

/// An account matching a search term, with the fields the payload needs.
pub async fn search_accounts(
    pool: &PgPool,
    term: &str,
    local_domain: &str,
    limit: i64,
) -> Result<Vec<AccountRow>, sqlx::Error> {
    // `@user@host`, `user@host` and plain `user` all mean the same thing to someone
    // typing into a search box. A handle narrows the answer to that one instance —
    // without the narrowing, `@alice@elsewhere.test` would match every local account,
    // because "user@anything" contains the pattern rather than equalling it.
    let trimmed = term.trim().trim_start_matches('@');
    let (name, host) = match trimmed.rsplit_once('@') {
        Some((name, host)) if !name.is_empty() && !host.is_empty() => {
            (name, Some(host.to_ascii_lowercase()))
        }
        _ => (trimmed, None),
    };
    let pattern = format!("%{name}%");
    let sql = format!(
        "SELECT {} FROM account a \
          WHERE a.suspended_at IS NULL AND a.silenced_at IS NULL \
            AND (a.username::text ILIKE $1 OR a.display_name ILIKE $1) \
            AND ($2::text IS NULL OR LOWER(COALESCE(a.domain::text, $3)) = $2) \
          ORDER BY a.followers_count DESC, a.username ASC LIMIT $4",
        crate::accounts::ACCOUNT_COLUMNS_ALIASED
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(pattern)
        .bind(host)
        .bind(local_domain.to_ascii_lowercase())
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// Statuses whose text matches, restricted to what the searcher may read.
///
/// A term matches either the post's own text or one of its hashtags (`#nodus` and `nodus`
/// both find a post tagged that way), because a reader searching a tag is asking for the
/// posts rather than for the tag's own page. `viewer` narrows to their own non-public
/// posts as well; `None` means only public.
pub async fn search_statuses(
    pool: &PgPool,
    term: &str,
    viewer: Option<&str>,
    limit: i64,
) -> Result<Vec<StatusRow>, sqlx::Error> {
    let pattern = format!("%{}%", term.trim());
    // A hashtag cannot contain whitespace, so a multi-word term only searches text.
    let bare = term.trim().trim_start_matches('#');
    let tag_pattern =
        (!bare.is_empty() && !bare.contains(char::is_whitespace)).then(|| format!("%{bare}%"));
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM status s \
          WHERE s.deleted_at IS NULL AND s.reblog_of_id IS NULL \
            AND (s.content ILIKE $1 OR ($4::text IS NOT NULL AND EXISTS ( \
                  SELECT 1 FROM status_tag t \
                   WHERE t.status_id = s.id AND t.tag::text ILIKE $4))) \
            AND (s.visibility IN ('public', 'unlisted') OR s.account_id = $2) \
          ORDER BY s.id DESC LIMIT $3"
    );
    sqlx::query_as::<_, StatusRow>(&sql)
        .bind(pattern)
        .bind(viewer)
        .bind(limit)
        .bind(tag_pattern)
        .fetch_all(pool)
        .await
}

/// A hashtag and how often it was used.
#[derive(Debug, Clone, FromRow)]
pub struct TagCount {
    pub name: String,
    pub uses: i64,
    /// How many distinct accounts used it, which Mastodon calls `accounts`.
    pub accounts: i64,
}

/// Tags matching a search term, most used first.
pub async fn search_tags(
    pool: &PgPool,
    term: &str,
    limit: i64,
) -> Result<Vec<TagCount>, sqlx::Error> {
    let pattern = format!("%{}%", term.trim_start_matches('#'));
    sqlx::query_as::<_, TagCount>(
        "SELECT t.tag::text AS name, COUNT(*)::bigint AS uses, \
                COUNT(DISTINCT s.account_id)::bigint AS accounts \
           FROM status_tag t JOIN status s ON s.id = t.status_id \
          WHERE s.deleted_at IS NULL AND t.tag::text ILIKE $1 \
          GROUP BY t.tag ORDER BY uses DESC, name ASC LIMIT $2",
    )
    .bind(pattern)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// The tags trending right now, by distinct authors rather than raw uses.
///
/// Distinct authors is the difference between "trending" and "one person posting the
/// same tag forty times", so it is also the sort key.
pub async fn trending_tags(pool: &PgPool, limit: i64) -> Result<Vec<TagCount>, sqlx::Error> {
    sqlx::query_as::<_, TagCount>(
        "SELECT t.tag::text AS name, COUNT(*)::bigint AS uses, \
                COUNT(DISTINCT s.account_id)::bigint AS accounts \
           FROM status_tag t JOIN status s ON s.id = t.status_id \
          WHERE s.deleted_at IS NULL AND s.visibility = 'public' \
            AND s.created_at > now() - interval '7 days' \
          GROUP BY t.tag \
         HAVING COUNT(DISTINCT s.account_id) > 1 \
          ORDER BY accounts DESC, uses DESC, name ASC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// The statuses trending right now, by engagement in the last week.
pub async fn trending_statuses(pool: &PgPool, limit: i64) -> Result<Vec<StatusRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM status s \
          WHERE s.deleted_at IS NULL AND s.reblog_of_id IS NULL \
            AND s.visibility = 'public' AND s.created_at > now() - interval '7 days' \
          ORDER BY (s.favourites_count * 2 + s.reblogs_count * 3 + s.replies_count) DESC, s.id DESC \
          LIMIT $1"
    );
    sqlx::query_as::<_, StatusRow>(&sql)
        .bind(limit)
        .fetch_all(pool)
        .await
}

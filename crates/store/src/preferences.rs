//! Per-account preferences: the defaults a client edits on the Preferences tab.
//!
//! Mastodon answers one flat object of key/value pairs. A row exists only for an account
//! that has changed something; a missing row answers [`Preferences::default`], so a new
//! account reads exactly like an untouched old one and needs no backfill.
//!
//! The key set is a superset of what Mastodon v4.6.3 emits: its serializer includes
//! `posting:default:quote_policy`, so rejecting that key would fail a client that PUTs the
//! map it just read. Mastodon's unreleased main branch also has
//! `posting:default:spoiler_field`; it is deliberately absent until a release this instance
//! claims to match emits it. The notification switches are the other direction: Mastodon
//! v4.6.3 does not emit them, but they are stored for round-tripping and have no effect on
//! this instance (no mailer, no report-notification policy).
//!
//! `posting:default:language` is `null` when the composer should not preselect a language.
//! It cannot be checked against a fixed list: the client's picker is served by
//! `GET /api/v1/instance/languages`, which reflects what this instance has seen. The store
//! therefore accepts `null` or an ISO 639 code (`en`, `fil`, `zh-CN`) and leaves the
//! picker's contents to the client.

use sqlx::{FromRow, PgPool};

use crate::Store;

/// The visibilities a new post may start with.
pub const VISIBILITIES: [&str; 4] = ["public", "unlisted", "private", "direct"];

/// Who may quote a new post. Stored, not enforced: this instance has no quote posts yet.
pub const QUOTE_POLICIES: [&str; 3] = ["public", "followers", "nobody"];

/// How media is expanded in the timeline.
pub const EXPAND_MEDIA: [&str; 3] = ["default", "show_all", "hide_all"];

/// One account's nine preferences, defaults filled in.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the document is a flat set of switches; splitting them would lie about the wire shape"
)]
pub struct Preferences {
    pub visibility: String,
    pub sensitive: bool,
    pub language: Option<String>,
    pub quote_policy: String,
    pub expand_media: String,
    pub expand_spoilers: bool,
    pub autoplay_gifs: bool,
    pub notification_email: bool,
    pub notification_report: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            visibility: "public".to_owned(),
            sensitive: false,
            language: None,
            quote_policy: "public".to_owned(),
            expand_media: "default".to_owned(),
            expand_spoilers: false,
            autoplay_gifs: false,
            notification_email: true,
            notification_report: true,
        }
    }
}

/// Whether `code` is shaped like an ISO 639 language: a two- or three-letter primary tag,
/// optionally followed by an uppercase region (`zh-CN`).
pub fn is_language_code(code: &str) -> bool {
    let mut parts = code.split('-');
    let primary = parts.next().unwrap_or_default();
    let region = parts.next();
    parts.next().is_none()
        && (2..=3).contains(&primary.len())
        && primary.bytes().all(|byte| byte.is_ascii_lowercase())
        && region.is_none_or(|region| {
            region.len() == 2 && region.bytes().all(|byte| byte.is_ascii_uppercase())
        })
}

/// Every preference for one account, defaults when the account has no row.
pub async fn load(pool: &PgPool, account_id: &str) -> Result<Preferences, sqlx::Error> {
    let row = sqlx::query_as::<_, Preferences>(
        "SELECT posting_default_visibility AS visibility, \
                posting_default_sensitive AS sensitive, \
                posting_default_language AS language, \
                posting_default_quote_policy AS quote_policy, \
                reading_expand_media AS expand_media, \
                reading_expand_spoilers AS expand_spoilers, \
                reading_autoplay_gifs AS autoplay_gifs, \
                notification_email, notification_report \
           FROM account_preference WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.unwrap_or_default())
}

/// Writes the whole set, leaving no half-updated row: the API merges a partial request
/// into what it read first, so every column is present here.
pub async fn save(
    pool: &PgPool,
    account_id: &str,
    preferences: &Preferences,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO account_preference ( \
            account_id, posting_default_visibility, posting_default_sensitive, \
            posting_default_language, posting_default_quote_policy, reading_expand_media, \
            reading_expand_spoilers, reading_autoplay_gifs, notification_email, \
            notification_report \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (account_id) DO UPDATE SET \
            posting_default_visibility = EXCLUDED.posting_default_visibility, \
            posting_default_sensitive = EXCLUDED.posting_default_sensitive, \
            posting_default_language = EXCLUDED.posting_default_language, \
            posting_default_quote_policy = EXCLUDED.posting_default_quote_policy, \
            reading_expand_media = EXCLUDED.reading_expand_media, \
            reading_expand_spoilers = EXCLUDED.reading_expand_spoilers, \
            reading_autoplay_gifs = EXCLUDED.reading_autoplay_gifs, \
            notification_email = EXCLUDED.notification_email, \
            notification_report = EXCLUDED.notification_report, \
            updated_at = now()",
    )
    .bind(account_id)
    .bind(&preferences.visibility)
    .bind(preferences.sensitive)
    .bind(preferences.language.as_deref())
    .bind(&preferences.quote_policy)
    .bind(&preferences.expand_media)
    .bind(preferences.expand_spoilers)
    .bind(preferences.autoplay_gifs)
    .bind(preferences.notification_email)
    .bind(preferences.notification_report)
    .execute(pool)
    .await?;
    Ok(())
}

// The API reaches preferences through these two single-subject ops, the way it reaches an
// account through `Store::account`: no handler names a table or holds the pool.
impl Store {
    /// One account's preferences, defaults filled in.
    pub async fn preferences(&self, account_id: &str) -> Result<Preferences, sqlx::Error> {
        load(&self.pool, account_id).await
    }

    /// Replaces one account's preferences with `preferences`.
    pub async fn save_preferences(
        &self,
        account_id: &str,
        preferences: &Preferences,
    ) -> Result<(), sqlx::Error> {
        save(&self.pool, account_id, preferences).await
    }
}

#[cfg(test)]
mod tests {
    use super::is_language_code;

    #[test]
    fn language_codes_are_iso_639_shaped() {
        assert!(is_language_code("en"));
        assert!(is_language_code("fil"));
        assert!(is_language_code("zh-CN"));
        assert!(!is_language_code("english"));
        assert!(!is_language_code("E"));
        assert!(!is_language_code("en-us"));
        assert!(!is_language_code("en-USA"));
    }
}

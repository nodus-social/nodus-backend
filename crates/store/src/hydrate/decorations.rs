//! Tags, custom emoji and mentions: one read for a page, not three per row.
//!
//! All three live in a table beside the status, so a page that fills them in asks the
//! store three times per row. One statement answers all three families for every
//! requested id: `requested` unnests the input once and three correlated aggregates fill
//! it. Keeping them in one statement makes the page's cost a property of the page, and it
//! keeps the three families in the same snapshot, so a status cannot render a tag from
//! before an edit beside a mention from after it.
//!
//! The map is keyed by the requested status id because the caller builds the page by
//! walking its rows; a key lookup cannot reorder what the client paginates by. A status
//! with nothing to decorate is absent rather than an empty entry: "absent" then means one
//! thing, and a padded row would make an empty status and a vanished one look alike.
//!
//! Decoration is not authorisation. The caller asks for the ids its page already holds,
//! after the page query decided what the viewer may see, so nothing here can make a
//! hidden status reveal itself: a hidden status never reaches this function.

use serde::Deserialize;
use sqlx::types::Json;

use super::{Batch, EssentialOp, RowMap};
use crate::statuses::StatusEmoji;

/// What a status carries beside its own columns.
#[derive(Debug, Clone, Default)]
pub struct StatusDecorations {
    /// Hashtags without the leading `#`, in the order a single-status read returns them.
    pub tags: Vec<String>,
    /// Custom emoji in the order the peer sent them.
    pub emojis: Vec<StatusEmoji>,
    /// The accounts the status mentions, ordered by account id.
    pub mentions: Vec<MentionRow>,
}

/// A mentioned account, reduced to what a mention payload is built from.
#[derive(Debug, Clone, Deserialize)]
pub struct MentionRow {
    pub id: String,
    pub username: String,
    pub domain: Option<String>,
}

impl Batch<'_> {
    /// Tags, custom emoji and mentions for these status ids. Essential: a page whose
    /// statuses lost their mentions and hashtags is not the page the client rendered.
    #[must_use]
    pub fn decorations(mut self, ids: &[String]) -> Self {
        self.essential.push(EssentialOp::Decorations(ids.to_vec()));
        self
    }
}

/// One statement for two tables and a join: the alternative is three round trips per page,
/// or one per row, and either way the three families can disagree about the same instant.
pub(super) async fn fetch_decorations<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    status_ids: &[String],
) -> Result<RowMap<StatusDecorations>, sqlx::Error> {
    let rows = sqlx::query_as::<_, DecorationsRow>(
        "WITH requested AS (SELECT unnest($1::text[]) AS status_id), \
         decorated AS ( \
             SELECT r.status_id, \
                    (SELECT array_agg(t.tag::text ORDER BY t.tag::text) \
                       FROM status_tag t WHERE t.status_id = r.status_id) AS tags, \
                    (SELECT jsonb_agg(jsonb_build_object('shortcode', e.shortcode, 'url', e.url) \
                                      ORDER BY e.position, e.shortcode) \
                       FROM status_emoji e WHERE e.status_id = r.status_id) AS emojis, \
                    (SELECT jsonb_agg(jsonb_build_object('id', a.id, 'username', a.username::text, \
                                                         'domain', a.domain::text) \
                                      ORDER BY a.id) \
                       FROM status_mention m JOIN account a ON a.id = m.account_id \
                      WHERE m.status_id = r.status_id) AS mentions \
               FROM requested r \
         ) \
         SELECT status_id, tags, emojis, mentions FROM decorated \
          WHERE tags IS NOT NULL OR emojis IS NOT NULL OR mentions IS NOT NULL",
    )
    .bind(status_ids)
    .fetch_all(executor)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let decorations = StatusDecorations {
                tags: row.tags.unwrap_or_default(),
                emojis: row.emojis.map(|Json(emojis)| emojis).unwrap_or_default(),
                mentions: row
                    .mentions
                    .map(|Json(mentions)| mentions)
                    .unwrap_or_default(),
            };
            (row.status_id, decorations)
        })
        .collect())
}

/// A row of the decoration statement; each family is `NULL` when the status has none.
#[derive(sqlx::FromRow)]
struct DecorationsRow {
    status_id: String,
    tags: Option<Vec<String>>,
    emojis: Option<Json<Vec<StatusEmoji>>>,
    mentions: Option<Json<Vec<MentionRow>>>,
}

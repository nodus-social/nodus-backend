//! Domain reads: a page is one snapshot, not a loop of row lookups.
//!
//! A feed handler knows what a page needs — authors, attachments, reaction chips, the viewer's relationship to each author — and asks for them one row at a time today, because the free functions take one id. One [`Batch`] expresses the whole page, so the query count is a property of the page, not of its length.
//!
//! A page assembled from separate snapshots can show a status whose author row is already gone: the media query sees the attachments, the account query misses the author, and the handler renders a row with attachments and no author (or drops it silently, advancing the client's cursor past a row it never saw). One `REPEATABLE READ READ ONLY` transaction fixes the page to a single point in time. Read-only also means a mistake such as an `UPDATE` inside a batch fails loudly instead of polluting the snapshot.
//!
//! Inside a transaction one failed statement aborts the whole transaction, so an op cannot be "allowed to fail" there. Optional ops therefore run after the essential transaction commits, as their own implicit transactions: a reaction aggregate that errors is reported in [`BatchOutcome::reactions`], and the page still renders without reaction chips. Reads do not fsync, so the extra statement is cheaper than a page that 500s over a decoration.
//!
//! Authorisation has no batch form. `accounts::verify_token` and the API's `can_view_for_viewer` stay one subject at a time: a `can_view(&[id])` invites "check twenty, then serve twenty", and moderation state changed between the check and the serve is a TOCTOU window. The seam does not offer one.

use std::collections::BTreeMap;

use crate::accounts::{AccountRow, ACCOUNT_COLUMNS};
use crate::media::MediaRow;
use crate::social::Relationship;
use crate::statuses::ReactionCount;
use crate::writer::StoreError;
use crate::Store;

/// Results keyed by the id that was asked for; a row that does not exist is absent, never padded (a positional `Vec` either pads with a placeholder or shifts every later row).
pub type RowMap<T> = BTreeMap<String, T>;

/// One page's worth of reads, run together by [`Batch::run`].
pub struct Batch<'a> {
    store: &'a Store,
    essential: Vec<EssentialOp>,
    optional: Vec<OptionalOp>,
}

enum EssentialOp {
    Accounts(Vec<String>),
    MediaByStatus(Vec<String>),
    Relationships(String, Vec<String>),
}

enum OptionalOp {
    Reactions(Vec<String>),
}

impl Store {
    /// Starts a page's read batch.
    pub fn batch(&self) -> Batch<'_> {
        Batch {
            store: self,
            essential: Vec::new(),
            optional: Vec::new(),
        }
    }
}

impl Batch<'_> {
    /// Authors for these account ids. Essential: a page without its authors is not a page.
    #[must_use]
    pub fn accounts(mut self, ids: &[String]) -> Self {
        self.essential.push(EssentialOp::Accounts(ids.to_vec()));
        self
    }

    /// Attachments grouped by the status they belong to. Essential for the same reason.
    #[must_use]
    pub fn media_by_status(mut self, ids: &[String]) -> Self {
        self.essential
            .push(EssentialOp::MediaByStatus(ids.to_vec()));
        self
    }

    /// The viewer's relationship to each account. Essential: block and mute flags are part of how the page renders, and a missing flag is a rendering lie.
    #[must_use]
    pub fn relationships(mut self, viewer: &str, ids: &[String]) -> Self {
        self.essential
            .push(EssentialOp::Relationships(viewer.to_owned(), ids.to_vec()));
        self
    }

    /// Reaction counts per status. Optional: a feed without reaction chips is still a feed, so this op may fail without taking the page with it.
    #[must_use]
    pub fn reactions(mut self, ids: &[String]) -> Self {
        self.optional.push(OptionalOp::Reactions(ids.to_vec()));
        self
    }

    /// Runs the essential ops in one snapshot, then the optional ops after it.
    ///
    /// # Errors
    ///
    /// Returns the first essential op's failure; optional failures are reported per slot in the outcome instead.
    pub async fn run(self) -> Result<BatchOutcome, StoreError> {
        // `begin_with` so the isolation level is part of the transaction's first statement; `SET TRANSACTION` after a query would be rejected by Postgres.
        let mut tx = self
            .store
            .pool()
            .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .await?;
        let mut outcome = BatchOutcome {
            accounts: RowMap::new(),
            media_by_status: RowMap::new(),
            relationships: RowMap::new(),
            reactions: Ok(RowMap::new()),
            snapshots_opened: 1,
        };
        for op in &self.essential {
            match op {
                EssentialOp::Accounts(ids) => {
                    outcome.accounts = fetch_accounts(&mut *tx, ids).await?;
                }
                EssentialOp::MediaByStatus(ids) => {
                    outcome.media_by_status = fetch_media(&mut *tx, ids).await?;
                }
                EssentialOp::Relationships(viewer, ids) => {
                    outcome.relationships = fetch_relationships(&mut *tx, viewer, ids).await?;
                }
            }
        }
        tx.commit().await?;
        for op in &self.optional {
            let OptionalOp::Reactions(ids) = op;
            outcome.reactions = fetch_reactions(self.store.pool(), ids)
                .await
                .map_err(Into::into);
        }
        Ok(outcome)
    }
}

/// The page, after [`Batch::run`].
pub struct BatchOutcome {
    /// Authors, keyed by account id.
    pub accounts: RowMap<AccountRow>,
    /// Attachments, keyed by status id; a status with none is absent.
    pub media_by_status: RowMap<Vec<MediaRow>>,
    /// Relationships, keyed by the target account id that was asked for.
    pub relationships: RowMap<Relationship>,
    /// Reaction counts, keyed by status id, or the optional op's failure.
    pub reactions: Result<RowMap<Vec<ReactionCount>>, StoreError>,
    /// How many snapshot transactions this batch opened: a test asserts a four-op page costs one.
    pub snapshots_opened: usize,
}

async fn fetch_accounts<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    ids: &[String],
) -> Result<RowMap<AccountRow>, sqlx::Error> {
    let sql = format!("SELECT {ACCOUNT_COLUMNS} FROM account WHERE id = ANY($1)");
    let rows = sqlx::query_as::<_, AccountRow>(&sql)
        .bind(ids)
        .fetch_all(executor)
        .await?;
    Ok(rows.into_iter().map(|row| (row.id.clone(), row)).collect())
}

async fn fetch_media<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    status_ids: &[String],
) -> Result<RowMap<Vec<MediaRow>>, sqlx::Error> {
    let mut map: RowMap<Vec<MediaRow>> = RowMap::new();
    // `m.*` plus the derived `remote_url` is the shape of `media::by_statuses` (`crates/store/src/media.rs:118`) without a second copy of its private column list; `FromRow` ignores the extra `meta` column.
    let rows = sqlx::query_as::<_, MediaRow>(
        "SELECT m.*, NULLIF(m.meta->>'url', '') AS remote_url FROM media_attachment m \
          WHERE m.status_id = ANY($1) ORDER BY m.created_at ASC, m.id ASC",
    )
    .bind(status_ids)
    .fetch_all(executor)
    .await?;
    for row in rows {
        if let Some(status_id) = row.status_id.clone() {
            map.entry(status_id).or_default().push(row);
        }
    }
    Ok(map)
}

async fn fetch_reactions<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    status_ids: &[String],
) -> Result<RowMap<Vec<ReactionCount>>, sqlx::Error> {
    let mut map: RowMap<Vec<ReactionCount>> = RowMap::new();
    // Per-status ordering matches `statuses::reactions`, so a batched page and a single-status page cannot disagree about "most common first".
    let rows = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT status_id, reaction, COUNT(*)::bigint AS count FROM status_reaction \
          WHERE status_id = ANY($1) GROUP BY status_id, reaction \
          ORDER BY status_id, count DESC, reaction ASC",
    )
    .bind(status_ids)
    .fetch_all(executor)
    .await?;
    for (status_id, reaction, count) in rows {
        map.entry(status_id)
            .or_default()
            .push(ReactionCount { reaction, count });
    }
    Ok(map)
}

async fn fetch_relationships<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    viewer: &str,
    ids: &[String],
) -> Result<RowMap<Relationship>, sqlx::Error> {
    // One pass over the requested ids. The scalar `social::relationship` asks the same questions with four correlated `EXISTS` subqueries per call, which a page of twenty ids pays twenty times.
    let rows = sqlx::query_as::<_, RelationshipKeyRow>(
        "SELECT t.target_id, f.state, f.reblogs, f.notify, \
                b.account_id IS NOT NULL, m.account_id IS NOT NULL, COALESCE(m.notifications, false), \
                back.state IS NOT NULL, bb.account_id IS NOT NULL \
           FROM unnest($2::text[]) AS t(target_id) \
           LEFT JOIN follow f ON f.account_id = $1 AND f.target_account_id = t.target_id \
           LEFT JOIN account_relation b ON b.account_id = $1 AND b.target_account_id = t.target_id AND b.kind = 'block' \
           LEFT JOIN account_relation m ON m.account_id = $1 AND m.target_account_id = t.target_id AND m.kind = 'mute' \
           LEFT JOIN follow back ON back.account_id = t.target_id AND back.target_account_id = $1 AND back.state = 'accepted' \
           LEFT JOIN account_relation bb ON bb.account_id = t.target_id AND bb.target_account_id = $1 AND bb.kind = 'block'",
    )
    .bind(viewer)
    .bind(ids)
    .fetch_all(executor)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let relationship = Relationship {
                following: row.1.as_deref() == Some("accepted"),
                requested: row.1.as_deref() == Some("pending"),
                showing_reblogs: row.2.unwrap_or(false),
                notifying: row.3.unwrap_or(false),
                blocked: row.4,
                muting: row.5,
                muting_notifications: row.6,
                followed_by: row.7,
                blocked_by: row.8,
            };
            (row.0, relationship)
        })
        .collect())
}

/// `(target id, follow state, reblogs, notify, blocked, muting, notify-on-mute, followed by, blocked by)`.
type RelationshipKeyRow = (
    String,
    Option<String>,
    Option<bool>,
    Option<bool>,
    bool,
    bool,
    bool,
    bool,
    bool,
);

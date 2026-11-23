//! Domain reads: a page is one snapshot, not a loop of row lookups.
//!
//! A feed handler knows what a page needs — authors, attachments, reaction chips, the viewer's relationship to each author — and asks for them one row at a time today, because the free functions take one id. One [`Batch`] expresses the whole page, so the query count is a property of the page, not of its length.
//!
//! A feed handler knows what a page needs — authors, attachments, reaction chips, polls, the viewer's relationship to each author — and asks for them one row at a time today, because the free functions take one id. One [`Batch`] expresses the whole page, so the query count is a property of the page, not of its length.
//!
//! Inside a transaction one failed statement aborts the whole transaction, so an op cannot be "allowed to fail" there. Optional ops therefore run after the essential transaction commits, as their own implicit transactions: a reaction aggregate that errors is reported in [`BatchOutcome::reactions`], and the page still renders without reaction chips. Reads do not fsync, so the extra statement is cheaper than a page that 500s over a decoration.
//!
//! Authorisation has no batch form. `accounts::verify_token` and the API's `can_view_for_viewer` stay one subject at a time: a `can_view(&[id])` invites "check twenty, then serve twenty", and moderation state changed between the check and the serve is a TOCTOU window. The seam does not offer one.

mod decorations;
mod external_ids;
mod polls;
mod probe;
mod profile_pictures;
mod relationships;

pub use decorations::{MentionRow, StatusDecorations};
pub use external_ids::ExternalIds;
pub use polls::PollFacts;
#[doc(hidden)]
pub use probe::TransactionSettings;
pub use profile_pictures::{PictureSize, ProfilePictures};

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
    Decorations(Vec<String>),
    ExternalIds {
        statuses: Vec<String>,
        accounts: Vec<String>,
    },
    Polls {
        statuses: Vec<String>,
        viewer: Option<String>,
    },
    ProfilePictures(Vec<String>),
    TransactionSettings,
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

    /// Polls attached to these statuses, tallies and the viewer's choices included. Essential: a poll that vanished from a status is a lie.
    #[must_use]
    pub fn polls(mut self, ids: &[String], viewer: Option<&str>) -> Self {
        self.essential.push(EssentialOp::Polls {
            statuses: ids.to_vec(),
            viewer: viewer.map(ToOwned::to_owned),
        });
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
            decorations: RowMap::new(),
            external_ids: ExternalIds::default(),
            polls: RowMap::new(),
            profile_pictures: RowMap::new(),
            reactions: Ok(RowMap::new()),
            transaction_settings: None,
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
                    outcome.relationships =
                        relationships::fetch_relationships(&mut *tx, viewer, ids).await?;
                }
                EssentialOp::Decorations(ids) => {
                    outcome.decorations = decorations::fetch_decorations(&mut *tx, ids).await?;
                }
                EssentialOp::ExternalIds { statuses, accounts } => {
                    outcome.external_ids =
                        external_ids::fetch_external_ids(&mut *tx, statuses, accounts).await?;
                }
                EssentialOp::Polls { statuses, viewer } => {
                    outcome.polls =
                        polls::fetch_polls(&mut tx, statuses, viewer.as_deref()).await?;
                }
                EssentialOp::ProfilePictures(ids) => {
                    outcome.profile_pictures =
                        profile_pictures::fetch_profile_pictures(&mut *tx, ids).await?;
                }
                EssentialOp::TransactionSettings => {
                    outcome.transaction_settings =
                        Some(probe::fetch_transaction_settings(&mut *tx).await?);
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
    /// Tags, custom emoji and mentions, keyed by status id; a status with none is absent.
    pub decorations: RowMap<StatusDecorations>,
    /// Dialect ids, keyed by the local id that was asked for; an unmapped id is absent.
    pub external_ids: ExternalIds,
    /// Polls keyed by status id, tallies counted; a status with none is absent.
    pub polls: RowMap<PollFacts>,
    /// Rendered profile picture shapes keyed by account id; a picture with no variant is
    /// absent.
    pub profile_pictures: RowMap<ProfilePictures>,
    /// Reaction counts, keyed by status id, or the optional op's failure.
    pub reactions: Result<RowMap<Vec<ReactionCount>>, StoreError>,
    /// What Postgres reported about the essential transaction, when the test-only
    /// [`Batch::transaction_settings`] op ran. `None` otherwise.
    #[doc(hidden)]
    pub transaction_settings: Option<TransactionSettings>,
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

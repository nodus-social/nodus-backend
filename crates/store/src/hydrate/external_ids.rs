//! A page's dialect ids, read once instead of row by row.
//!
//! Misskey names a note and its author with a dialect-local id, so a page that renders
//! twenty notes used to ask `external_id` twice per note. The page already knows the
//! local ids it will render; one statement answers both kinds for the whole page.
//!
//! The result is two [`RowMap`]s keyed by the local id that was asked for, because the
//! caller walks its page rows and cannot use a positional answer. A local id with no
//! mapping is absent rather than a placeholder: the caller treats absence as "not
//! allocated yet" and creates the mapping, which is a write and cannot live in the
//! read-only snapshot.

use super::{Batch, EssentialOp, RowMap};

/// Dialect ids for one page, keyed by the local id that was asked for.
#[derive(Debug, Clone, Default)]
pub struct ExternalIds {
    /// Status id → dialect id.
    pub statuses: RowMap<String>,
    /// Account id → dialect id.
    pub accounts: RowMap<String>,
}

impl ExternalIds {
    /// The dialect id for a local row of `kind` (`status` or `account`), when the page
    /// read found one.
    #[must_use]
    pub fn get(&self, kind: &str, local_id: &str) -> Option<&String> {
        match kind {
            "status" => self.statuses.get(local_id),
            "account" => self.accounts.get(local_id),
            _ => None,
        }
    }
}

impl Batch<'_> {
    /// Dialect ids for these statuses and accounts. Essential: every note must carry an
    /// id the client can address.
    ///
    /// Two id lists rather than `(kind, id)` pairs because a Misskey page has exactly
    /// these two kinds; a generic op would cost one statement per kind and double the
    /// page's dialect-id reads.
    #[must_use]
    pub fn external_ids(mut self, statuses: &[String], accounts: &[String]) -> Self {
        self.essential.push(EssentialOp::ExternalIds {
            statuses: statuses.to_vec(),
            accounts: accounts.to_vec(),
        });
        self
    }
}

/// One statement for both kinds. Ids without a row are absent from the result.
pub(super) async fn fetch_external_ids<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    statuses: &[String],
    accounts: &[String],
) -> Result<ExternalIds, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String, String, String)>(
        "SELECT kind, local_id, external_id FROM external_id \
          WHERE (kind = 'status' AND local_id = ANY($1)) \
             OR (kind = 'account' AND local_id = ANY($2))",
    )
    .bind(statuses)
    .bind(accounts)
    .fetch_all(executor)
    .await?;
    let mut outcome = ExternalIds::default();
    for (kind, local_id, external_id) in rows {
        match kind.as_str() {
            "status" => {
                outcome.statuses.insert(local_id, external_id);
            }
            "account" => {
                outcome.accounts.insert(local_id, external_id);
            }
            _ => {}
        }
    }
    Ok(outcome)
}

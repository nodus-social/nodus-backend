//! What Postgres says about the batch's transaction, so a test can prove the isolation
//! instead of trusting the line that opened it.
//!
//! The seam's promise is that a page is read in one `REPEATABLE READ READ ONLY`
//! transaction. A test that asserts a counter the seam maintains proves the counter; this
//! op asks the database, from inside the transaction, what isolation and access mode it is
//! actually running under, so the promise is checked where it is enforced.

use super::{Batch, EssentialOp};

/// The transaction settings Postgres reported for the batch that ran this op.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionSettings {
    /// `current_setting('transaction_isolation')`, e.g. `repeatable read`.
    pub isolation: String,
    /// `current_setting('transaction_read_only')`, `on` or `off`.
    pub read_only: String,
}

impl Batch<'_> {
    /// Adds an essential op that records the settings Postgres sees inside the batch.
    ///
    /// Test-only, and `#[doc(hidden)]` rather than `#[cfg(test)]` because an integration
    /// test links the crate without `cfg(test)`; production callers have no use for it.
    #[doc(hidden)]
    #[must_use]
    pub fn transaction_settings(mut self) -> Self {
        self.essential.push(EssentialOp::TransactionSettings);
        self
    }
}

pub(super) async fn fetch_transaction_settings<'e>(
    executor: impl sqlx::PgExecutor<'e>,
) -> Result<TransactionSettings, sqlx::Error> {
    let (isolation, read_only) = sqlx::query_as::<_, (String, String)>(
        "SELECT current_setting('transaction_isolation'), current_setting('transaction_read_only')",
    )
    .fetch_one(executor)
    .await?;
    Ok(TransactionSettings {
        isolation,
        read_only,
    })
}

//! The transactional outbox.
//!
//! A message is inserted by the same transaction that creates the state it announces, so
//! there is no window in which an account exists and its confirmation was never recorded.
//! Delivery is a separate loop: the request has already answered by the time a socket is
//! opened, and a mail server that is down can only delay this table.
//!
//! `attempts` and `last_error` are the operator's view of a stuck message; after
//! [`MAX_ATTEMPTS`] the row is left in place instead of being retried forever.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::store::Error;
use nodus_mail::{Message, Transport};

/// How often a message is tried before it is left failed for an operator to inspect.
pub const MAX_ATTEMPTS: i32 = 5;

const BATCH: i64 = 20;
const POLL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeliveryReport {
    pub sent: usize,
    pub failed: usize,
}

/// Inserts a message using the caller's transaction or pool.
///
/// Taking an executor rather than the pool is the whole point: registration passes its
/// open transaction, so the mail row and the account commit or roll back together.
///
/// # Errors
///
/// Fails only on the database; a mail server is not contacted here.
pub async fn enqueue<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    message: &Message,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO email_outbox (id, recipient, subject, body_text, body_html) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(ulid::Ulid::new().to_string())
    .bind(&message.to)
    .bind(&message.subject)
    .bind(&message.text)
    .bind(message.html.as_deref().unwrap_or(""))
    .execute(executor)
    .await?;
    Ok(())
}

/// Sends every message that is still owed and returns what happened.
///
/// One message's failure does not stop the batch: a single bad recipient must not hold
/// back the confirmations queued behind it.
///
/// # Errors
///
/// Fails when the queue cannot be read. Transport failures are recorded per row.
pub async fn deliver_due(
    pool: &PgPool,
    transport: &dyn Transport,
) -> Result<DeliveryReport, Error> {
    let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT id, recipient::text, subject, body_text, body_html FROM email_outbox \
         WHERE sent_at IS NULL AND attempts < $1 ORDER BY created_at LIMIT $2",
    )
    .bind(MAX_ATTEMPTS)
    .bind(BATCH)
    .fetch_all(pool)
    .await?;

    let mut report = DeliveryReport::default();
    for (id, to, subject, text, html) in rows {
        let message = Message {
            to,
            subject,
            text,
            html: (!html.is_empty()).then_some(html),
        };
        match transport.send(&message).await {
            Ok(()) => {
                sqlx::query("UPDATE email_outbox SET sent_at = now() WHERE id = $1")
                    .bind(&id)
                    .execute(pool)
                    .await?;
                report.sent += 1;
            }
            Err(error) => {
                sqlx::query(
                    "UPDATE email_outbox SET attempts = attempts + 1, last_error = $2 \
                     WHERE id = $1",
                )
                .bind(&id)
                .bind(error.to_string())
                .execute(pool)
                .await?;
                tracing::warn!(%error, id = %id, "mail delivery failed");
                report.failed += 1;
            }
        }
    }
    Ok(report)
}

/// Delivers until the process stops.
///
/// The first pass runs immediately, so a restart drains mail that was queued while the
/// previous process was exiting rather than waiting out a poll interval.
pub async fn run(pool: PgPool, transport: Arc<dyn Transport>) {
    let mut ticker = tokio::time::interval(POLL);
    loop {
        ticker.tick().await;
        match deliver_due(&pool, transport.as_ref()).await {
            Ok(report) if report.sent > 0 || report.failed > 0 => {
                tracing::info!(sent = report.sent, failed = report.failed, "mail delivered");
            }
            Ok(_) => {}
            Err(error) => tracing::error!(%error, "mail queue could not be read"),
        }
    }
}

/// A queued confirmation: the token the link carries, not the raw one.
#[derive(Debug, Clone)]
pub struct Confirmation {
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub message: Message,
}

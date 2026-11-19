//! Running the instance's moderation rules while a post is stored.
//!
//! Two places call this: a note ingested from another instance (`inbound`) and a post one
//! of our accounts publishes (`local`). Both hand over the stored row and the plain text,
//! not the request, so the same rules act on a scheduled post and on a delivery retry.
//!
//! It cannot fail a request. The post is already written by the time this runs, and a
//! delivery that is refused after the row exists is a delivery the peer will send again
//! forever. A broken rule is logged, and the store records it in the audit log as
//! `moderation_rule_error` so it is visible rather than merely quiet.

use sqlx::PgPool;

use nodus_server_store::moderation_rules;

/// Tests `text` against the enabled rules for `scope` and applies what matches.
pub async fn screen(pool: &PgPool, scope: &str, status_id: &str, account_id: &str, text: &str) {
    let mut conn = match pool.acquire().await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, status = %status_id, "moderation rules could not run: no connection");
            return;
        }
    };
    match moderation_rules::screen(&mut conn, scope, status_id, account_id, text).await {
        Ok(fired) => {
            for rule in fired {
                tracing::info!(
                    rule = %rule.rule_name,
                    rule_id = %rule.rule_id,
                    action = %rule.action,
                    status = %status_id,
                    "moderation rule applied"
                );
            }
        }
        Err(error) => {
            tracing::warn!(%error, status = %status_id, "moderation rules could not run");
        }
    }
}

//! Web Push subscriptions: where a browser wants notifications delivered.
//!
//! One row per (account, endpoint). The endpoint is the browser's own push service URL and
//! the two key columns are the material a sender encrypts with; this module stores them and
//! nothing more, because delivery and encryption are slice 2. The store is still the place
//! that owns the rule "a second POST of the same endpoint updates rather than duplicates":
//! [`upsert`] is one statement on the unique `(account_id, endpoint)` pair.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};

/// One stored subscription.
#[derive(Debug, Clone, FromRow)]
pub struct SubscriptionRow {
    pub id: String,
    pub account_id: String,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
    pub alerts: Value,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub failure_count: i32,
}

const COLUMNS: &str = "id, account_id, endpoint, p256dh, auth, alerts, user_agent, \
                       created_at, last_success_at, failure_count";

/// Every subscription this account has, newest first.
///
/// A browser profile is a subscription, so the list is the account's device list. Ordering
/// by creation keeps the newest first, which is also the row [`get`] answers.
pub async fn list(pool: &PgPool, account_id: &str) -> Result<Vec<SubscriptionRow>, sqlx::Error> {
    sqlx::query_as::<_, SubscriptionRow>(&format!(
        "SELECT {COLUMNS} FROM push_subscription \
          WHERE account_id = $1 ORDER BY created_at DESC, id DESC"
    ))
    .bind(account_id)
    .fetch_all(pool)
    .await
}

/// The account's current subscription, or `None`.
///
/// Mastodon's `GET /api/v1/push/subscription` answers one entity without naming an
/// endpoint. This instance may hold several (one per browser), so "current" is the most
/// recently created row; [`list`] is the full device list behind it.
pub async fn get(pool: &PgPool, account_id: &str) -> Result<Option<SubscriptionRow>, sqlx::Error> {
    sqlx::query_as::<_, SubscriptionRow>(&format!(
        "SELECT {COLUMNS} FROM push_subscription \
          WHERE account_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1"
    ))
    .bind(account_id)
    .fetch_optional(pool)
    .await
}

/// Creates the row, or updates the one already at this endpoint.
///
/// Browsers rotate their keys under a stable endpoint, so the conflict branch replaces both
/// key columns and the alert map. A resubscribe is a fresh start for the delivery counters:
/// the old key has never succeeded, and the old failures say nothing about the new one. The
/// `id` and `created_at` stay, so the same browser remains the same subscription to a
/// client that wrote it down.
pub async fn upsert(
    pool: &PgPool,
    account_id: &str,
    endpoint: &str,
    p256dh: &str,
    auth: &str,
    alerts: &Value,
    user_agent: Option<&str>,
) -> Result<SubscriptionRow, sqlx::Error> {
    sqlx::query_as::<_, SubscriptionRow>(&format!(
        "INSERT INTO push_subscription \
             (id, account_id, endpoint, p256dh, auth, alerts, user_agent) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (account_id, endpoint) DO UPDATE \
            SET p256dh = EXCLUDED.p256dh, \
                auth = EXCLUDED.auth, \
                alerts = EXCLUDED.alerts, \
                user_agent = COALESCE(EXCLUDED.user_agent, push_subscription.user_agent), \
                last_success_at = NULL, \
                failure_count = 0 \
         RETURNING {COLUMNS}"
    ))
    .bind(nodus_server_core::Id::new().to_string())
    .bind(account_id)
    .bind(endpoint)
    .bind(p256dh)
    .bind(auth)
    .bind(alerts)
    .bind(user_agent)
    .fetch_one(pool)
    .await
}

/// Replaces the alert map of the account's current subscription.
///
/// `PUT /api/v1/push/subscription` carries alerts only. `None` means there is no row to
/// update, which the API answers as Mastodon's 404.
pub async fn update_alerts(
    pool: &PgPool,
    account_id: &str,
    alerts: &Value,
) -> Result<Option<SubscriptionRow>, sqlx::Error> {
    sqlx::query_as::<_, SubscriptionRow>(&format!(
        "UPDATE push_subscription SET alerts = $2 \
          WHERE id = ( \
              SELECT id FROM push_subscription \
               WHERE account_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1 \
          ) \
         RETURNING {COLUMNS}"
    ))
    .bind(account_id)
    .bind(alerts)
    .fetch_optional(pool)
    .await
}

/// Removes one subscription. `false` means the pair was already gone.
///
/// The account id is part of the predicate, so one account can never delete another's row
/// even if it learns the endpoint.
pub async fn delete(pool: &PgPool, account_id: &str, endpoint: &str) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("DELETE FROM push_subscription WHERE account_id = $1 AND endpoint = $2")
            .bind(account_id)
            .bind(endpoint)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() == 1)
}

/// Counts one failed delivery. The row survives on purpose: a stale endpoint is identified
/// (its count is high) and retired by the delivery slice, not by the failure that noticed it.
pub async fn record_failure(
    pool: &PgPool,
    account_id: &str,
    endpoint: &str,
) -> Result<Option<SubscriptionRow>, sqlx::Error> {
    sqlx::query_as::<_, SubscriptionRow>(&format!(
        "UPDATE push_subscription SET failure_count = failure_count + 1 \
          WHERE account_id = $1 AND endpoint = $2 \
         RETURNING {COLUMNS}"
    ))
    .bind(account_id)
    .bind(endpoint)
    .fetch_optional(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{self, NewAccount};

    async fn create_account(pool: &PgPool, label: &str) -> String {
        let username = format!("push_test_{label}_{}", nodus_server_core::Id::new()).to_lowercase();
        accounts::insert(
            pool,
            &NewAccount {
                username: &username,
                display_name: &username,
                note: "",
                bot: false,
                locked: false,
            },
        )
        .await
        .expect("insert account")
        .id
    }

    fn alerts(mention: bool) -> Value {
        serde_json::json!({
            "mention": mention,
            "reblog": true,
            "follow": true,
            "follow_request": true,
            "favourite": true,
            "poll": true,
            "status": true,
            "update": true,
            "admin.sign_up": true,
            "admin.report": true,
        })
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn push_subscription_round_trips_and_a_repeat_upsert_updates_in_place(pool: PgPool) {
        let account = create_account(&pool, "round-trip").await;

        let first = upsert(
            &pool,
            &account,
            "https://push.example/one",
            "p256dh-one",
            "auth-one",
            &alerts(true),
            Some("Firefox on Linux"),
        )
        .await
        .expect("insert subscription");
        assert_eq!(first.failure_count, 0);
        assert_eq!(first.user_agent.as_deref(), Some("Firefox on Linux"));

        let second = upsert(
            &pool,
            &account,
            "https://push.example/one",
            "p256dh-two",
            "auth-two",
            &alerts(false),
            None,
        )
        .await
        .expect("upsert same endpoint");

        assert_eq!(
            second.id, first.id,
            "the same endpoint is the same subscription"
        );
        assert_eq!(second.p256dh, "p256dh-two");
        assert_eq!(second.auth, "auth-two");
        assert_eq!(second.alerts["mention"], Value::Bool(false));
        assert_eq!(
            second.user_agent.as_deref(),
            Some("Firefox on Linux"),
            "a repeat POST with no User-Agent keeps the name already stored"
        );

        let rows = list(&pool, &account).await.expect("list");
        assert_eq!(rows.len(), 1, "a repeat POST must not duplicate the row");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn push_rotated_key_replaces_the_old_one(pool: PgPool) {
        let account = create_account(&pool, "rotation").await;
        upsert(
            &pool,
            &account,
            "https://push.example/rotate",
            "old-key",
            "old-auth",
            &alerts(true),
            None,
        )
        .await
        .expect("insert");
        let rotated = upsert(
            &pool,
            &account,
            "https://push.example/rotate",
            "new-key",
            "new-auth",
            &alerts(true),
            None,
        )
        .await
        .expect("rotate");

        assert_eq!(rotated.p256dh, "new-key");
        assert_eq!(rotated.auth, "new-auth");
        let stored: Vec<String> =
            sqlx::query_scalar("SELECT p256dh FROM push_subscription WHERE account_id = $1")
                .bind(&account)
                .fetch_all(&pool)
                .await
                .expect("read back");
        assert_eq!(stored, vec!["new-key".to_owned()]);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn push_delete_removes_only_the_callers_row(pool: PgPool) {
        let alice = create_account(&pool, "delete-alice").await;
        let bob = create_account(&pool, "delete-bob").await;
        let endpoint = "https://push.example/shared-endpoint";

        upsert(
            &pool,
            &alice,
            endpoint,
            "alice-key",
            "alice-auth",
            &alerts(true),
            None,
        )
        .await
        .expect("alice");
        upsert(
            &pool,
            &bob,
            endpoint,
            "bob-key",
            "bob-auth",
            &alerts(true),
            None,
        )
        .await
        .expect("bob");

        assert!(delete(&pool, &alice, endpoint).await.expect("delete alice"));
        assert!(get(&pool, &alice).await.expect("alice get").is_none());
        let bobs = get(&pool, &bob)
            .await
            .expect("bob get")
            .expect("bob survives");
        assert_eq!(bobs.p256dh, "bob-key");
        assert!(
            !delete(&pool, &alice, endpoint)
                .await
                .expect("second delete"),
            "deleting an absent row is not an error but reports it removed nothing"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn push_record_failure_increments_and_keeps_the_row(pool: PgPool) {
        let account = create_account(&pool, "failure").await;
        let endpoint = "https://push.example/failing";
        upsert(
            &pool,
            &account,
            endpoint,
            "key",
            "auth",
            &alerts(true),
            None,
        )
        .await
        .expect("insert");

        let first = record_failure(&pool, &account, endpoint)
            .await
            .expect("record")
            .expect("row still exists");
        let second = record_failure(&pool, &account, endpoint)
            .await
            .expect("record")
            .expect("row still exists");

        assert_eq!(first.failure_count, 1);
        assert_eq!(second.failure_count, 2);
        assert!(get(&pool, &account).await.expect("get").is_some());
        assert!(
            record_failure(&pool, &account, "https://push.example/absent")
                .await
                .expect("record absent")
                .is_none()
        );
    }
}

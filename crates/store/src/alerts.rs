//! Persistent administrator alerts for abuse signals.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};

use nodus_server_core::Id;

/// One alert row.
#[derive(Debug, Clone, FromRow)]
pub struct AlertRow {
    pub id: String,
    pub kind: String,
    pub severity: String,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<i32>,
    pub remote_ip: Option<String>,
    pub account_id: Option<String>,
    pub detail: Value,
    pub created_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
}

/// One abuse signal to persist.
#[derive(Debug, Clone, Copy)]
pub struct NewAlert<'a> {
    pub kind: &'a str,
    pub method: Option<&'a str>,
    pub path: Option<&'a str>,
    pub status: Option<i32>,
    pub remote_ip: Option<&'a str>,
    pub account_id: Option<&'a str>,
    pub detail: &'a Value,
}

/// Record one abuse signal. Errors are the caller's to log; an alert must never
/// turn a rejected request into a server error.
pub async fn record(pool: &PgPool, alert: &NewAlert<'_>) -> Result<AlertRow, sqlx::Error> {
    let id = Id::new().to_string();
    sqlx::query_as::<_, AlertRow>(
        "INSERT INTO admin_alert
            (id, kind, method, path, status, remote_ip, account_id, detail)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *",
    )
    .bind(&id)
    .bind(alert.kind)
    .bind(alert.method)
    .bind(alert.path)
    .bind(alert.status)
    .bind(alert.remote_ip)
    .bind(alert.account_id)
    .bind(alert.detail)
    .fetch_one(pool)
    .await
}

/// Newest alerts, optionally only unacknowledged ones.
pub async fn recent(
    pool: &PgPool,
    limit: i64,
    unacknowledged: bool,
) -> Result<Vec<AlertRow>, sqlx::Error> {
    let sql = if unacknowledged {
        "SELECT * FROM admin_alert WHERE acknowledged_at IS NULL ORDER BY created_at DESC LIMIT $1"
    } else {
        "SELECT * FROM admin_alert ORDER BY created_at DESC LIMIT $1"
    };
    sqlx::query_as::<_, AlertRow>(sql)
        .bind(limit.clamp(1, 200))
        .fetch_all(pool)
        .await
}

/// Acknowledge one alert by an administrator.
pub async fn acknowledge(pool: &PgPool, id: &str, admin_id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE admin_alert SET acknowledged_at = now(), acknowledged_by = $2
         WHERE id = $1 AND acknowledged_at IS NULL",
    )
    .bind(id)
    .bind(admin_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

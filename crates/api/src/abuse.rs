//! Abuse logging.
//!
//! Rejected authentication, authorisation and throttling responses are both logged
//! and persisted so an administrator can review them after the fact. Recording is
//! best-effort: a failed insert never changes the response the client sees.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use serde_json::json;

use crate::state::AppState;

/// Log and persist abuse-shaped rejections.
pub async fn record(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    let remote_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip().to_string());

    let response = next.run(request).await;
    let status = response.status();
    if !matches!(
        status,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
    ) {
        return response;
    }

    let kind = match status {
        StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        StatusCode::FORBIDDEN => "forbidden",
        _ => "authentication_failed",
    };
    tracing::warn!(
        abuse = kind,
        %method,
        %path,
        status = status.as_u16(),
        remote_ip = remote_ip.as_deref().unwrap_or("-"),
        "rejected request"
    );

    // A client that retries a refused request produces identical rows, and a console that
    // has no grant yet retries on every redraw: one alert per shape per window keeps the
    // review list readable without hiding a new kind of refusal.
    if !should_record(&shape(kind, &method, &path, status, remote_ip.as_deref())) {
        return response;
    }

    let pool = state.store().pool().clone();
    let detail = json!({ "user_agent": "-" });
    tokio::spawn(async move {
        let alert = nodus_server_store::alerts::NewAlert {
            kind,
            method: Some(&method),
            path: Some(&path),
            status: Some(i32::from(status.as_u16())),
            remote_ip: remote_ip.as_deref(),
            account_id: None,
            detail: &detail,
        };
        if let Err(error) = nodus_server_store::alerts::record(&pool, &alert).await {
            tracing::warn!(%error, "could not persist admin alert");
        }
    });
    response
}

/// How long one refusal shape is remembered before it is recorded again.
const WINDOW: Duration = Duration::from_secs(60);

/// Identifies a refusal by what was asked, from where, and how it was answered.
fn shape(
    kind: &str,
    method: &str,
    path: &str,
    status: StatusCode,
    remote_ip: Option<&str>,
) -> String {
    format!(
        "{kind}\u{1f}{method}\u{1f}{path}\u{1f}{}\u{1f}{}",
        status.as_u16(),
        remote_ip.unwrap_or("-")
    )
}

fn recent() -> &'static Mutex<HashMap<String, Instant>> {
    static RECENT: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    RECENT.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether this refusal is worth a second look by a person.
fn should_record(key: &str) -> bool {
    should_record_at(key, Instant::now())
}

fn should_record_at(key: &str, now: Instant) -> bool {
    let Ok(mut seen) = recent().lock() else {
        return true;
    };
    seen.retain(|_, at| now.duration_since(*at) < WINDOW);
    if seen.contains_key(key) {
        return false;
    }
    seen.insert(key.to_owned(), now);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shape_is_recorded_once_per_window() {
        let now = Instant::now();
        let key = shape(
            "authentication_failed",
            "GET",
            "/api/v1/accounts/1/statuses",
            StatusCode::UNAUTHORIZED,
            Some("10.0.1.1"),
        );
        assert!(should_record_at(&format!("{key}-a"), now));
        assert!(!should_record_at(&format!("{key}-a"), now + Duration::from_secs(1)));
        assert!(should_record_at(&format!("{key}-a"), now + WINDOW + Duration::from_secs(1)));
    }

    #[test]
    fn a_different_shape_is_its_own_alert() {
        let now = Instant::now();
        let one = shape(
            "authentication_failed",
            "GET",
            "/api/v1/accounts/1/statuses",
            StatusCode::UNAUTHORIZED,
            Some("10.0.1.1"),
        );
        let two = shape(
            "forbidden",
            "GET",
            "/api/v1/admin/topology",
            StatusCode::FORBIDDEN,
            Some("10.0.1.1"),
        );
        assert!(should_record_at(&one, now));
        assert!(should_record_at(&two, now));
    }
}

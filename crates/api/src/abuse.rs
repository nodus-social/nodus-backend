//! Abuse logging.
//!
//! Rejected authentication, authorisation and throttling responses are both logged
//! and persisted so an administrator can review them after the fact. Recording is
//! best-effort: a failed insert never changes the response the client sees.

use std::net::SocketAddr;

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

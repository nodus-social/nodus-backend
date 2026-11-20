//! `POST /api/v2/media`: the asynchronous upload Mastodon clients poll.
//!
//! The upload answers before the variants exist, so these tests hold both halves of that
//! promise together: the `202` is immediate and carries the shape a client reads
//! unconditionally, and the id it names becomes the full attachment once the pipeline says
//! so — or says it failed.

mod support;

use std::sync::Once;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use nodus_server_core::Id;

use support::{create_account, create_token, run_db_test};

static MEDIA_ENV: Once = Once::new();

/// A 1×1 RGBA PNG: small enough to render in a test, real enough for the pipeline.
#[rustfmt::skip]
const TINY_PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
    0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
    0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49,
    0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

fn init_media_env() {
    MEDIA_ENV.call_once(|| {
        let base = std::env::temp_dir().join(format!("nodus-media-async-{}", Id::new()));
        std::fs::create_dir_all(base.join("variants")).expect("create media dirs");
        std::env::set_var("NODUS_MEDIA_DIR", &base);
        std::env::set_var("NODUS_MEDIA_VARIANTS_DIR", base.join("variants"));
        // No cluster: the pipeline reads and writes the local disk, so the test can look
        // at what it produced.
        std::env::remove_var("NODUS_MEDIA_CLUSTER_URL");
        std::env::remove_var("NODUS_MEDIA_CLUSTER_TOKEN");
    });
}

fn hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn upload_request(
    uri: &str,
    token: &str,
    filename: &str,
    content_type: &str,
    payload: &[u8],
) -> Request<Body> {
    let boundary = format!("----nodus-async-{}", Id::new());
    let mut body = Vec::with_capacity(payload.len() + 512);
    body.extend_from_slice(
        format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"description\"\r\n\r\na tiny square\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n\
             Content-Type: {content_type}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(payload);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("multipart request")
}

async fn post_upload(
    app: &Router,
    uri: &str,
    token: &str,
    filename: &str,
    content_type: &str,
    payload: &[u8],
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(upload_request(uri, token, filename, content_type, payload))
        .await
        .expect("upload response");
    let status = response.status();
    let bytes: Bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn json_get(app: &Router, uri: &str, token: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes: Bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn s(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("{key} missing from {value}"))
        .to_owned()
}

/// Polls until the row stops being pending, the way a client would.
async fn settled(app: &Router, token: &str, id: &str) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (status, row) = json_get(app, &format!("/api/v1/media/{id}"), token).await;
        assert_eq!(status, StatusCode::OK, "{row}");
        let processing = s(&row, "processing");
        if processing != "pending" {
            return row;
        }
        assert!(
            Instant::now() < deadline,
            "still pending after a minute: {row}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A `202` with urls that do not exist yet, and a pollable id that grows them.
#[tokio::test]
async fn a_v2_upload_is_accepted_then_finishes_in_the_background() {
    init_media_env();
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "media_v2").await;
        let token = create_token(store.pool(), &account, &["read", "write", "read:drive"]).await;

        let (status, accepted) = post_upload(
            &app,
            "/api/v2/media",
            &token,
            "tiny.png",
            "image/png",
            TINY_PNG,
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
        let id = s(&accepted, "id");
        assert_eq!(s(&accepted, "type"), "image");
        assert!(accepted["url"].is_null(), "{accepted}");
        assert!(accepted["preview_url"].is_null(), "{accepted}");
        assert!(accepted["blurhash"].is_null(), "{accepted}");
        assert_eq!(accepted["meta"], serde_json::json!({}));
        assert_eq!(accepted["description"], "a tiny square");
        assert_eq!(s(&accepted, "processing"), "pending");

        // The same id is what a client polls, and it reports the pipeline's verdict.
        let ready = settled(&app, &token, &id).await;
        assert_eq!(s(&ready, "processing"), "ready", "{ready}");
        assert!(
            s(&ready, "url").ends_with(&format!("/media/{id}/compressed")),
            "{ready}"
        );
        assert_eq!(ready["meta"]["original"]["width"], 1);
        assert_eq!(ready["meta"]["original"]["height"], 1);

        // The upload is also a drive file, and its state followed the pipeline.
        let (status, files) = json_get(&app, "/api/v1/drive/files", &token).await;
        assert_eq!(status, StatusCode::OK, "{files}");
        let filed = files
            .as_array()
            .expect("a listing")
            .iter()
            .find(|row| row["sha256"] == hex(TINY_PNG).as_str())
            .unwrap_or_else(|| panic!("no drive row for the upload: {files}"));
        assert_eq!(s(filed, "processing_state"), "ready", "{filed}");
        assert_eq!(s(filed, "filename"), "tiny.png");
        assert_eq!(s(filed, "mime_type"), "image/png");
    })
    .await;
}

/// Bytes the renderer cannot read end as `failed`, which a polling client must see too.
#[tokio::test]
async fn a_upload_that_cannot_be_rendered_reports_failed() {
    init_media_env();
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "media_v2_failed").await;
        let token = create_token(store.pool(), &account, &["read", "write"]).await;
        let (status, accepted) = post_upload(
            &app,
            "/api/v2/media",
            &token,
            "broken.png",
            "image/png",
            b"this is not a png".as_slice(),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
        let failed = settled(&app, &token, &s(&accepted, "id")).await;
        assert_eq!(s(&failed, "processing"), "failed", "{failed}");
        // A failed row still answers as an attachment, with no urls to follow.
        assert!(failed["url"].is_string(), "{failed}");
    })
    .await;
}

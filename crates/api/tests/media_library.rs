//! Uploaded-file management: reuse, the library read, and safe deletion.
//!
//! The operator's case is the same picture uploaded twice for a side banner. The library
//! is the repair view that makes the duplicate and its users visible without collapsing
//! existing rows; deletion is safe because it refuses anything a status, a drive object or
//! a published style still names.

mod support;

use std::path::PathBuf;
use std::sync::Once;

use axum::body::{Body, Bytes};
use axum::http::{header, Request, StatusCode};
use axum::Router;
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use nodus_server_core::Id;
use nodus_server_store::media::{self, MediaRow};

use support::{create_account, create_status, create_token, run_db_test};

static MEDIA_ENV: Once = Once::new();

/// A 1×1 RGBA PNG: real enough for the render pipeline to accept and small enough to
/// upload in every case below.
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
        let base = std::env::temp_dir().join(format!("nodus-media-library-{}", Id::new()));
        std::fs::create_dir_all(base.join("variants")).expect("create media dirs");
        std::env::set_var("NODUS_MEDIA_DIR", &base);
        std::env::set_var("NODUS_MEDIA_VARIANTS_DIR", base.join("variants"));
        // The local disk is the only store, so the test can look for the blob itself.
        std::env::remove_var("NODUS_MEDIA_CLUSTER_URL");
        std::env::remove_var("NODUS_MEDIA_CLUSTER_TOKEN");
    });
}

fn media_dir() -> PathBuf {
    PathBuf::from(std::env::var("NODUS_MEDIA_DIR").expect("media dir"))
}

fn hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn upload_request(token: &str, description: Option<&str>) -> Request<Body> {
    let boundary = format!("----nodus-media-library-{}", Id::new());
    let mut body = Vec::with_capacity(TINY_PNG.len() + 512);
    if let Some(description) = description {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\n\
                 Content-Disposition: form-data; name=\"description\"\r\n\r\n\
                 {description}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"tiny.png\"\r\n\
             Content-Type: image/png\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(TINY_PNG);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Request::builder()
        .method("POST")
        .uri("/api/v1/media")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("upload request")
}

fn stored_object_request(token: &str, object_id: &str) -> Request<Body> {
    let boundary = format!("----nodus-media-library-{}", Id::new());
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"stored_object_id\"\r\n\r\n\
         {object_id}\r\n--{boundary}--\r\n"
    );
    Request::builder()
        .method("POST")
        .uri("/api/v1/media")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("stored object request")
}

async fn answer(app: &Router, request: Request<Body>) -> (StatusCode, Bytes) {
    let response = app.clone().oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, bytes)
}

async fn upload(app: &Router, token: &str, description: Option<&str>) -> (StatusCode, Value) {
    let (status, bytes) = answer(app, upload_request(token, description)).await;
    (status, serde_json::from_slice(&bytes).expect("json body"))
}

async fn post_status(app: &Router, token: &str, media_ids: &[&str]) -> (StatusCode, Value) {
    let (status, bytes) = answer(
        app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/statuses")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "status": "a picture", "media_ids": media_ids }).to_string(),
            ))
            .expect("status request"),
    )
    .await;
    (status, serde_json::from_slice(&bytes).expect("json body"))
}

async fn library(app: &Router, token: &str) -> Value {
    let (status, bytes) = answer(
        app,
        Request::builder()
            .method("GET")
            .uri("/api/v1/media/library")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("library request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    serde_json::from_slice(&bytes).expect("json body")
}

/// The upload route answers while the row is still `pending` and finishes processing in
/// the background. A non-pending row is the state the operator's second upload sees, so
/// the reuse cases wait for it instead of racing the worker.
async fn wait_until_processed(pool: &PgPool, id: &str) {
    for _ in 0..200 {
        let row = media::by_id(pool, id)
            .await
            .expect("read media row")
            .expect("media row exists");
        match row.processing_state.as_str() {
            "ready" => return,
            "failed" => panic!("media {id} failed to process"),
            _ => {}
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("media {id} never left pending");
}

fn item<'a>(library: &'a Value, id: &str) -> &'a Value {
    library["media"]
        .as_array()
        .expect("media array")
        .iter()
        .find(|item| item["id"] == id)
        .expect("item in library")
}

async fn delete(app: &Router, token: &str, id: &str) -> (StatusCode, String) {
    let (status, bytes) = answer(
        app,
        Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/media/library/{id}"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("delete request"),
    )
    .await;
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Inserts a row directly, for states the upload route never leaves behind (a stuck
/// `pending` row) and for an orphan whose blob has no drive projection.
async fn insert_row(pool: &PgPool, account: &str, digest: &str, state: &str) -> String {
    let id = Id::new().to_string();
    media::insert(
        pool,
        &MediaRow {
            id: id.clone(),
            account_id: account.to_owned(),
            status_id: None,
            stored_object_id: None,
            digest: digest.to_owned(),
            content_type: "image/png".to_owned(),
            size: i64::try_from(TINY_PNG.len()).expect("size"),
            width: Some(1),
            height: Some(1),
            blurhash: None,
            description: "orphan".to_owned(),
            sensitive: false,
            lossless: false,
            processing_state: state.to_owned(),
            processing_progress: 0,
            processing_error: None,
            original_pruned: false,
            remote: false,
            remote_url: None,
            content_hash: None,
            perceptual_hash: None,
            quarantine_state: "none".to_owned(),
            quarantine_set: None,
            created_at: Utc::now(),
        },
    )
    .await
    .expect("insert media row");
    id
}

#[tokio::test]
async fn the_same_bytes_from_one_account_reuse_the_attachment() {
    init_media_env();
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "reuse").await;
        let token = create_token(&pool, &account, &["write", "read"]).await;

        let (first_status, first) = upload(&app, &token, None).await;
        assert_eq!(first_status, StatusCode::OK);
        let id = first["id"].as_str().expect("id").to_owned();
        wait_until_processed(&pool, &id).await;

        let (second_status, second) = upload(&app, &token, None).await;
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(second["id"], id);
        assert_eq!(second["url"], first["url"]);

        let library = library(&app, &token).await;
        assert_eq!(library["media"].as_array().expect("media").len(), 1);
        assert!(library["media"][0]["duplicate_of"].is_null());
    })
    .await;
}

#[tokio::test]
async fn the_same_bytes_after_publishing_get_a_fresh_attachment() {
    init_media_env();
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "republish").await;
        let token = create_token(&pool, &account, &["write", "read"]).await;

        let (_, first) = upload(&app, &token, None).await;
        let first_id = first["id"].as_str().expect("id").to_owned();
        wait_until_processed(&pool, &first_id).await;
        let (first_code, first_post) = post_status(&app, &token, &[first_id.as_str()]).await;
        assert_eq!(first_code, StatusCode::OK, "{first_post}");
        let first_status = first_post["id"].as_str().expect("status id").to_owned();
        let published = media::by_id(&pool, &first_id)
            .await
            .expect("read media row")
            .expect("media row exists");
        assert_eq!(published.status_id.as_deref(), Some(first_status.as_str()));

        // The bytes are published, so a second upload must not answer the claimed row:
        // an id that no status can attach again is not an upload.
        let (second_code, second) = upload(&app, &token, None).await;
        assert_eq!(second_code, StatusCode::OK, "{second}");
        let second_id = second["id"].as_str().expect("id").to_owned();
        assert_ne!(second_id, first_id, "{second}");
        wait_until_processed(&pool, &second_id).await;

        let (post_code, second_post) = post_status(&app, &token, &[second_id.as_str()]).await;
        assert_eq!(post_code, StatusCode::OK, "{second_post}");
        let second_status = second_post["id"].as_str().expect("status id").to_owned();
        assert_ne!(second_status, first_status);

        let rows: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT id, status_id FROM media_attachment \
             WHERE account_id = $1 AND digest = $2 ORDER BY created_at ASC, id ASC",
        )
        .bind(&account)
        .bind(hex(TINY_PNG))
        .fetch_all(&pool)
        .await
        .expect("media rows for the digest");
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0].0, first_id);
        assert_eq!(rows[0].1.as_deref(), Some(first_status.as_str()));
        assert_eq!(rows[1].0, second_id);
        assert_eq!(rows[1].1.as_deref(), Some(second_status.as_str()));
    })
    .await;
}

#[tokio::test]
async fn a_published_attachment_is_never_reused() {
    init_media_env();
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "claimed").await;
        let token = create_token(&pool, &account, &["write", "read"]).await;

        let (_, first) = upload(&app, &token, None).await;
        let first_id = first["id"].as_str().expect("id").to_owned();
        wait_until_processed(&pool, &first_id).await;
        let (code, posted) = post_status(&app, &token, &[first_id.as_str()]).await;
        assert_eq!(code, StatusCode::OK, "{posted}");

        let (_, second) = upload(&app, &token, None).await;
        let second_id = second["id"].as_str().expect("id").to_owned();
        assert_ne!(second_id, first_id, "{second}");
        let fresh = media::by_id(&pool, &second_id)
            .await
            .expect("read media row")
            .expect("media row exists");
        assert!(
            fresh.status_id.is_none(),
            "an upload hands back an unattached row: {fresh:?}"
        );

        // The library still shows the earlier picture and reports the new row as its
        // duplicate; nothing collapsed the two rows.
        let library = library(&app, &token).await;
        assert_eq!(item(&library, &first_id)["duplicate_of"], Value::Null);
        assert_eq!(item(&library, &second_id)["duplicate_of"], first_id);
    })
    .await;
}

#[tokio::test]
async fn an_unpublished_attachment_is_reused() {
    init_media_env();
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "unclaimed").await;
        let token = create_token(&pool, &account, &["write", "read"]).await;

        let (_, first) = upload(&app, &token, None).await;
        let id = first["id"].as_str().expect("id").to_owned();
        wait_until_processed(&pool, &id).await;

        let (second_code, second) = upload(&app, &token, None).await;
        assert_eq!(second_code, StatusCode::OK, "{second}");
        assert_eq!(second["id"], id.as_str(), "{second}");
        let row = media::by_id(&pool, &id)
            .await
            .expect("read media row")
            .expect("media row exists");
        assert!(row.status_id.is_none());

        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM media_attachment WHERE account_id = $1 AND digest = $2",
        )
        .bind(&account)
        .bind(hex(TINY_PNG))
        .fetch_one(&pool)
        .await
        .expect("row count");
        assert_eq!(rows, 1);
    })
    .await;
}

#[tokio::test]
async fn a_reuse_files_the_bytes_in_the_drive_again() {
    init_media_env();
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "refile").await;
        let token = create_token(&pool, &account, &["write", "read"]).await;

        let (_, first) = upload(&app, &token, None).await;
        let id = first["id"].as_str().expect("id").to_owned();
        wait_until_processed(&pool, &id).await;

        // Deleting from the drive removes the listing and keeps the picture: the bytes are
        // still named by the attachment, so `release_digest` leaves the blob in place.
        let object_id: Uuid =
            sqlx::query_scalar("SELECT id FROM drive_object WHERE account_id = $1 AND sha256 = $2")
                .bind(&account)
                .bind(hex(TINY_PNG))
                .fetch_one(&pool)
                .await
                .expect("drive projection");
        let (deleted, _) = answer(
            &app,
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/drive/files/{object_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("delete request"),
        )
        .await;
        assert_eq!(deleted, StatusCode::NO_CONTENT);

        // The second upload answers the same attachment, and the drive lists it again: an
        // upload that is not findable in the drive is what this pins.
        let (second_status, second) = upload(&app, &token, None).await;
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(second["id"], id);

        let (state, filename): (String, String) = sqlx::query_as(
            "SELECT processing_state, filename FROM drive_object \
             WHERE account_id = $1 AND sha256 = $2",
        )
        .bind(&account)
        .bind(hex(TINY_PNG))
        .fetch_one(&pool)
        .await
        .expect("the re-upload is filed in the drive");
        assert_eq!(state, "ready");
        assert_eq!(filename, "tiny.png");
    })
    .await;
}

#[tokio::test]
async fn the_same_bytes_from_two_accounts_are_not_reused() {
    init_media_env();
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let first_account = create_account(&pool, "first").await;
        let second_account = create_account(&pool, "second").await;
        let first_token = create_token(&pool, &first_account, &["write", "read"]).await;
        let second_token = create_token(&pool, &second_account, &["write", "read"]).await;

        let (_, first) = upload(&app, &first_token, None).await;
        let (_, second) = upload(&app, &second_token, None).await;
        let first_id = first["id"].as_str().expect("id");
        let second_id = second["id"].as_str().expect("id");
        assert_ne!(first_id, second_id);

        assert_eq!(
            library(&app, &first_token).await["media"]
                .as_array()
                .expect("media")
                .len(),
            1
        );
        assert_eq!(
            library(&app, &second_token).await["media"]
                .as_array()
                .expect("media")
                .len(),
            1
        );

        let (status, body) = delete(&app, &second_token, first_id).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    })
    .await;
}

#[tokio::test]
async fn a_different_description_on_reuse_is_refused() {
    init_media_env();
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "description").await;
        let token = create_token(&pool, &account, &["write", "read"]).await;

        let (_, first) = upload(&app, &token, Some("one")).await;
        let id = first["id"].as_str().expect("id").to_owned();
        wait_until_processed(&pool, &id).await;

        let (status, body) = upload(&app, &token, Some("two")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("different description"),
            "{body}"
        );

        let (status, again) = upload(&app, &token, Some("one")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(again["id"], id);
        assert_eq!(again["description"], "one");
    })
    .await;
}

#[tokio::test]
async fn a_processing_row_is_not_reused() {
    init_media_env();
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "processing").await;
        let token = create_token(&pool, &account, &["write", "read"]).await;
        let digest = hex(TINY_PNG);
        // A render whose worker died leaves this state behind for good; a retry must
        // render the bytes again instead of answering the row that never finishes.
        let stuck_id = insert_row(&pool, &account, &digest, "processing").await;

        let (status, uploaded) = upload(&app, &token, None).await;
        assert_eq!(status, StatusCode::OK);
        let uploaded_id = uploaded["id"].as_str().expect("id").to_owned();
        assert_ne!(uploaded_id, stuck_id);
        wait_until_processed(&pool, &uploaded_id).await;

        let stuck = media::by_id(&pool, &stuck_id)
            .await
            .expect("read media row")
            .expect("media row exists");
        assert_eq!(stuck.processing_state, "processing");
        assert!(stuck.status_id.is_none());
    })
    .await;
}

#[tokio::test]
async fn a_pending_row_is_not_reused() {
    init_media_env();
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "pending").await;
        let token = create_token(&pool, &account, &["write", "read"]).await;
        let digest = hex(TINY_PNG);
        let pending_id = insert_row(&pool, &account, &digest, "pending").await;

        let (status, uploaded) = upload(&app, &token, None).await;
        assert_eq!(status, StatusCode::OK);
        let uploaded_id = uploaded["id"].as_str().expect("id").to_owned();
        assert_ne!(uploaded_id, pending_id);

        let library = library(&app, &token).await;
        let items = library["media"].as_array().expect("media");
        assert_eq!(items.len(), 2);
        assert_eq!(item(&library, &uploaded_id)["duplicate_of"], pending_id);
        assert!(item(&library, &pending_id)["duplicate_of"].is_null());
    })
    .await;
}

#[tokio::test]
async fn the_library_reports_a_status_as_the_user() {
    init_media_env();
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "status").await;
        let token = create_token(&pool, &account, &["write", "read"]).await;
        let (_, uploaded) = upload(&app, &token, None).await;
        let id = uploaded["id"].as_str().expect("id").to_owned();
        let status_id = create_status(&pool, &account, "with a picture", "public", &[], &[]).await;
        media::attach(&pool, std::slice::from_ref(&id), &account, &status_id)
            .await
            .expect("attach media");

        let library = library(&app, &token).await;
        let row = item(&library, &id);
        assert_eq!(row["usage"], "status");
        assert_eq!(row["usage_id"], status_id);

        let (status, body) = delete(&app, &token, &id).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains(&status_id), "{body}");
    })
    .await;
}

#[tokio::test]
async fn the_library_reports_a_drive_attachment_and_refuses_to_delete_it() {
    init_media_env();
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "drive").await;
        let token = create_token(&pool, &account, &["write", "read"]).await;
        let (_, uploaded) = upload(&app, &token, None).await;
        let upload_id = uploaded["id"].as_str().expect("id").to_owned();

        // The upload's drive projection is the object a zero-copy attach can name.
        let object_id: Uuid =
            sqlx::query_scalar("SELECT id FROM drive_object WHERE account_id = $1 AND sha256 = $2")
                .bind(&account)
                .bind(hex(TINY_PNG))
                .fetch_one(&pool)
                .await
                .expect("drive projection");
        let (status, attached) =
            answer(&app, stored_object_request(&token, &object_id.to_string())).await;
        assert_eq!(status, StatusCode::OK);
        let attached: Value = serde_json::from_slice(&attached).expect("json");
        let attached_id = attached["id"].as_str().expect("id").to_owned();

        let library = library(&app, &token).await;
        assert_eq!(item(&library, &attached_id)["usage"], "drive");
        assert_eq!(
            item(&library, &attached_id)["usage_id"],
            object_id.to_string()
        );

        let (status, body) = delete(&app, &token, &attached_id).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains(&object_id.to_string()), "{body}");

        // The original upload's own row is not used by a status or a style, but its
        // projection is now the attached row's source, so it is not an orphan either.
        let (status, body) = delete(&app, &token, &upload_id).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains(&object_id.to_string()), "{body}");
    })
    .await;
}

#[tokio::test]
async fn the_library_reports_a_published_style_and_refuses_to_delete_it() {
    init_media_env();
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "style").await;
        let token = create_token(&pool, &account, &["write", "read"]).await;
        let (_, uploaded) = upload(&app, &token, None).await;
        let id = uploaded["id"].as_str().expect("id").to_owned();

        let (status, bytes) = answer(
            &app,
            Request::builder()
                .method("PUT")
                .uri("/api/v1/style/public")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "top": {
                            "slots": [
                                { "url": "https://social.test/media/top", "media_id": id }
                            ]
                        }
                    })
                    .to_string(),
                ))
                .expect("style request"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );

        let library = library(&app, &token).await;
        assert_eq!(item(&library, &id)["usage"], "style");
        assert!(item(&library, &id)["usage_id"].is_null());

        let (status, body) = delete(&app, &token, &id).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains("published style"), "{body}");
    })
    .await;
}

#[tokio::test]
async fn deleting_a_profile_picture_is_refused() {
    init_media_env();
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "profile").await;
        let token = create_token(&pool, &account, &["write", "read"]).await;
        let id = insert_row(&pool, &account, &hex(TINY_PNG), "ready").await;
        sqlx::query("UPDATE account SET avatar_ref = $1 WHERE id = $2")
            .bind(format!("{id}/avatar"))
            .bind(&account)
            .execute(&pool)
            .await
            .expect("set avatar");

        // A profile is not one of the four usage kinds, so the row reads as unused; the
        // refusal is what keeps the avatar from pointing at a deleted row.
        assert_eq!(item(&library(&app, &token).await, &id)["usage"], "none");
        let (status, body) = delete(&app, &token, &id).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains("avatar"), "{body}");
    })
    .await;
}

#[tokio::test]
async fn deleting_an_orphan_removes_the_row_and_the_blob() {
    init_media_env();
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "orphan").await;
        let token = create_token(&pool, &account, &["write", "read"]).await;
        let digest = hex(TINY_PNG);
        let id = insert_row(&pool, &account, &digest, "ready").await;
        let blob = media_dir().join(&digest);
        std::fs::write(&blob, TINY_PNG).expect("write blob");
        assert!(blob.exists());

        assert_eq!(item(&library(&app, &token).await, &id)["usage"], "none");
        let (status, body) = delete(&app, &token, &id).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert!(!blob.exists(), "the blob should be unlinked");
        assert_eq!(
            library(&app, &token).await["media"]
                .as_array()
                .expect("media")
                .len(),
            0
        );
    })
    .await;
}

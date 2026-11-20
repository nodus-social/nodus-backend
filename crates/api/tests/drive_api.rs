//! The drive's REST surface: folders, uploads, ranges, quota and blob lifetime.
//!
//! Every test drives the real router against a schema of its own, so the accounts,
//! tokens and rows are the harness's, not fixtures invented here.

mod support;

use std::sync::Once;

use axum::body::{Body, Bytes};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use nodus_server_core::Id;

use support::{create_account, create_token, run_db_test};

static DRIVE_ENV: Once = Once::new();

/// The drive's own quota is small on purpose: a test can then fill it with a handful of
/// bytes, and every other upload in this binary is well under it.
const QUOTA: i64 = 4096;

fn init_drive_env() {
    DRIVE_ENV.call_once(|| {
        let media = std::env::temp_dir().join(format!("nodus-drive-{}", Id::new()));
        std::fs::create_dir_all(&media).expect("create temp media dir");
        std::env::set_var("NODUS_MEDIA_DIR", &media);
        std::env::set_var("NODUS_DRIVE_QUOTA_BYTES", QUOTA.to_string());
        // No cluster: the local disk is the only store, which is what the blob checks
        // below look at.
        std::env::remove_var("NODUS_MEDIA_CLUSTER_URL");
        std::env::remove_var("NODUS_MEDIA_CLUSTER_TOKEN");
    });
}

fn media_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("NODUS_MEDIA_DIR").expect("media dir"))
}

fn hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// One request with full control over headers and body, answered raw.
async fn raw(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: Body,
) -> (StatusCode, HeaderMap, Bytes) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(builder.body(body).expect("request"))
        .await
        .expect("router response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, headers, bytes)
}

async fn json(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let (body, headers): (Body, Vec<(&str, &str)>) = match body {
        None => (Body::empty(), Vec::new()),
        Some(value) => (
            Body::from(value.to_string()),
            vec![(header::CONTENT_TYPE.as_str(), "application/json")],
        ),
    };
    let (status, _, bytes) = raw(app, method, uri, Some(token), &headers, body).await;
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

/// A multipart upload: `file` plus whatever text fields the test needs.
fn multipart(
    uri: &str,
    token: &str,
    filename: &str,
    content_type: &str,
    payload: &[u8],
    fields: &[(&str, &str)],
) -> Request<Body> {
    let boundary = format!("----nodus-drive-{}", Id::new());
    let mut body = Vec::with_capacity(payload.len() + 512);
    for (name, value) in fields {
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
                .as_bytes(),
        );
    }
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

async fn upload(
    app: &Router,
    token: &str,
    filename: &str,
    payload: &[u8],
    fields: &[(&str, &str)],
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(multipart(
            "/api/v1/drive/files",
            token,
            filename,
            "text/plain",
            payload,
            fields,
        ))
        .await
        .expect("upload response");
    let status = response.status();
    let bytes = response
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

#[tokio::test]
async fn folders_are_created_listed_renamed_and_moved() {
    init_drive_env();
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "drive_folders").await;
        let token = create_token(store.pool(), &account, &["read:drive", "write:drive"]).await;

        let (status, tree) = json(
            &app,
            "POST",
            "/api/v1/drive/folders",
            &token,
            Some(serde_json::json!({ "name": "photos" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{tree}");
        let photos = s(&tree, "id");

        let (status, child) = json(
            &app,
            "POST",
            "/api/v1/drive/folders",
            &token,
            Some(serde_json::json!({ "parent_id": photos, "name": "2024" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{child}");
        let year = s(&child, "id");

        let (status, nested) = json(
            &app,
            "POST",
            "/api/v1/drive/folders",
            &token,
            Some(serde_json::json!({ "parent_id": year, "name": "spring" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{nested}");
        let spring = s(&nested, "id");

        let (status, tree) = json(&app, "GET", "/api/v1/drive/folders", &token, None).await;
        assert_eq!(status, StatusCode::OK);
        let roots = tree["folders"].as_array().expect("roots");
        assert_eq!(roots.len(), 1, "one root: {tree}");
        assert_eq!(s(&roots[0], "name"), "photos");
        assert_eq!(roots[0]["children"][0]["name"], "2024");
        assert_eq!(roots[0]["children"][0]["children"][0]["name"], "spring");

        // Rename, and re-parent to the root with an explicit null.
        let (status, renamed) = json(
            &app,
            "PATCH",
            &format!("/api/v1/drive/folders/{photos}"),
            &token,
            Some(serde_json::json!({ "name": "pictures" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{renamed}");
        assert_eq!(s(&renamed, "name"), "pictures");

        let (status, moved) = json(
            &app,
            "PATCH",
            &format!("/api/v1/drive/folders/{spring}"),
            &token,
            Some(serde_json::json!({ "parent_id": null })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{moved}");
        assert_eq!(moved["parent_id"], serde_json::Value::Null);

        // A move into a descendant would detach the subtree into a cycle.
        let (status, body) = json(
            &app,
            "PATCH",
            &format!("/api/v1/drive/folders/{photos}"),
            &token,
            Some(serde_json::json!({ "parent_id": year })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(s(&body, "error"), "a folder cannot be moved inside itself");

        // A folder in another account is not a parent, and not visible either.
        let stranger = create_account(store.pool(), "drive_stranger").await;
        let stranger_token =
            create_token(store.pool(), &stranger, &["read:drive", "write:drive"]).await;
        let (status, _) = json(
            &app,
            "PATCH",
            &format!("/api/v1/drive/folders/{photos}"),
            &stranger_token,
            Some(serde_json::json!({ "name": "mine now" })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = json(
            &app,
            "DELETE",
            &format!("/api/v1/drive/folders/{photos}"),
            &stranger_token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn an_upload_stores_bytes_and_a_duplicate_costs_nothing() {
    init_drive_env();
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "drive_upload").await;
        let token = create_token(store.pool(), &account, &["read:drive", "write:drive"]).await;
        let payload = b"hello drive".as_slice();
        let digest = hex(payload);

        let (status, first) = upload(&app, &token, "hello.txt", payload, &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{first}");
        assert_eq!(s(&first, "sha256"), digest);
        assert_eq!(s(&first, "processing_state"), "ready");
        assert_eq!(s(&first, "filename"), "hello.txt");
        assert!(
            media_dir().join(&digest).exists(),
            "the bytes were written under the media root"
        );

        let (status, summary) = json(&app, "GET", "/api/v1/drive", &token, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(summary["used_bytes"], payload.len() as i64);
        assert_eq!(summary["objects"], 1);
        assert_eq!(summary["folders"], 0);

        // The same bytes again: a second row, the same digest, no new bytes.
        let (status, second) = upload(&app, &token, "hello-again.txt", payload, &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{second}");
        assert_eq!(s(&second, "sha256"), digest);
        assert_ne!(s(&second, "id"), s(&first, "id"));

        let (_, summary) = json(&app, "GET", "/api/v1/drive", &token, None).await;
        assert_eq!(
            summary["used_bytes"],
            payload.len() as i64,
            "a duplicate digest occupies the drive once"
        );
        assert_eq!(summary["objects"], 2);

        let (status, files) = json(&app, "GET", "/api/v1/drive/files", &token, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(files.as_array().expect("files").len(), 2);

        // Somebody else's id does not exist for this caller, and never answers 403.
        let stranger = create_account(store.pool(), "drive_upload_stranger").await;
        let stranger_token =
            create_token(store.pool(), &stranger, &["read:drive", "write:drive"]).await;
        let id = s(&first, "id");
        let (status, _) = json(
            &app,
            "PATCH",
            &format!("/api/v1/drive/files/{id}"),
            &stranger_token,
            Some(serde_json::json!({ "filename": "stolen.txt" })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, _) = raw(
            &app,
            "GET",
            &format!("/api/v1/drive/files/{id}/content"),
            Some(&stranger_token),
            &[],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = json(
            &app,
            "DELETE",
            &format!("/api/v1/drive/files/{id}"),
            &stranger_token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn an_upload_over_the_quota_is_refused_before_a_byte_is_written() {
    init_drive_env();
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "drive_quota").await;
        let token = create_token(store.pool(), &account, &["read:drive", "write:drive"]).await;

        let payload = vec![b'x'; usize::try_from(QUOTA).expect("fits") + 1];
        let digest = hex(&payload);
        let (status, body) = upload(&app, &token, "too-big.bin", &payload, &[]).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
        assert_eq!(s(&body, "error"), "the drive is full");
        assert!(
            !media_dir().join(&digest).exists(),
            "a refused upload writes nothing"
        );

        let (_, summary) = json(&app, "GET", "/api/v1/drive", &token, None).await;
        assert_eq!(summary["used_bytes"], 0);
        assert_eq!(summary["objects"], 0);
    })
    .await;
}

#[tokio::test]
async fn content_honours_ranges_and_reports_its_length() {
    init_drive_env();
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "drive_ranges").await;
        let token = create_token(store.pool(), &account, &["read:drive", "write:drive"]).await;
        let payload = b"0123456789ab".as_slice();

        let (status, object) = upload(&app, &token, "digits.txt", payload, &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{object}");
        let uri = format!("/api/v1/drive/files/{}/content", s(&object, "id"));

        let (status, headers, bytes) =
            raw(&app, "GET", &uri, Some(&token), &[], Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], "text/plain");
        assert_eq!(
            headers[header::CONTENT_DISPOSITION],
            "attachment; filename=\"digits.txt\""
        );
        assert_eq!(headers[header::ACCEPT_RANGES], "bytes");
        assert_eq!(headers[header::CONTENT_LENGTH], "12");
        assert_eq!(bytes.as_ref(), payload);

        let (status, headers, bytes) = raw(
            &app,
            "GET",
            &uri,
            Some(&token),
            &[("range", "bytes=0-3")],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes.as_ref(), b"0123");
        assert_eq!(headers[header::CONTENT_LENGTH], "4");
        assert_eq!(headers[header::CONTENT_RANGE], "bytes 0-3/12");

        let (status, headers, _) = raw(
            &app,
            "GET",
            &uri,
            Some(&token),
            &[("range", "bytes=999-")],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(headers[header::CONTENT_RANGE], "bytes */12");

        // A header this store cannot read is ignored: the whole body is the answer.
        let (status, headers, bytes) = raw(
            &app,
            "GET",
            &uri,
            Some(&token),
            &[("range", "bytes=x")],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_LENGTH], "12");
        assert_eq!(bytes.as_ref(), payload);
    })
    .await;
}

#[tokio::test]
async fn a_deleted_file_frees_its_bytes_only_when_nothing_else_needs_them() {
    init_drive_env();
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "drive_delete").await;
        let token = create_token(store.pool(), &account, &["read:drive", "write:drive"]).await;
        let payload = b"pinned by a post".as_slice();
        let digest = hex(payload);

        let (status, object) = upload(&app, &token, "post.png", payload, &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{object}");
        let id = s(&object, "id");

        // A published post still shows these bytes, as a `media_attachment` with the
        // same digest and no foreign key back to the drive.
        sqlx::query(
            "INSERT INTO media_attachment (id, account_id, digest, content_type, size) \
             VALUES ($1, $2, $3, 'text/plain', $4)",
        )
        .bind(Id::new().to_string())
        .bind(&account)
        .bind(&digest)
        .bind(i64::try_from(payload.len()).expect("fits"))
        .execute(store.pool())
        .await
        .expect("insert attachment");

        let (status, _, _) = raw(
            &app,
            "DELETE",
            &format!("/api/v1/drive/files/{id}"),
            Some(&token),
            &[],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            media_dir().join(&digest).exists(),
            "an attachment still points at these bytes"
        );

        // Nothing references the second file: deleting it deletes the bytes too.
        let other = b"nobody wants me".as_slice();
        let other_digest = hex(other);
        let (status, second) = upload(&app, &token, "gone.bin", other, &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{second}");
        assert!(media_dir().join(&other_digest).exists());

        let (status, _, _) = raw(
            &app,
            "DELETE",
            &format!("/api/v1/drive/files/{}", s(&second, "id")),
            Some(&token),
            &[],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            !media_dir().join(&other_digest).exists(),
            "an unreferenced blob is unlinked"
        );
    })
    .await;
}

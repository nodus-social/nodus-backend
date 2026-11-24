//! Changing a profile picture the way a Mastodon client does: one multipart request.
//!
//! `PATCH /api/v1/accounts/update_credentials` has to accept an `avatar`/`header` file
//! part, not only a media id, because the SDK and every Mastodon client put the picture
//! bytes in the form. The uploaded bytes go through the media route's own ingestion, so
//! these tests hold the answers together: the account names the profile layer, the media
//! row belongs to the reader, and a refused upload leaves the profile as it was.

mod support;

use std::sync::Once;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use nodus_server_core::Id;

use support::{create_account, create_token, json_of, run_db_test, send, send_anon};

static MEDIA_ENV: Once = Once::new();

/// A 1×1 RGBA PNG, the smallest real image the render pipeline can decode.
#[rustfmt::skip]
const TINY_PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
    0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
    0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49,
    0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

const CREDENTIALS: &str = "/api/v1/accounts/update_credentials";
const VERIFY: &str = "/api/v1/accounts/verify_credentials";

fn init_media_env() {
    MEDIA_ENV.call_once(|| {
        let base = std::env::temp_dir().join(format!("nodus-profile-upload-{}", Id::new()));
        std::fs::create_dir_all(base.join("variants")).expect("create media dirs");
        std::env::set_var("NODUS_MEDIA_DIR", &base);
        std::env::set_var("NODUS_MEDIA_VARIANTS_DIR", base.join("variants"));
        // No cluster: the test process reads and renders from its own disk.
        std::env::remove_var("NODUS_MEDIA_CLUSTER_URL");
        std::env::remove_var("NODUS_MEDIA_CLUSTER_TOKEN");
    });
}

enum Part<'a> {
    Field(&'a str, &'a str),
    File {
        name: &'a str,
        filename: &'a str,
        content_type: &'a str,
        bytes: &'a [u8],
    },
}

async fn multipart_patch(app: &Router, token: &str, parts: &[Part<'_>]) -> (StatusCode, String) {
    let boundary = format!("----nodus-profile-{}", Id::new());
    let mut body = Vec::new();
    for part in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        match part {
            Part::Field(name, value) => body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
                    .as_bytes(),
            ),
            Part::File {
                name,
                filename,
                content_type,
                bytes,
            } => {
                body.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n\
                         Content-Type: {content_type}\r\n\r\n"
                    )
                    .as_bytes(),
                );
                body.extend_from_slice(bytes);
                body.extend_from_slice(b"\r\n");
            }
        }
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let request = Request::builder()
        .method("PATCH")
        .uri(CREDENTIALS)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("multipart request");
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes: Bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn account(app: &Router, id: &str) -> Value {
    let (status, body) = send_anon(app, "GET", &format!("/api/v1/accounts/{id}")).await;
    assert_eq!(status, StatusCode::OK, "body was {body}");
    json_of(&body)
}

/// Waits for the background render and returns the account document that reports it.
async fn shaped_picture(app: &Router, id: &str, meta: &str) -> Value {
    // 600 x 25ms = 15s, not 5s: the render is an in-process task, and under a full
    // `cargo test --workspace` at 32 jobs it competes with every other sqlx test for the
    // CPU and the database. Five seconds passed alone and flaked in the workspace run —
    // the budget is about "eventually", not about how fast this box is today.
    for _ in 0..600 {
        let document = account(app, id).await;
        if document[meta]["original"]["width"].as_i64().is_some() {
            return document;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{meta} never reported a rendered shape");
}

async fn seed_media(store: &nodus_server_store::Store, account_id: &str) -> String {
    let id = Id::new().to_string();
    sqlx::query(
        "INSERT INTO media_attachment (id, account_id, digest, content_type, size) \
         VALUES ($1, $2, $3, 'image/png', 1)",
    )
    .bind(&id)
    .bind(account_id)
    .bind(format!("{id}-digest"))
    .execute(store.pool())
    .await
    .expect("insert media");
    id
}

#[tokio::test]
async fn a_multipart_avatar_upload_becomes_the_profile_picture() {
    run_db_test(|store, app| async move {
        init_media_env();
        let pool = store.pool().clone();
        let id = create_account(&pool, "avatarupload").await;
        let token = create_token(&pool, &id, &["read", "write"]).await;

        let (status, body) = multipart_patch(
            &app,
            &token,
            &[
                Part::Field("display_name", "Uploaded"),
                Part::File {
                    name: "avatar",
                    filename: "avatar.png",
                    content_type: "image/png",
                    bytes: TINY_PNG,
                },
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let document = json_of(&body);
        assert_eq!(document["display_name"], json!("Uploaded"));
        let avatar = document["avatar"].as_str().expect("avatar");
        let prefix = "https://social.test/media/";
        let media_id = avatar
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix("/avatar"))
            .expect("the picture names the profile layer");
        assert_eq!(
            document["avatar_static"],
            json!(format!("{prefix}{media_id}/avatar_static"))
        );

        let (owner, content_type): (String, String) =
            sqlx::query_as("SELECT account_id, content_type FROM media_attachment WHERE id = $1")
                .bind(media_id)
                .fetch_one(&pool)
                .await
                .expect("the upload made a media row");
        assert_eq!(owner, id);
        assert_eq!(content_type, "image/png");

        let shaped = shaped_picture(&app, &id, "avatar_meta").await;
        assert_eq!(shaped["avatar"], json!(avatar));
        assert_eq!(shaped["avatar_meta"]["original"]["width"], json!(1));
        assert_eq!(shaped["avatar_meta"]["original"]["height"], json!(1));
        assert_eq!(shaped["avatar_meta"]["original"]["size"], json!("1x1"));
        assert!(shaped["avatar_meta"]["original"]["aspect"].is_number());
        assert!(shaped["avatar_meta"]["small"].is_null());
    })
    .await;
}

#[tokio::test]
async fn a_multipart_header_upload_becomes_the_profile_header() {
    run_db_test(|store, app| async move {
        init_media_env();
        let pool = store.pool().clone();
        let id = create_account(&pool, "headerupload").await;
        let token = create_token(&pool, &id, &["read", "write"]).await;

        let (status, body) = multipart_patch(
            &app,
            &token,
            &[Part::File {
                name: "header",
                filename: "header.png",
                content_type: "image/png",
                bytes: TINY_PNG,
            }],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let header = json_of(&body)["header"]
            .as_str()
            .expect("header")
            .to_owned();
        assert!(
            header.starts_with("https://social.test/media/") && header.ends_with("/header"),
            "header was {header}"
        );

        let shaped = shaped_picture(&app, &id, "header_meta").await;
        assert_eq!(shaped["header"], json!(header));
        assert_eq!(shaped["header_meta"]["original"]["width"], json!(1));
        assert_eq!(shaped["header_meta"]["original"]["height"], json!(1));
    })
    .await;
}

#[tokio::test]
async fn a_media_id_in_a_json_body_still_sets_the_picture() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let id = create_account(&pool, "idpath").await;
        let token = create_token(&pool, &id, &["read", "write"]).await;
        let media_id = seed_media(&store, &id).await;

        let (status, body) = send(
            &app,
            &token,
            "PATCH",
            CREDENTIALS,
            Some(json!({ "avatar": media_id })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(
            json_of(&body)["avatar"],
            json!(format!("https://social.test/media/{media_id}/avatar"))
        );
    })
    .await;
}

#[tokio::test]
async fn an_unsupported_file_part_leaves_the_profile_alone() {
    run_db_test(|store, app| async move {
        init_media_env();
        let pool = store.pool().clone();
        let id = create_account(&pool, "badtype").await;
        let token = create_token(&pool, &id, &["read", "write"]).await;
        let before = account(&app, &id).await;

        // A text part under a picture slot reaches the media route's own refusal; no
        // profile write happens behind it.
        let (status, body) = multipart_patch(
            &app,
            &token,
            &[
                Part::Field("note", "must stay absent"),
                Part::File {
                    name: "avatar",
                    filename: "notes.txt",
                    content_type: "text/plain",
                    bytes: b"not a picture",
                },
            ],
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
        assert_eq!(json_of(&body)["error"], json!("Unsupported media type"));

        let after = account(&app, &id).await;
        assert_eq!(after["avatar"], before["avatar"]);
        assert_eq!(after["note"], json!(""), "the refused save changed nothing");
    })
    .await;
}

#[tokio::test]
async fn an_unknown_file_part_is_refused() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let id = create_account(&pool, "strayfile").await;
        let token = create_token(&pool, &id, &["read", "write"]).await;

        let (status, body) = multipart_patch(
            &app,
            &token,
            &[Part::File {
                name: "banner",
                filename: "banner.png",
                content_type: "image/png",
                bytes: TINY_PNG,
            }],
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
        assert!(
            json_of(&body)["error"]
                .as_str()
                .unwrap_or_default()
                .contains("only avatar and header"),
            "{body}"
        );
    })
    .await;
}

#[tokio::test]
async fn profile_fields_are_refused_in_a_multipart_body() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let id = create_account(&pool, "fieldsform").await;
        let token = create_token(&pool, &id, &["read", "write"]).await;

        let (status, body) = multipart_patch(
            &app,
            &token,
            &[
                Part::Field("note", "must stay absent"),
                Part::Field("fields_attributes[0][name]", "Blog"),
                Part::Field("fields_attributes[0][value]", "https://example.test"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
        assert!(
            json_of(&body)["error"]
                .as_str()
                .unwrap_or_default()
                .contains("no nested keys"),
            "{body}"
        );

        let after = account(&app, &id).await;
        assert_eq!(after["note"], json!(""));
        assert_eq!(after["fields"], json!([]));
    })
    .await;
}

#[tokio::test]
async fn verify_credentials_still_answers_after_the_multipart_change() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let id = create_account(&pool, "verify").await;
        let token = create_token(&pool, &id, &["read", "write"]).await;
        let (status, body) = send(&app, &token, "GET", VERIFY, None).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(json_of(&body)["id"], json!(id));
    })
    .await;
}

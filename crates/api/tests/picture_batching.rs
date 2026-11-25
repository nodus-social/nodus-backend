//! A response's picture shapes are one read, not one per status.
//!
//! `avatar_meta`/`header_meta` come from the batch's picture statement. Threads,
//! collections and pages used to build each status through `statuses::dto`, which read
//! one account's picture per row; a response that paints twenty posts therefore paid
//! twenty picture reads on top of its real work. Each case below captures sqlx's
//! statement log, measures the same endpoint at N=1 and N=20 and pins the picture read
//! at one statement: a per-row regression makes the count N and the pin fails.

// One scenario per endpoint in one binary: the subscriber installs once, and the cases
// share the pictured accounts that make the reads measurable.
#![allow(clippy::too_many_lines)]

mod support;

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use serde_json::Value;
use sqlx::PgPool;

use nodus_server_core::Id;
use nodus_server_store::media::{self, VariantRow};
use nodus_server_store::statuses::{self, NewStatus};

use support::{create_account, create_status, create_token, expect_ok, json_of, run_db_test, send};

#[derive(Clone)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
    type Writer = CapturedLog;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn clear(log: &CapturedLog) {
    log.0.lock().expect("log buffer").clear();
}

fn captured(log: &CapturedLog) -> String {
    String::from_utf8_lossy(&log.0.lock().expect("log buffer")).into_owned()
}

fn statements(log: &CapturedLog) -> usize {
    captured(log).matches("sqlx::query:").count()
}

/// The picture statement's own text; one per response, whatever the row count. The
/// decorations statement shares the `WITH requested AS` prefix, so the slot lookup is
/// what identifies this one.
fn picture_reads(log: &CapturedLog) -> usize {
    captured(log)
        .matches("NULLIF(split_part(a.avatar_ref, '/', 1)")
        .count()
}

/// Seeds a media row and a rendered variant for one profile layer, then points the
/// account at it. The dimensions are unequal so a square guess cannot pass.
async fn render_picture(store: &nodus_server_store::Store, id: &str, slot: &str, width: i32) {
    let media_id = format!("{id}-{slot}-media");
    sqlx::query(
        "INSERT INTO media_attachment (id, account_id, digest, content_type, size) \
         VALUES ($1, $2, $3, 'image/png', 1)",
    )
    .bind(&media_id)
    .bind(id)
    .bind(format!("{media_id}-digest"))
    .execute(store.pool())
    .await
    .expect("insert media");
    media::upsert_variant(
        store.pool(),
        &VariantRow {
            media_id: media_id.clone(),
            layer: slot.to_owned(),
            max_edge: i64::from(width),
            object_key: format!("media/{media_id}/{slot}"),
            content_type: "image/webp".to_owned(),
            digest: format!("{media_id}-{width}"),
            size: 1,
            width: Some(width),
            height: Some(if slot == "avatar" { 300 } else { 500 }),
            expires_at: None,
            created_at: chrono::Utc::now(),
        },
    )
    .await
    .expect("insert variant");
}

async fn give_pictures(store: &nodus_server_store::Store, id: &str) {
    render_picture(store, id, "avatar", 400).await;
    render_picture(store, id, "header", 1500).await;
    sqlx::query("UPDATE account SET avatar_ref = $1, header_ref = $2 WHERE id = $3")
        .bind(format!("{id}-avatar-media"))
        .bind(format!("{id}-header-media"))
        .bind(id)
        .execute(store.pool())
        .await
        .expect("point account at pictures");
}

/// A public reply, which is what puts an author into a thread's descendants.
async fn reply(pool: &PgPool, author: &str, parent: &str, parent_author: &str) -> String {
    let id = Id::new().to_string();
    statuses::create(
        pool,
        &NewStatus {
            id: &id,
            account_id: author,
            content: "a reply with a face",
            content_html: "a reply with a face",
            content_source: None,
            content_format: "html",
            spoiler_text: "",
            visibility: "public",
            sensitive: false,
            in_reply_to_id: Some(parent),
            in_reply_to_account_id: Some(parent_author),
            reblog_of_id: None,
            language: None,
        },
        &[],
        &[],
        &[],
    )
    .await
    .expect("reply");
    id
}

struct Measured {
    statements: usize,
    pictures: usize,
    body: Value,
}

async fn measure(log: &CapturedLog, app: &axum::Router, token: &str, uri: &str) -> Measured {
    clear(log);
    let (status, body) = send(app, token, "GET", uri, None).await;
    let body = expect_ok(status, &body, uri);
    let statements = statements(log);
    let pictures = picture_reads(log);
    assert!(
        status == StatusCode::OK,
        "{uri}: expected 200, got {status}: {body}"
    );
    Measured {
        statements,
        pictures,
        body: json_of(&body),
    }
}

/// Walks to the first object that has both metas and returns them as (avatar, header).
fn first_picture_metas(value: &Value) -> Option<(Value, Value)> {
    match value {
        Value::Object(map) => {
            if map.contains_key("acct") && map.contains_key("avatar_meta") {
                return Some((map["avatar_meta"].clone(), map["header_meta"].clone()));
            }
            map.values().find_map(first_picture_metas)
        }
        Value::Array(items) => items.iter().find_map(first_picture_metas),
        _ => None,
    }
}

#[tokio::test]
async fn a_response_reads_picture_shapes_once_however_many_statuses_it_paints() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let log = CapturedLog(Arc::new(Mutex::new(Vec::new())));
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(log.clone())
            .try_init()
            .ok();

        // One viewer owns the threads and lists; the favouriting viewers are separate so
        // the same binary can ask the shelf for one row and for twenty.
        let owner = create_account(pool, "picture-batch-owner").await;
        let owner_token = create_token(pool, &owner, &["read", "write"]).await;
        let one_viewer = create_account(pool, "picture-batch-one").await;
        let one_token = create_token(pool, &one_viewer, &["read", "write"]).await;
        let twenty_viewer = create_account(pool, "picture-batch-twenty").await;
        let twenty_token = create_token(pool, &twenty_viewer, &["read", "write"]).await;
        give_pictures(&store, &owner).await;

        let mut authors = Vec::new();
        for index in 0..21 {
            let id = create_account(pool, &format!("picture-author-{index}")).await;
            give_pictures(&store, &id).await;
            authors.push(id);
        }

        // ---- A thread: one reply vs twenty, each by a pictured author. ----
        let one_root = create_status(pool, &owner, "one reply thread", "public", &[], &[]).await;
        reply(pool, &authors[0], &one_root, &owner).await;
        let twenty_root =
            create_status(pool, &owner, "twenty reply thread", "public", &[], &[]).await;
        for author in &authors[..20] {
            reply(pool, author, &twenty_root, &owner).await;
        }

        let thread_one = measure(
            &log,
            &app,
            &owner_token,
            &format!("/api/v1/statuses/{one_root}/context"),
        )
        .await;
        let thread_twenty = measure(
            &log,
            &app,
            &owner_token,
            &format!("/api/v1/statuses/{twenty_root}/context"),
        )
        .await;
        let thread_one_count = thread_one.body["descendants"].as_array().map(Vec::len);
        let thread_twenty_count = thread_twenty.body["descendants"].as_array().map(Vec::len);
        assert_eq!(thread_one_count, Some(1), "one-reply thread descendants");
        assert_eq!(
            thread_twenty_count,
            Some(20),
            "twenty-reply thread descendants"
        );
        assert_eq!(thread_one.pictures, 1, "one-reply thread picture reads");
        assert_eq!(
            thread_twenty.pictures, 1,
            "twenty-reply thread picture reads"
        );
        // Pinned flat: the thread is hydrated as one page, so one reply and twenty replies
        // cost the same statements. A reintroduced per-row read moves the twenty by N.
        assert_eq!(thread_one.statements, 16, "one-reply thread statements");
        assert_eq!(
            thread_twenty.statements, 16,
            "twenty-reply thread statements"
        );
        for (index, status) in thread_twenty.body["descendants"]
            .as_array()
            .expect("descendants")
            .iter()
            .enumerate()
        {
            let (avatar, header) = first_picture_metas(status)
                .unwrap_or_else(|| panic!("descendant {index} has no metas"));
            assert!(avatar.is_object(), "descendant {index} avatar is null");
            assert!(header.is_object(), "descendant {index} header is null");
        }

        // ---- A collection: one favourite vs twenty, one of them a boost. ----
        let boosted =
            create_status(pool, &authors[20], "the boosted post", "public", &[], &[]).await;
        let boost = statuses::reblog(pool, &authors[0], &boosted)
            .await
            .expect("reblog")
            .expect("new boost");
        nodus_server_store::social::favourite(pool, &one_viewer, &boost.id)
            .await
            .expect("one favourite");
        nodus_server_store::social::favourite(pool, &twenty_viewer, &boost.id)
            .await
            .expect("twenty favourites");
        for author in &authors[..19] {
            let id = create_status(pool, author, "a shelf post", "public", &[], &[]).await;
            nodus_server_store::social::favourite(pool, &twenty_viewer, &id)
                .await
                .expect("twenty favourites");
        }

        let collection_one = measure(&log, &app, &one_token, "/api/v1/favourites").await;
        let collection_twenty = measure(&log, &app, &twenty_token, "/api/v1/favourites").await;
        let one_favourites = collection_one.body.as_array().map(Vec::len);
        let twenty_favourites = collection_twenty.body.as_array().map(Vec::len);
        assert_eq!(one_favourites, Some(1), "one favourite");
        assert_eq!(twenty_favourites, Some(20), "twenty favourites");
        assert_eq!(collection_one.pictures, 1, "one-favourite picture reads");
        assert_eq!(
            collection_twenty.pictures, 1,
            "twenty-favourite picture reads"
        );
        // A shelf is a page too: the same hydration paints one favourite and twenty.
        assert_eq!(collection_one.statements, 13, "one-favourite statements");
        assert_eq!(
            collection_twenty.statements, 13,
            "twenty-favourite statements"
        );
        // The boost paints two accounts: its author and the boosted author, whose id the
        // row names only as a status. Both come from the one map.
        let boost = collection_one
            .body
            .as_array()
            .expect("favourites")
            .iter()
            .find(|status| status["reblog"].is_object())
            .expect("the boost is on the shelf");
        assert!(
            boost["account"]["avatar_meta"].is_object(),
            "boost author is missing its avatar shape"
        );
        assert!(
            boost["reblog"]["account"]["avatar_meta"].is_object(),
            "boosted author is missing its avatar shape"
        );

        // ---- A page: a list timeline, batched before this change and still one read. ----
        // Fresh authors, because a list timeline answers every status its members wrote and
        // the authors above already have rows of their own.
        let one_author = create_account(pool, "picture-list-one").await;
        give_pictures(&store, &one_author).await;
        let twenty_author = create_account(pool, "picture-list-twenty").await;
        give_pictures(&store, &twenty_author).await;
        let one_list = nodus_server_store::lists::create(pool, &owner, "one", "list", false)
            .await
            .expect("one list");
        nodus_server_store::lists::add_account(pool, &one_list.id, &one_author)
            .await
            .expect("one member");
        create_status(pool, &one_author, "one list post", "public", &[], &[]).await;
        let twenty_list = nodus_server_store::lists::create(pool, &owner, "twenty", "list", false)
            .await
            .expect("twenty list");
        nodus_server_store::lists::add_account(pool, &twenty_list.id, &twenty_author)
            .await
            .expect("twenty member");
        for _ in 0..20 {
            create_status(pool, &twenty_author, "a list post", "public", &[], &[]).await;
        }

        let page_one = measure(
            &log,
            &app,
            &owner_token,
            &format!("/api/v1/timelines/list/{}", one_list.id),
        )
        .await;
        let page_twenty = measure(
            &log,
            &app,
            &owner_token,
            &format!("/api/v1/timelines/list/{}", twenty_list.id),
        )
        .await;
        assert_eq!(
            page_one.body.as_array().map(Vec::len),
            Some(1),
            "one-post list"
        );
        assert_eq!(
            page_twenty.body.as_array().map(Vec::len),
            Some(20),
            "twenty-post list"
        );
        assert_eq!(page_one.pictures, 1, "one-post list picture reads");
        assert_eq!(page_twenty.pictures, 1, "twenty-post list picture reads");
        // A page-shaped endpoint: the whole read set is already flat.
        assert_eq!(page_one.statements, 10, "one-post list statements");
        assert_eq!(page_twenty.statements, 10, "twenty-post list statements");

        // ---- An outbox: `/accounts/{id}/statuses` paints the same page shape. ----
        // It used to build each row through `statuses::dto`, reading the author, media,
        // decorations and viewer flags one row at a time (~12 statements per status). The
        // page seam makes the count a property of the page, not of its length.
        let one_outbox_owner = create_account(pool, "picture-outbox-one").await;
        give_pictures(&store, &one_outbox_owner).await;
        create_status(
            pool,
            &one_outbox_owner,
            "one outbox post",
            "public",
            &[],
            &[],
        )
        .await;
        let twenty_outbox_owner = create_account(pool, "picture-outbox-twenty").await;
        give_pictures(&store, &twenty_outbox_owner).await;
        for _ in 0..20 {
            create_status(
                pool,
                &twenty_outbox_owner,
                "an outbox post",
                "public",
                &[],
                &[],
            )
            .await;
        }

        let outbox_one = measure(
            &log,
            &app,
            &owner_token,
            &format!("/api/v1/accounts/{one_outbox_owner}/statuses"),
        )
        .await;
        let outbox_twenty = measure(
            &log,
            &app,
            &owner_token,
            &format!("/api/v1/accounts/{twenty_outbox_owner}/statuses"),
        )
        .await;
        assert_eq!(
            outbox_one.body.as_array().map(Vec::len),
            Some(1),
            "one-post outbox"
        );
        assert_eq!(
            outbox_twenty.body.as_array().map(Vec::len),
            Some(20),
            "twenty-post outbox"
        );
        assert_eq!(outbox_one.pictures, 1, "one-post outbox picture reads");
        assert_eq!(
            outbox_twenty.pictures, 1,
            "twenty-post outbox picture reads"
        );
        assert_eq!(
            outbox_twenty.statements, outbox_one.statements,
            "outbox statements must not grow with the page"
        );
    })
    .await;
}

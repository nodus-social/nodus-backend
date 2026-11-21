//! A feed page's reads are a property of the page, not of its length.
//!
//! The Mastodon timeline used to read each author and each status's attachments on its
//! own, so a page of twenty posts paid twenty account queries. This binary captures
//! sqlx's statement log and measures the same endpoint at N=1 and N=20: the count must
//! not grow. Misskey names every note and author through `external_id`; the page reads
//! all of those mappings in one statement, so its total is also flat, and a per-note
//! regression shows up in the pinned `external_id` read count.

mod support;

use std::sync::{Arc, Mutex};

use axum::Router;
use serde_json::json;
use sqlx::PgPool;

use nodus_server_core::pagination::PageParams;
use nodus_server_core::Id;
use nodus_server_store::{accounts, media, polls, statuses, Store};

use support::{
    create_account, create_status, create_token, expect_ok, follow, json_of, run_db_test, send,
};

/// A writer that keeps sqlx's statement log so the test can count statements.
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

/// Every statement sqlx logs, whatever the query builder was.
fn statements(log: &CapturedLog) -> usize {
    captured(log).matches("sqlx::query:").count()
}

/// How many statements touched one table; a per-row loop shows up here as N.
fn table_reads(log: &CapturedLog, marker: &str) -> usize {
    captured(log).matches(marker).count()
}

async fn attach(pool: &PgPool, account_id: &str, status_id: &str) {
    sqlx::query(
        "INSERT INTO media_attachment (id, account_id, status_id, digest, content_type, size) \
         VALUES ($1, $2, $3, $4, 'image/png', 12)",
    )
    .bind(Id::new().to_string())
    .bind(account_id)
    .bind(status_id)
    .bind(Id::new().to_string())
    .execute(pool)
    .await
    .expect("insert attachment");
}

/// Gives a status one hashtag, one custom emoji and one mention: the three families a
/// page used to read per row.
async fn decorate(pool: &PgPool, status_id: &str, mentioned: &str, tag: &str) {
    sqlx::query("INSERT INTO status_tag (status_id, tag) VALUES ($1, $2)")
        .bind(status_id)
        .bind(tag)
        .execute(pool)
        .await
        .expect("insert tag");
    sqlx::query("INSERT INTO status_mention (status_id, account_id) VALUES ($1, $2)")
        .bind(status_id)
        .bind(mentioned)
        .execute(pool)
        .await
        .expect("insert mention");
    sqlx::query("INSERT INTO status_emoji (status_id, shortcode, url) VALUES ($1, $2, $3)")
        .bind(status_id)
        .bind(format!("emoji{status_id}"))
        .bind("https://cdn.example/emoji.png")
        .execute(pool)
        .await
        .expect("insert emoji");
}

/// The ids on the page, in the order the client reads them.
async fn home_ids(app: &Router, token: &str) -> Vec<String> {
    let (status, body) = send(app, token, "GET", "/api/v1/timelines/home", None).await;
    let body = expect_ok(status, &body, "/api/v1/timelines/home");
    json_of(&body)
        .as_array()
        .expect("timeline is an array")
        .iter()
        .map(|item| item["id"].as_str().expect("status has an id").to_owned())
        .collect()
}

/// The removed path's reads, replayed against the same page: one attachment scan, one
/// poll scan, then one author lookup per row.
async fn old_path_statements(store: &Store, page_ids: &[String], log: &CapturedLog) -> usize {
    let mut authors = Vec::with_capacity(page_ids.len());
    for id in page_ids {
        let row = statuses::by_id(store.pool(), id)
            .await
            .expect("status row")
            .expect("status exists");
        authors.push(row.account_id);
    }
    clear(log);
    let _ = media::by_statuses(store.pool(), page_ids)
        .await
        .expect("attachment scan");
    let _ = polls::by_status_ids(store.pool(), page_ids)
        .await
        .expect("poll scan");
    for author in &authors {
        let _ = accounts::by_id(store.pool(), author)
            .await
            .expect("author lookup");
    }
    statements(log)
}

/// A followed author with one public post; `attached` gives the post an attachment.
async fn seed_author(pool: &PgPool, viewer: &str, index: usize, attached: bool) -> String {
    let author = create_account(pool, &format!("feedauthor{index}")).await;
    follow(pool, viewer, &author).await;
    let status = create_status(pool, &author, &format!("post {index}"), "public", &[], &[]).await;
    if attached {
        attach(pool, &author, &status).await;
    }
    status
}

/// The Misskey home timeline's total statement count, and how many of those touched the
/// reaction and attachment tables.
async fn misskey_page_stats(
    app: &Router,
    token: &str,
    log: &CapturedLog,
    limit: u32,
) -> (usize, usize, usize, usize, usize) {
    clear(log);
    let (status, body) = send(
        app,
        token,
        "POST",
        "/api/notes/timeline",
        Some(json!({ "i": token, "limit": limit })),
    )
    .await;
    let body = expect_ok(status, &body, "/api/notes/timeline");
    assert_eq!(
        json_of(&body).as_array().expect("notes array").len(),
        usize::try_from(limit).expect("fits"),
        "the Misskey home timeline returned the page"
    );
    (
        statements(log),
        table_reads(log, "FROM status_reaction"),
        table_reads(log, "FROM media_attachment"),
        table_reads(log, "FROM status_tag"),
        table_reads(log, "FROM external_id"),
    )
}

/// The parked read has to reach the payload: a page whose statuses carry a tag, an emoji
/// and a mention renders all three, the same as a single-status read does.
async fn assert_page_render_decorations(
    app: &Router,
    token: &str,
    status_id: &str,
    mentioned: &str,
) {
    let (status, body) = send(app, token, "GET", "/api/v1/timelines/home", None).await;
    let body = expect_ok(status, &body, "/api/v1/timelines/home");
    let rendered = json_of(&body);
    let first = rendered
        .as_array()
        .expect("timeline array")
        .iter()
        .find(|item| item["id"] == status_id)
        .expect("the decorated status is on the page");
    assert_eq!(first["tags"][0]["name"], "nodus");
    assert!(
        first["emojis"]
            .as_array()
            .is_some_and(|emojis| !emojis.is_empty()),
        "the page rendered no custom emoji: {first}"
    );
    assert_eq!(first["mentions"][0]["id"], mentioned);
    assert!(
        first["mentions"][0]["acct"].is_string(),
        "a mention without acct is a client decode failure: {first}"
    );
}

/// The Misskey page's reads are flat too: every table is read once, including the page's
/// dialect ids.
async fn assert_misskey_page_is_flat(app: &Router, token: &str, log: &CapturedLog) {
    // Misskey names every note and author through `external_id`. Allocating a
    // missing mapping is a write path and stays row by row, so warm the page once;
    // the measured request is the read path a returning client sees.
    let _ = misskey_page_stats(app, token, log, 20).await;
    let (misskey_twenty, reaction_reads, media_reads, tag_reads, external_reads) =
        misskey_page_stats(app, token, log, 20).await;
    let (misskey_one, one_reaction, one_media, one_tag, one_external) =
        misskey_page_stats(app, token, log, 1).await;
    assert_eq!(
        misskey_one, misskey_twenty,
        "a page of twenty must cost the same statements as a page of one \
         (N=1 {misskey_one}, N=20 {misskey_twenty})"
    );
    assert_eq!(
        reaction_reads, 1,
        "twenty notes should read the reaction table once, saw {reaction_reads}"
    );
    assert_eq!(
        media_reads, 1,
        "twenty notes should read attachments once, saw {media_reads}"
    );
    assert_eq!(
        tag_reads, 1,
        "twenty notes should read tags and emoji once, saw {tag_reads}"
    );
    // One statement covers the page's status ids and its authors' account ids. A
    // per-note regression would read `external_id` at least once per note or author.
    assert_eq!(
        (one_external, external_reads),
        (1, 1),
        "twenty notes should read external ids once for the whole page, saw \
         {external_reads} (N=1 saw {one_external})"
    );
    assert_eq!(
        (one_reaction, one_media, one_tag),
        (1, 1, 1),
        "the single note's page should read each table once"
    );
    eprintln!(
        "misskey home timeline: N=1 {misskey_one} statements, N=20 {misskey_twenty} \
         statements ({reaction_reads} reaction read, {media_reads} attachment read, \
          {tag_reads} tag read, {external_reads} external_id read)"
    );
}

#[tokio::test]
async fn a_feed_page_reads_the_same_statements_at_any_page_size() {
    run_db_test(|store, app| async move {
        let viewer = create_account(store.pool(), "feedviewer").await;
        let token = create_token(store.pool(), &viewer, &["read", "write"]).await;

        // sqlx logs each statement at `DEBUG`; the subscriber lives for this process and
        // this binary has one test, so the capture cannot pick up another test's queries.
        let log = CapturedLog(Arc::new(Mutex::new(Vec::new())));
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(log.clone())
            .try_init()
            .expect("capture sqlx statement log");

        // One author and one post first, with an attachment and a reaction, so the N=1
        // page is a real page before the measurement starts.
        let first_status = seed_author(store.pool(), &viewer, 0, true).await;
        statuses::set_reaction(store.pool(), &first_status, &viewer, "⭐")
            .await
            .expect("set reaction");
        let mentioned = create_account(store.pool(), "mentioned").await;
        decorate(store.pool(), &first_status, &mentioned, "nodus").await;

        // Warm the request path (instance settings, token cache) so the N=1 measurement
        // is not paying first-request one-offs the N=20 measurement never sees.
        let _ = home_ids(&app, &token).await;

        clear(&log);
        let one_ids = home_ids(&app, &token).await;
        let one_endpoint = statements(&log);
        let one_old = old_path_statements(&store, &one_ids, &log).await;

        for index in 1..20 {
            let status = seed_author(store.pool(), &viewer, index, index < 3).await;
            if index < 3 {
                decorate(store.pool(), &status, &mentioned, "nodus").await;
            }
        }

        clear(&log);
        let twenty_ids = home_ids(&app, &token).await;
        let twenty_endpoint = statements(&log);
        let twenty_tag_reads = table_reads(&log, "FROM status_tag");
        let twenty_emoji_reads = table_reads(&log, "FROM status_emoji");
        let twenty_mention_reads = table_reads(&log, "FROM status_mention");
        let twenty_old = old_path_statements(&store, &twenty_ids, &log).await;

        // The page order is the store page's order, not `RowMap`'s id order: the handler
        // must walk `page.items`, because keys sorted by id are not sorted by time.
        let expected: Vec<String> = statuses::home_page(store.pool(), &viewer, PageParams::new())
            .await
            .expect("home page")
            .items
            .iter()
            .map(|row| row.id.clone())
            .collect();
        assert_eq!(twenty_ids, expected, "the endpoint reordered the page");

        assert_eq!(one_ids.len(), 1, "one post, one page");
        assert_eq!(twenty_ids.len(), 20, "twenty posts, one page");
        assert_eq!(
            one_endpoint, twenty_endpoint,
            "a page of twenty must cost the same statements as a page of one \
             (N=1 {one_endpoint}, N=20 {twenty_endpoint})"
        );
        assert_eq!(
            twenty_old - one_old,
            19,
            "the removed path paid one author lookup per extra row (N=1 {one_old}, N=20 {twenty_old})"
        );
        // Decorations are the same read at any page length: three families in one
        // statement, so a per-row regression shows up here as twenty.
        assert_eq!(
            (twenty_tag_reads, twenty_emoji_reads, twenty_mention_reads),
            (1, 1, 1),
            "twenty statuses should read tags, emoji and mentions once each, saw \
             ({twenty_tag_reads}, {twenty_emoji_reads}, {twenty_mention_reads})"
        );
        eprintln!(
            "mastodon home timeline: N=1 {one_endpoint} statements (old {one_old}); \
             N=20 {twenty_endpoint} statements (old {twenty_old}); \
             decorations: {twenty_tag_reads} tag, {twenty_emoji_reads} emoji, \
             {twenty_mention_reads} mention read"
        );

        assert_page_render_decorations(&app, &token, &first_status, &mentioned).await;

        assert_misskey_page_is_flat(&app, &token, &log).await;
    })
    .await;
}

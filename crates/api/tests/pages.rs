//! Backend-assembled pages: one call, one snapshot, one visibility gate.
//!
//! The functional cases cover the profile and the thread; the last case captures sqlx's
//! statement log and pins the read count so a per-row regression (the thing the page seam
//! exists to prevent) fails here.

mod support;

use std::sync::{Arc, Mutex};

use serde_json::Value;
use sqlx::PgPool;

use nodus_server_core::Id;
use nodus_server_store::statuses::{self, NewStatus};

use support::{
    create_account, create_status, create_token, expect_ok, json_of, run_db_test, send, send_anon,
};

/// Every test in this binary takes this guard: the statement-log subscriber is
/// process-wide, and a concurrently running test's queries would land in the capture.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL.lock().await
}

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

fn statements(log: &CapturedLog) -> usize {
    String::from_utf8_lossy(&log.0.lock().expect("log buffer"))
        .matches("sqlx::query:")
        .count()
}

fn table_reads(log: &CapturedLog, marker: &str) -> usize {
    String::from_utf8_lossy(&log.0.lock().expect("log buffer"))
        .matches(marker)
        .count()
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

async fn create_reply(
    pool: &PgPool,
    account_id: &str,
    parent_id: &str,
    parent_author: &str,
    content: &str,
) -> String {
    let id = Id::new().to_string();
    statuses::create(
        pool,
        &NewStatus {
            id: &id,
            account_id,
            content,
            content_html: content,
            content_source: None,
            content_format: "html",
            spoiler_text: "",
            visibility: "public",
            sensitive: false,
            in_reply_to_id: Some(parent_id),
            in_reply_to_account_id: Some(parent_author),
            reblog_of_id: None,
            language: None,
        },
        &[],
        &[],
        &[],
    )
    .await
    .expect("insert reply");
    id
}

fn page(body: &Value) -> &Value {
    body.get("page").expect("page cursors")
}

#[tokio::test]
async fn a_profile_page_carries_the_account_and_its_statuses() {
    let _serial = serial().await;
    run_db_test(|store, app| async move {
        let author = create_account(store.pool(), "profile").await;
        let first = create_status(store.pool(), &author, "first", "public", &[], &[]).await;
        let second = create_status(store.pool(), &author, "second", "public", &[], &[]).await;
        statuses::set_reaction(store.pool(), &first, &author, "⭐")
            .await
            .expect("reaction");

        let (status, body) =
            send_anon(&app, "GET", &format!("/api/v1/pages/profile/{author}")).await;
        let body = expect_ok(status, &body, "public profile page");
        let body = json_of(&body);
        assert_eq!(body["account"]["id"], author);
        let ids: Vec<&str> = body["statuses"]
            .as_array()
            .expect("statuses")
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, vec![second.as_str(), first.as_str()]);
        assert_eq!(body["statuses"][1]["reactions"][0]["reaction"], "⭐");
        assert!(body["relationship"].is_null(), "{body}");
        assert!(page(&body)["next"].is_null(), "two posts fit one page");
        assert!(
            page(&body)["prev"].is_null(),
            "the first page has no newer page"
        );

        // A signed-in reader gets the relationship in the same payload.
        let viewer = create_account(store.pool(), "profileviewer").await;
        let token = create_token(store.pool(), &viewer, &["read"]).await;
        let (status, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/pages/profile/{author}"),
            None,
        )
        .await;
        let body = expect_ok(status, &body, "signed-in profile page");
        let body = json_of(&body);
        assert_eq!(body["relationship"]["following"], false);
        assert_eq!(body["relationship"]["id"], author);
    })
    .await;
}

#[tokio::test]
async fn a_private_account_does_not_show_its_post_to_an_anonymous_reader() {
    let _serial = serial().await;
    run_db_test(|store, app| async move {
        let author = create_account(store.pool(), "privateprofile").await;
        sqlx::query("UPDATE account SET locked = true WHERE id = $1")
            .bind(&author)
            .execute(store.pool())
            .await
            .expect("lock account");
        let public = create_status(store.pool(), &author, "public still", "public", &[], &[]).await;
        let private =
            create_status(store.pool(), &author, "followers only", "private", &[], &[]).await;

        let (status, body) =
            send_anon(&app, "GET", &format!("/api/v1/pages/profile/{author}")).await;
        let body = expect_ok(status, &body, "private profile page");
        let body = json_of(&body);
        let ids: Vec<&str> = body["statuses"]
            .as_array()
            .expect("statuses")
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(
            ids,
            vec![public.as_str()],
            "the private post leaked: {body}"
        );
        assert!(
            !ids.contains(&private.as_str()),
            "a locked account's followers-only post is not an anonymous page"
        );
    })
    .await;
}

#[tokio::test]
async fn a_paused_domain_author_is_absent_from_the_payload() {
    let _serial = serial().await;
    run_db_test(|store, app| async move {
        let author = create_account(store.pool(), "pausedauthor").await;
        sqlx::query(
            "UPDATE account SET local = false, domain = 'paused.test', \
             uri = 'https://paused.test/users/x' WHERE id = $1",
        )
        .bind(&author)
        .execute(store.pool())
        .await
        .expect("make author remote");
        create_status(
            store.pool(),
            &author,
            "from a paused domain",
            "public",
            &[],
            &[],
        )
        .await;
        sqlx::query("INSERT INTO domain_pause (domain, reason) VALUES ('paused.test', 'test')")
            .execute(store.pool())
            .await
            .expect("pause domain");

        let (status, body) =
            send_anon(&app, "GET", &format!("/api/v1/pages/profile/{author}")).await;
        let body = expect_ok(status, &body, "paused profile page");
        let body = json_of(&body);
        assert!(
            body["statuses"].as_array().is_some_and(Vec::is_empty),
            "a paused domain's post leaked: {body}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_status_page_carries_its_ancestor_and_its_reply() {
    let _serial = serial().await;
    run_db_test(|store, app| async move {
        let author = create_account(store.pool(), "thread").await;
        let parent = create_status(store.pool(), &author, "parent", "public", &[], &[]).await;
        let focused = create_reply(store.pool(), &author, &parent, &author, "focused reply").await;
        let reply =
            create_reply(store.pool(), &author, &focused, &author, "reply to focused").await;
        statuses::set_reaction(store.pool(), &focused, &author, "🔥")
            .await
            .expect("reaction");

        let (status, body) =
            send_anon(&app, "GET", &format!("/api/v1/pages/status/{focused}")).await;
        let body = expect_ok(status, &body, "status page");
        let body = json_of(&body);
        assert_eq!(body["status"]["id"], focused);
        assert_eq!(body["status"]["reactions"][0]["reaction"], "🔥");
        assert_eq!(
            body["ancestors"][0]["id"], parent,
            "the chain is ordered oldest first"
        );
        assert_eq!(body["descendants"][0]["id"], reply);
        assert!(body["context"]["next"].is_null());

        let viewer = create_account(store.pool(), "threadviewer").await;
        let token = create_token(store.pool(), &viewer, &["read"]).await;
        let (status, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/pages/status/{focused}"),
            None,
        )
        .await;
        let body = expect_ok(status, &body, "signed-in status page");
        assert_eq!(json_of(&body)["status"]["id"], focused);

        // A quarantined reply is not painted on the thread, even though its row exists.
        sqlx::query("UPDATE status SET quarantined_at = now() WHERE id = $1")
            .bind(&reply)
            .execute(store.pool())
            .await
            .expect("quarantine reply");
        let (status, body) =
            send_anon(&app, "GET", &format!("/api/v1/pages/status/{focused}")).await;
        let body = expect_ok(status, &body, "status page after quarantine");
        let body = json_of(&body);
        assert!(
            body["descendants"].as_array().is_some_and(Vec::is_empty),
            "a quarantined reply leaked: {body}"
        );
        assert_eq!(body["ancestors"][0]["id"], parent);
    })
    .await;
}

#[tokio::test]
async fn page_reads_do_not_grow_with_the_number_of_posts() {
    let _serial = serial().await;
    run_db_test(|store, app| async move {
        let log = CapturedLog(Arc::new(Mutex::new(Vec::new())));
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(log.clone())
            .try_init()
            .ok();

        let author = create_account(store.pool(), "pagecount").await;
        let viewer = create_account(store.pool(), "pagecountviewer").await;
        let token = create_token(store.pool(), &viewer, &["read"]).await;
        for index in 0..20 {
            let status = create_status(
                store.pool(),
                &author,
                &format!("page post {index}"),
                "public",
                &[],
                &[],
            )
            .await;
            if index == 0 {
                attach(store.pool(), &author, &status).await;
            }
            statuses::set_reaction(store.pool(), &status, &viewer, "⭐")
                .await
                .expect("reaction");
        }

        // Warm the request path so the N=1 measurement does not pay a first-request cost.
        let (status, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/pages/profile/{author}?limit=1"),
            None,
        )
        .await;
        expect_ok(status, &body, "warm profile page");

        clear(&log);
        let (status, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/pages/profile/{author}?limit=1"),
            None,
        )
        .await;
        let body = expect_ok(status, &body, "profile page of one");
        assert_eq!(json_of(&body)["statuses"].as_array().map(Vec::len), Some(1));
        let one = statements(&log);

        clear(&log);
        let (status, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/pages/profile/{author}?limit=20"),
            None,
        )
        .await;
        let body = expect_ok(status, &body, "profile page of twenty");
        assert_eq!(
            json_of(&body)["statuses"].as_array().map(Vec::len),
            Some(20)
        );
        let twenty = statements(&log);
        let reaction_reads = table_reads(&log, "FROM status_reaction");
        let media_reads = table_reads(&log, "WHERE m.status_id = ANY");

        assert_eq!(
            one, twenty,
            "a page of twenty must cost the same statements as a page of one \
             (N=1 {one}, N=20 {twenty})"
        );
        assert_eq!(reaction_reads, 1, "reaction chips came from one read");
        assert_eq!(one, 13, "the profile page's statement count changed");

        // The thread page's count is pinned for a one-ancestor, one-reply fixture. Its
        // rows never carry a `limit`, so this is the page's shape, not a page-size knob.
        let parent = create_status(store.pool(), &author, "count parent", "public", &[], &[]).await;
        let focused = create_reply(store.pool(), &author, &parent, &author, "count focused").await;
        create_reply(store.pool(), &author, &focused, &author, "count reply").await;
        clear(&log);
        let (status, body) =
            send_anon(&app, "GET", &format!("/api/v1/pages/status/{focused}")).await;
        expect_ok(status, &body, "thread page");
        let thread_reads = statements(&log);
        let thread_reaction_reads = table_reads(&log, "FROM status_reaction");
        assert_eq!(
            thread_reaction_reads, 1,
            "the thread's chips came from one read"
        );

        eprintln!(
            "pages: profile N=1 {one} statements, N=20 {twenty} statements \
             ({reaction_reads} reaction read, {media_reads} attachment read); \
             thread {thread_reads} statements"
        );
        assert_eq!(media_reads, 1, "attachments came from one read");
        assert_eq!(
            thread_reads, 12,
            "the thread page's statement count changed"
        );
    })
    .await;
}

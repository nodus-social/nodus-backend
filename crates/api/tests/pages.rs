//! Backend-assembled pages: one call, one snapshot, one visibility gate.
//!
//! The functional cases cover the profile and the thread; the last case captures sqlx's
//! statement log and pins the read count so a per-row regression (the thing the page seam
//! exists to prevent) fails here.

mod support;

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
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

/// sqlx logs each statement's shortened summary at DEBUG; these two markers are long
/// enough to be unique among them and short enough to survive the truncation.
const COMMIT: &str = "summary=\"COMMIT\"";
const HANDLE_RESOLVE: &str = "summary=\"SELECT id, username::text AS";
const PAGE_READ: &str = "summary=\"SELECT s.id, s.account_id";

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

/// The `name@host` spelling of a fixture account: the same handle a reader would type in
/// the web client's `/accounts/{host}/{name}` route.
async fn handle_of(pool: &PgPool, account_id: &str, host: &str) -> String {
    let username: String = sqlx::query_scalar("SELECT username::text FROM account WHERE id = $1")
        .bind(account_id)
        .fetch_one(pool)
        .await
        .expect("account username");
    format!("{username}@{host}")
}

async fn profile_by_id(app: &axum::Router, account_id: &str) -> Value {
    let (status, body) =
        send_anon(app, "GET", &format!("/api/v1/pages/profile/{account_id}")).await;
    json_of(&expect_ok(status, &body, "profile by id"))
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
async fn a_handle_answers_the_same_profile_page_as_an_id() {
    let _serial = serial().await;
    run_db_test(|store, app| async move {
        let author = create_account(store.pool(), "handlepage").await;
        create_status(store.pool(), &author, "first", "public", &[], &[]).await;
        create_status(store.pool(), &author, "second", "public", &[], &[]).await;
        let by_id = profile_by_id(&app, &author).await;

        // The SDK's URL builder leaves `@` literal in a path segment; a client that
        // percent-encodes it instead is decoded by axum, so both spellings answer.
        let handle = handle_of(store.pool(), &author, "social.test").await;
        let (status, body) =
            send_anon(&app, "GET", &format!("/api/v1/pages/profile/{handle}")).await;
        let by_handle = json_of(&expect_ok(status, &body, "profile by handle"));
        assert_eq!(
            by_handle, by_id,
            "the handle form must answer the id form's document"
        );

        let encoded = handle.replace('@', "%40");
        let (status, body) =
            send_anon(&app, "GET", &format!("/api/v1/pages/profile/{encoded}")).await;
        let by_encoded = json_of(&expect_ok(status, &body, "profile by encoded handle"));
        assert_eq!(by_encoded, by_id, "a %40 handle answers the same document");

        // The viewer-dependent half of the payload (the relationship) is identical too.
        let viewer = create_account(store.pool(), "handleviewer").await;
        let token = create_token(store.pool(), &viewer, &["read"]).await;
        let (status, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/pages/profile/{author}"),
            None,
        )
        .await;
        let signed_in_by_id = json_of(&expect_ok(status, &body, "signed-in profile by id"));
        let (status, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/pages/profile/{handle}"),
            None,
        )
        .await;
        let signed_in_by_handle = json_of(&expect_ok(status, &body, "signed-in profile by handle"));
        assert_eq!(signed_in_by_handle, signed_in_by_id);
        assert_eq!(signed_in_by_handle["relationship"]["id"], author);

        // `pinned=true` is refused on both forms, before either target is resolved.
        for target in [author.as_str(), handle.as_str()] {
            let (status, body) = send_anon(
                &app,
                "GET",
                &format!("/api/v1/pages/profile/{target}?pinned=true"),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{target}: {body}");
            assert_eq!(
                json_of(&body)["error"],
                "pinned statuses are not stored on this instance"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn a_remote_handle_resolves_by_its_own_domain() {
    let _serial = serial().await;
    run_db_test(|store, app| async move {
        let author = create_account(store.pool(), "remotehandle").await;
        sqlx::query(
            "UPDATE account SET local = false, domain = 'remote.test', \
             uri = 'https://remote.test/users/x' WHERE id = $1",
        )
        .bind(&author)
        .execute(store.pool())
        .await
        .expect("make author remote");
        create_status(
            store.pool(),
            &author,
            "from the remote host",
            "public",
            &[],
            &[],
        )
        .await;

        let by_id = profile_by_id(&app, &author).await;
        let handle = handle_of(store.pool(), &author, "remote.test").await;
        let (status, body) =
            send_anon(&app, "GET", &format!("/api/v1/pages/profile/{handle}")).await;
        let by_handle = json_of(&expect_ok(status, &body, "remote profile by handle"));
        assert_eq!(by_handle, by_id, "the remote domain is part of the handle");
        assert_eq!(
            by_handle["statuses"].as_array().map(Vec::len),
            Some(1),
            "the remote account's post is on the page: {by_handle}"
        );

        // The same username under a different host names nobody on this instance; the
        // instance domain must not be silently substituted for it.
        let username = handle_of(store.pool(), &author, "elsewhere.test").await;
        let (status, body) =
            send_anon(&app, "GET", &format!("/api/v1/pages/profile/{username}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    })
    .await;
}

#[tokio::test]
async fn an_unknown_handle_is_a_404_that_names_it() {
    let _serial = serial().await;
    run_db_test(|store, app| async move {
        let _ = store;
        let (status, body) =
            send_anon(&app, "GET", "/api/v1/pages/profile/nobody%40social.test").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let body = json_of(&body);
        let message = body["error"].as_str().unwrap_or_default();
        assert!(
            message.contains("nobody@social.test"),
            "the reason names the handle: {body}"
        );
        assert!(
            message.contains("not known here"),
            "the reason says the handle is unknown here, not that the page is empty: {body}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_silenced_accounts_handle_is_refused_by_the_id_forms_predicate() {
    let _serial = serial().await;
    run_db_test(|store, app| async move {
        let author = create_account(store.pool(), "silencedhandle").await;
        create_status(store.pool(), &author, "before silence", "public", &[], &[]).await;
        sqlx::query("UPDATE account SET silenced_at = now() WHERE id = $1")
            .bind(&author)
            .execute(store.pool())
            .await
            .expect("silence account");

        let by_id = profile_by_id(&app, &author).await;
        assert!(
            by_id["statuses"].as_array().is_some_and(Vec::is_empty),
            "the id form's predicate hides a silenced author's post: {by_id}"
        );

        let handle = handle_of(store.pool(), &author, "social.test").await;
        let (status, body) =
            send_anon(&app, "GET", &format!("/api/v1/pages/profile/{handle}")).await;
        let by_handle = json_of(&expect_ok(status, &body, "silenced profile by handle"));
        assert_eq!(
            by_handle, by_id,
            "the handle form must apply the same predicate, not a looser one"
        );
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
        assert_eq!(
            one, 14,
            "the profile page's statement count changed: the picture-shape op is one \
             page-level read, not one per account"
        );
        let id_commits = table_reads(&log, COMMIT);

        // The handle form resolves the account inside the same snapshot as the page: one
        // explicit transaction, so the resolve replaces the id lookup and its `COMMIT`
        // is the only statement the id form does not pay.
        let handle = handle_of(store.pool(), &author, "social.test").await;
        clear(&log);
        let (status, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/pages/profile/{handle}?limit=1"),
            None,
        )
        .await;
        let body = expect_ok(status, &body, "profile page by handle");
        assert_eq!(json_of(&body)["statuses"].as_array().map(Vec::len), Some(1));
        let by_handle = statements(&log);
        let text = String::from_utf8_lossy(&log.0.lock().expect("log buffer")).into_owned();
        let resolve_at = text
            .find(HANDLE_RESOLVE)
            .expect("the handle resolve is missing from the log");
        let page_at = text
            .find(PAGE_READ)
            .expect("the page read is missing from the log");
        let commit_at = text.find(COMMIT).expect("no commit for the handle page");
        assert!(
            resolve_at < page_at && page_at < commit_at,
            "the handle must be resolved and the page read in one snapshot, in that order"
        );
        let handle_commits = table_reads(&log, COMMIT);
        assert_eq!(
            (id_commits, handle_commits),
            (1, 2),
            "the handle page adds one explicit transaction (the resolve + page snapshot) \
             on top of the id form's hydration batch"
        );
        assert_eq!(
            by_handle,
            one + 1,
            "the handle form costs the id form's statements plus its snapshot's COMMIT \
             (id {one}, handle {by_handle})"
        );

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
             profile by handle {by_handle} statements; thread {thread_reads} statements"
        );
        assert_eq!(media_reads, 1, "attachments came from one read");
        assert_eq!(
            thread_reads, 13,
            "the thread page's statement count changed: one picture-shape read covers every \
             author on the page"
        );
    })
    .await;
}

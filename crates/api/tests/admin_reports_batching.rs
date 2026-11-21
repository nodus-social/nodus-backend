//! A report page reads its accounts once, not four times per row.
//!
//! `report_dto` names four accounts — reporter, target, assignee, acting moderator — and
//! used to read each with a statement of its own, per report. This binary captures sqlx's
//! statement log and pins the account-table read count and the total at N=1 and N=20.
//!
//! Reports carry no statuses or rules on purpose: status hydration lives in `statuses.rs`.

mod support;

use std::sync::{Arc, Mutex};

use axum::Router;
use sqlx::PgPool;

use nodus_server_store::accounts;
use nodus_server_store::moderation::{self, NewReport, ReportFilter, ReportRow};
use nodus_server_store::Store;

use support::{create_account, create_token, expect_ok, json_of, run_db_test, send};

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

fn account_reads(log: &CapturedLog) -> usize {
    captured(log).matches("FROM account").count()
}

/// A staff account and a token carrying exactly the scopes under test.
async fn staff(pool: &PgPool, label: &str, role: &str, scopes: &[&str]) -> (String, String) {
    let id = create_account(pool, label).await;
    accounts::set_staff_role(pool, &id, role)
        .await
        .expect("set staff role");
    let token = create_token(pool, &id, scopes).await;
    (id, token)
}

/// Files `count` reports about distinct targets; every second one is assigned to a
/// moderator and resolved, so the page carries assignees and acting moderators too.
async fn seed_reports(
    pool: &PgPool,
    reporter: &str,
    moderator: &str,
    count: usize,
) -> Vec<ReportRow> {
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let target = create_account(pool, &format!("reported{index}")).await;
        let row = moderation::create_report(
            pool,
            &NewReport {
                account_id: Some(reporter),
                target_account_id: &target,
                status_ids: &[],
                category: "spam",
                comment: "",
                rule_ids: &[],
                activity_uri: None,
            },
        )
        .await
        .expect("create report");
        if index % 2 == 0 {
            moderation::assign_report(pool, &row.id, Some(moderator))
                .await
                .expect("assign report");
            moderation::resolve_report(pool, &row.id, moderator, "")
                .await
                .expect("resolve report");
        }
        rows.push(row);
    }
    rows
}

/// One queue page, and how many statements it took to build.
async fn page_stats(app: &Router, token: &str, log: &CapturedLog, limit: u32) -> (usize, usize) {
    clear(log);
    let (status, body) = send(
        app,
        token,
        "GET",
        &format!("/api/v1/admin/reports?limit={limit}"),
        None,
    )
    .await;
    let body = expect_ok(status, &body, "/api/v1/admin/reports");
    let page = json_of(&body);
    let items = page.as_array().expect("reports is an array");
    assert_eq!(
        items.len(),
        usize::try_from(limit).expect("fits"),
        "the queue returned the requested page"
    );
    // Every named account still reaches the payload in its own slot: a batch that
    // dropped rows would show up as a null here.
    for item in items {
        assert!(
            item["target_account"]["id"].is_string(),
            "a report lost its target account: {item}"
        );
        assert!(
            item["reporter"]["id"].is_string(),
            "a report lost its reporter: {item}"
        );
    }
    (statements(log), account_reads(log))
}

/// The removed path, replayed against the same page: four reads per report.
async fn old_path_statements(store: &Store, page: &[ReportRow], log: &CapturedLog) -> usize {
    clear(log);
    for row in page {
        if let Some(id) = row.account_id.as_deref() {
            let _ = store.account(id).await.expect("reporter read");
        }
        let _ = store
            .account(&row.target_account_id)
            .await
            .expect("target read");
        if let Some(id) = row.assigned_account_id.as_deref() {
            let _ = store.account(id).await.expect("assignee read");
        }
        if let Some(id) = row.action_taken_by_account_id.as_deref() {
            let _ = store.account(id).await.expect("acting moderator read");
        }
    }
    statements(log)
}

#[tokio::test]
async fn a_report_page_reads_its_accounts_once() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (moderator, token) = staff(pool, "report-mod", "moderator", &["admin:read"]).await;
        let reporter = create_account(pool, "report-reporter").await;
        seed_reports(pool, &reporter, &moderator, 20).await;

        // sqlx logs each statement at `DEBUG`; the subscriber lives for this process and
        // this binary has one test, so the capture cannot pick up another test's queries.
        let log = CapturedLog(Arc::new(Mutex::new(Vec::new())));
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(log.clone())
            .try_init()
            .expect("install the capturing subscriber");

        let (twenty_total, twenty_accounts) = page_stats(&app, &token, &log, 20).await;
        let (one_total, one_accounts) = page_stats(&app, &token, &log, 1).await;
        assert_eq!(
            (one_accounts, twenty_accounts),
            (1, 1),
            "a page of reports must read the account table once, whatever its length \
             (N=1 {one_accounts}, N=20 {twenty_accounts})"
        );
        assert_eq!(
            one_total, twenty_total,
            "a page of twenty must cost the same statements as a page of one \
             (N=1 {one_total}, N=20 {twenty_total})"
        );

        // The removed path, replayed on the same rows, pays the old price.
        let page = moderation::reports(
            pool,
            &ReportFilter {
                limit: 20,
                ..ReportFilter::default()
            },
        )
        .await
        .expect("report page");
        let before = old_path_statements(&store, &page, &log).await;
        assert!(before > twenty_total, "per-row path cost {before}");

        // A single report reads its own four ids in one batch too. The queue lists
        // untouched reports first, so pick one that carries both moderator slots.
        let resolved = page
            .iter()
            .find(|row| row.assigned_account_id.is_some())
            .expect("a resolved report on the page");
        let one_before = old_path_statements(&store, std::slice::from_ref(resolved), &log).await;
        clear(&log);
        let (status, detail) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/admin/reports/{}", resolved.id),
            None,
        )
        .await;
        let detail = json_of(&expect_ok(status, &detail, "/api/v1/admin/reports/{id}"));
        assert_eq!(
            account_reads(&log),
            1,
            "one report must read its accounts in one statement"
        );
        for slot in [
            "reporter",
            "target_account",
            "assigned_account",
            "action_taken_by",
        ] {
            assert!(
                detail[slot]["id"].is_string(),
                "the detail route lost its {slot}: {detail}"
            );
        }
        eprintln!(
            "report queue: {before} account statements before, {twenty_accounts} now \
             (page total {twenty_total} at N=20, {one_total} at N=1); report detail: \
             {one_before} before, 1 now"
        );
    })
    .await;
}

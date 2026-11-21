//! `GET /api/v1/lists/{id}/accounts` reads a page of members in one snapshot.
//!
//! The endpoint used to look each member up on its own, in `account_ids` order. Reading
//! them in one batch must not change that order: the list is a client-visible sequence
//! (newest membership first), not a set.

mod support;

use std::sync::{Arc, Mutex};

use serde_json::json;

use support::{create_account, create_token, expect_ok, run_db_test, send};

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

/// Counts the account-table lookups and all statements in the captured log.
fn statement_counts(log: &CapturedLog) -> (usize, usize) {
    let buffer = log.0.lock().expect("log buffer");
    let text = String::from_utf8_lossy(&buffer);
    (
        text.matches("FROM account WHERE id").count(),
        text.matches("sqlx::query:").count(),
    )
}

#[tokio::test]
async fn list_members_come_back_in_membership_order() {
    run_db_test(|store, app| async move {
        let owner = create_account(store.pool(), "listowner").await;
        let token = create_token(store.pool(), &owner, &["read", "write"]).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/lists",
            Some(json!({ "title": "Members" })),
        )
        .await;
        let list: serde_json::Value = serde_json::from_str(&expect_ok(
            status,
            &body,
            "POST /api/v1/lists",
        ))
        .expect("list json");
        let list_id = list["id"].as_str().expect("list id").to_owned();

        let mut members = Vec::new();
        for index in 0..12 {
            members.push(create_account(store.pool(), &format!("member{index}")).await);
        }
        for member in &members {
            let (status, body) = send(
                &app,
                &token,
                "POST",
                &format!("/api/v1/lists/{list_id}/accounts"),
                Some(json!({ "account_ids": [member] })),
            )
            .await;
            let _ = expect_ok(status, &body, "POST …/lists/{id}/accounts");
        }

        // sqlx logs each statement at `DEBUG`; the subscriber lives for this process and
        // this binary has one test, so the capture cannot pick up another test's queries.
        let log = CapturedLog(Arc::new(Mutex::new(Vec::new())));
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(log.clone())
            .try_init()
            .expect("capture sqlx statement log");
        log.0.lock().expect("log buffer").clear();

        let (status, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/lists/{list_id}/accounts"),
            None,
        )
        .await;
        let listed: serde_json::Value = serde_json::from_str(&expect_ok(
            status,
            &body,
            "GET …/lists/{id}/accounts",
        ))
        .expect("accounts json");
        let returned: Vec<String> = listed
            .as_array()
            .expect("account array")
            .iter()
            .map(|account| account["id"].as_str().expect("account id").to_owned())
            .collect();

        let (batched_lookups, batched_statements) = statement_counts(&log);

        // The baseline the endpoint used to pay: the same membership read, then one
        // `accounts::by_id` per member.
        log.0.lock().expect("log buffer").clear();
        for member in &members {
            let _ = store.account(member)
                .await
                .expect("by_id");
        }
        let (per_member_lookups, _) = statement_counts(&log);

        // The batch is keyed by id (`RowMap` is sorted); the response must still be the
        // membership sequence the store's own read returns.
        let expected = nodus_server_store::lists::account_ids(store.pool(), &list_id, 200)
            .await
            .expect("membership ids");
        assert_eq!(returned, expected);
        assert_eq!(returned.len(), members.len());
        assert_eq!(
            batched_lookups, 1,
            "the endpoint should read the account table once, saw {batched_statements} statements"
        );
        assert_eq!(
            per_member_lookups,
            members.len(),
            "the removed path is one account lookup per member"
        );
        eprintln!(
            "lists accounts: {} members, endpoint {batched_statements} statements/{batched_lookups} account lookups; \
             removed loop {per_member_lookups} account lookups",
            members.len()
        );
    })
    .await;
}

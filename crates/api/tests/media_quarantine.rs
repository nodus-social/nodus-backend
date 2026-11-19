//! What the content sets do to media federated in, and what a moderator can do about it.
//!
//! The point of the whole path is that nobody had to be looking: an attachment that matches
//! a registered set leaves the public timelines on its own and lands in the queue with the
//! set's name on it. These tests drive the real check (`guard::screen_status`) against media
//! rows that already carry their hashes, so no peer is involved and no bytes are fetched —
//! the hash step itself is covered by the media crate's own tests.

mod support;

use axum::Router;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use nodus_server_api::guard::{self, PERCEPTUAL_DISTANCE_MAX};
use nodus_server_core::Id;
use nodus_server_store::media::{self, MediaRow, RemoteAttachment};
use nodus_server_store::moderation;
use nodus_server_store::scanners::{self, NewAsset};

use support::{create_account, create_status, create_token, run_db_test, send, send_anon};

const SET_NAME: &str = "known-hostile-images";

fn hex_sha(seed: &str) -> String {
    format!("{:x}", Sha256::digest(seed.as_bytes()))
}

/// Registers a hash set the way an administrator uploads one: one entry per line.
async fn upload_set(pool: &PgPool, name: &str, entries: &[String]) {
    let content = entries.join("\n");
    let digest = format!("{:x}", Sha256::digest(content.as_bytes()));
    scanners::create_asset(
        pool,
        &NewAsset {
            name,
            kind: "hashes",
            digest: &digest,
            size: i64::try_from(content.len()).unwrap(),
            content_type: "text/plain",
            content: content.as_bytes(),
        },
    )
    .await
    .expect("register a content set");
}

/// One federated attachment row, pointing at a URL no test ever fetches.
async fn attach_remote(pool: &PgPool, status_id: &str, account_id: &str, url: &str) -> String {
    media::replace_remote(
        pool,
        status_id,
        account_id,
        false,
        &[RemoteAttachment {
            url,
            content_type: "image/png",
            description: "",
            width: Some(64),
            height: Some(64),
            blurhash: None,
        }],
    )
    .await
    .expect("store a remote attachment");
    media::by_status(pool, status_id)
        .await
        .expect("read attachments")
        .into_iter()
        .find(|row| row.remote_url.as_deref() == Some(url))
        .expect("the attachment just stored")
        .id
}

async fn make_admin(pool: &PgPool, account_id: &str) {
    sqlx::query("UPDATE account SET admin = true, approved = true WHERE id = $1")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("make the account staff");
}

async fn quarantined(pool: &PgPool, media_id: &str) -> String {
    media::by_id(pool, media_id)
        .await
        .expect("read media")
        .expect("media exists")
        .quarantine_state
}

async fn hidden_until(pool: &PgPool, status_id: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    sqlx::query_scalar("SELECT quarantined_at FROM status WHERE id = $1")
        .bind(status_id)
        .fetch_one(pool)
        .await
        .expect("read status")
}

async fn on_public_timeline(app: &Router, status_id: &str) -> bool {
    let (status, body) = send_anon(app, "GET", "/api/v1/timelines/public").await;
    assert_eq!(status, 200, "public timeline: {body}");
    let page: Value = serde_json::from_str(&body).expect("timeline json");
    page.as_array()
        .expect("a timeline is an array")
        .iter()
        .any(|entry| entry["id"] == status_id)
}

/// The open report about a post, if the queue has one.
async fn open_report(pool: &PgPool, status_id: &str) -> Option<moderation::ReportRow> {
    moderation::reports(
        pool,
        &moderation::ReportFilter {
            state: Some("open"),
            limit: 50,
            ..Default::default()
        },
    )
    .await
    .expect("read the queue")
    .into_iter()
    .find(|row| row.status_ids.iter().any(|id| id == status_id))
}

async fn audit_actions(pool: &PgPool, target_id: &str) -> Vec<(String, Value)> {
    sqlx::query_as("SELECT action, detail FROM audit_log WHERE target_id = $1 ORDER BY created_at")
        .bind(target_id)
        .fetch_all(pool)
        .await
        .expect("read the audit log")
}

#[tokio::test]
async fn an_exact_match_quarantines_the_post_and_opens_a_report() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = create_account(pool, "author").await;
        let status_id = create_status(pool, &author, "look at this", "public", &[], &[]).await;
        let media_id = attach_remote(pool, &status_id, &author, "https://peer.test/a.png").await;

        let sha = hex_sha("hostile block");
        media::set_hashes(pool, &media_id, &sha, None)
            .await
            .expect("record the hash");
        upload_set(pool, SET_NAME, std::slice::from_ref(&sha)).await;

        let matched = guard::screen_status(pool, &status_id, &author)
            .await
            .expect("run the check");
        assert_eq!(matched, 1, "an exact hash must match");

        let row = media::by_id(pool, &media_id)
            .await
            .expect("read media")
            .expect("media exists");
        assert_eq!(row.quarantine_state, "quarantined");
        assert_eq!(row.quarantine_set.as_deref(), Some(SET_NAME));
        assert!(
            hidden_until(pool, &status_id).await.is_some(),
            "the post must leave the timelines"
        );
        assert!(
            !on_public_timeline(&app, &status_id).await,
            "a quarantined post is not on the public timeline"
        );

        // A link someone already has still resolves: the post is hidden, not a 404.
        let (status, body) = send_anon(&app, "GET", &format!("/api/v1/statuses/{status_id}")).await;
        assert_eq!(status, 200, "direct link: {body}");
        assert!(body.contains(&status_id), "body: {body}");

        let report = open_report(pool, &status_id)
            .await
            .expect("the queue must hold the match");
        assert_eq!(report.target_account_id, author);
        assert!(
            report.account_id.is_none(),
            "the instance filed this one, not a person"
        );
        assert!(
            report.comment.contains(SET_NAME),
            "the report must name the set: {}",
            report.comment
        );

        // Running the check again changes nothing: no second report, same state.
        let again = guard::screen_status(pool, &status_id, &author)
            .await
            .expect("run the check again");
        assert_eq!(again, 0);
        assert_eq!(
            moderation::reports(
                pool,
                &moderation::ReportFilter {
                    state: Some("open"),
                    limit: 50,
                    ..Default::default()
                },
            )
            .await
            .expect("read the queue")
            .len(),
            1
        );
    })
    .await;
}

#[tokio::test]
async fn a_near_hash_matches_and_one_outside_the_reach_does_not() {
    run_db_test(|store, _app| async move {
        let pool = store.pool();
        let author = create_account(pool, "author-near").await;

        // Two bits away from the listed value: inside the threshold.
        let listed = 0x0000_0000_0000_0000u64;
        let near = listed ^ (1 << 3) ^ (1 << 9);
        // Every bit different: 64 away, far outside it.
        let far = u64::MAX;

        upload_set(pool, SET_NAME, &[format!("{listed:016x}")]).await;

        let near_status = create_status(pool, &author, "near", "public", &[], &[]).await;
        let near_media =
            attach_remote(pool, &near_status, &author, "https://peer.test/near.png").await;
        media::set_hashes(
            pool,
            &near_media,
            &hex_sha("near"),
            Some(&format!("{near:016x}")),
        )
        .await
        .expect("record the near hash");

        let far_status = create_status(pool, &author, "far", "public", &[], &[]).await;
        let far_media =
            attach_remote(pool, &far_status, &author, "https://peer.test/far.png").await;
        media::set_hashes(
            pool,
            &far_media,
            &hex_sha("far"),
            Some(&format!("{far:016x}")),
        )
        .await
        .expect("record the far hash");

        let distance = (near ^ listed).count_ones();
        assert!(distance <= PERCEPTUAL_DISTANCE_MAX, "the test's premise");

        assert_eq!(
            guard::screen_status(pool, &near_status, &author)
                .await
                .expect("run the check"),
            1,
            "{distance} bits away is inside the {PERCEPTUAL_DISTANCE_MAX}-bit threshold"
        );
        assert_eq!(quarantined(pool, &near_media).await, "quarantined");

        assert_eq!(
            guard::screen_status(pool, &far_status, &author)
                .await
                .expect("run the check"),
            0,
            "a different picture must not match"
        );
        assert_eq!(quarantined(pool, &far_media).await, "none");
        assert!(hidden_until(pool, &far_status).await.is_none());
    })
    .await;
}

#[tokio::test]
async fn releasing_puts_the_post_back_and_closes_the_report() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = create_account(pool, "author-release").await;
        let staff = create_account(pool, "staff-release").await;
        make_admin(pool, &staff).await;
        let token = create_token(pool, &staff, &["read", "admin:read", "admin:write"]).await;

        let status_id = create_status(pool, &author, "released", "public", &[], &[]).await;
        let media_id = attach_remote(pool, &status_id, &author, "https://peer.test/ok.png").await;
        let sha = hex_sha("released block");
        media::set_hashes(pool, &media_id, &sha, None)
            .await
            .expect("record the hash");
        upload_set(pool, SET_NAME, &[sha]).await;
        guard::screen_status(pool, &status_id, &author)
            .await
            .expect("run the check");
        assert!(!on_public_timeline(&app, &status_id).await);

        // Staff see the match, named, before they decide.
        let (status, body) =
            send(&app, &token, "GET", "/api/v1/admin/media/quarantined", None).await;
        assert_eq!(status, 200, "queue: {body}");
        assert!(
            body.contains(SET_NAME) && body.contains(&media_id),
            "the decision screen must name the set and the attachment: {body}"
        );

        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/admin/media/{media_id}/quarantine"),
            Some(json!({ "release": true, "reason": "it is a stock photo of a fence" })),
        )
        .await;
        assert_eq!(status, 200, "release: {body}");

        assert_eq!(quarantined(pool, &media_id).await, "released");
        assert!(
            hidden_until(pool, &status_id).await.is_none(),
            "release restores the post"
        );
        assert!(
            on_public_timeline(&app, &status_id).await,
            "a released post is back on the public timeline"
        );
        let report = open_report(pool, &status_id).await;
        assert!(report.is_none(), "the release closes the queue entry");
        let entries = audit_actions(pool, &media_id).await;
        assert!(
            entries
                .iter()
                .any(|(action, detail)| action == "release_media_quarantine"
                    && detail["reason"] == "it is a stock photo of a fence"),
            "the decision is written down: {entries:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn deleting_removes_the_attachment_and_keeps_the_report_resolved() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = create_account(pool, "author-delete").await;
        let staff = create_account(pool, "staff-delete").await;
        make_admin(pool, &staff).await;
        let token = create_token(pool, &staff, &["read", "admin:read", "admin:write"]).await;

        let status_id = create_status(pool, &author, "deleted", "public", &[], &[]).await;
        let media_id = attach_remote(pool, &status_id, &author, "https://peer.test/bad.png").await;
        let sha = hex_sha("deleted block");
        media::set_hashes(pool, &media_id, &sha, None)
            .await
            .expect("record the hash");
        upload_set(pool, SET_NAME, &[sha]).await;
        guard::screen_status(pool, &status_id, &author)
            .await
            .expect("run the check");
        assert!(open_report(pool, &status_id).await.is_some());

        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/admin/media/{media_id}/quarantine"),
            Some(json!({ "release": false, "reason": "known CSAM set" })),
        )
        .await;
        assert_eq!(status, 200, "delete: {body}");

        assert!(
            media::by_id(pool, &media_id)
                .await
                .expect("read media")
                .is_none(),
            "the attachment is gone"
        );
        assert!(
            hidden_until(pool, &status_id).await.is_none(),
            "with nothing left hidden the post is readable again"
        );
        let report = moderation::reports(
            pool,
            &moderation::ReportFilter {
                state: Some("resolved"),
                limit: 50,
                ..Default::default()
            },
        )
        .await
        .expect("read the queue")
        .into_iter()
        .find(|row| row.status_ids.iter().any(|id| id == &status_id))
        .expect("the report stays in the record, resolved");
        assert!(report.action_taken, "deleting counts as acting on it");
        assert!(report.action_taken_note.contains("known CSAM set"));
        let entries = audit_actions(pool, &media_id).await;
        assert!(
            entries
                .iter()
                .any(|(action, _)| action == "delete_media_quarantine"),
            "the deletion is written down: {entries:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_local_upload_is_never_quarantined() {
    run_db_test(|store, _app| async move {
        let pool = store.pool();
        let author = create_account(pool, "author-local").await;
        let status_id = create_status(pool, &author, "mine", "public", &[], &[]).await;

        // The same bytes as an exact hit on the set, uploaded by one of our own accounts.
        let sha = hex_sha("local block");
        upload_set(pool, SET_NAME, std::slice::from_ref(&sha)).await;
        let media_id = Id::new().to_string();
        let now = chrono::Utc::now();
        media::insert(
            pool,
            &MediaRow {
                id: media_id.clone(),
                account_id: author.clone(),
                status_id: Some(status_id.clone()),
                digest: format!("digest-{media_id}"),
                content_type: "image/png".to_owned(),
                size: 512,
                width: Some(64),
                height: Some(64),
                blurhash: None,
                description: String::new(),
                sensitive: false,
                lossless: false,
                processing_state: "ready".to_owned(),
                processing_progress: 100,
                processing_error: None,
                original_pruned: false,
                remote: false,
                content_hash: Some(sha),
                perceptual_hash: None,
                quarantine_state: "none".to_owned(),
                quarantine_set: None,
                remote_url: None,
                created_at: now,
            },
        )
        .await
        .expect("insert a local upload");

        assert_eq!(
            guard::screen_status(pool, &status_id, &author)
                .await
                .expect("run the check"),
            0,
            "an upload by one of our own accounts is not the check's subject"
        );
        assert_eq!(quarantined(pool, &media_id).await, "none");
        assert!(hidden_until(pool, &status_id).await.is_none());
        assert!(open_report(pool, &status_id).await.is_none());
    })
    .await;
}

#[tokio::test]
async fn the_decision_route_is_not_open_to_anonymous_callers() {
    run_db_test(|_store, app| async move {
        let (status, body) = send_anon(
            &app,
            "POST",
            "/api/v1/admin/media/0190a000-0000-7000-8000-000000000000/quarantine",
        )
        .await;
        assert_eq!(status, 401, "anonymous callers get a JSON answer: {body}");
        assert!(
            body.trim_start().starts_with('{') && body.contains("error"),
            "never an HTML shell: {body}"
        );
    })
    .await;
}

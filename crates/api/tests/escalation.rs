//! Escalation: an instance that remembers.
//!
//! A moderator decides each case by hand, so an account that breaks the same rule four times
//! used to look exactly like one that broke it once. These tests pin the five promises that
//! fix that:
//!
//! * every silence, suspension or warning leaves a strike, and the strikes inside the window
//!   are what the policy counts;
//! * a strike older than the window does not count, even though the row stays;
//! * disabling the policy stops escalation and deletes no history;
//! * a step never lifts a restriction already in force — a `silence` step reached while the
//!   account is suspended leaves the suspension alone;
//! * a policy that cannot be reasoned about is refused with the offending step named.
//!
//! The actions go through the admin endpoint the console uses, so the escalation is proven to
//! come from the real write path rather than from a helper only the tests call.

use axum::http::StatusCode;
use axum::Router;
use serde_json::{json, Value};
use sqlx::PgPool;

use nodus_server_store::accounts;
use nodus_server_store::Store;

mod support;

use support::{create_account, create_token, json_of, run_db_test, send};

const POLICY: &str = "/api/v1/admin/escalation";

/// A staff account with both admin scopes: the console's own operator.
async fn staff(pool: &PgPool, label: &str) -> String {
    let id = create_account(pool, label).await;
    accounts::set_staff_role(pool, &id, "admin")
        .await
        .expect("grant role");
    create_token(pool, &id, &["admin:read", "admin:write"]).await
}

async fn put_policy(app: &Router, token: &str, body: Value) -> (StatusCode, String) {
    send(app, token, "PUT", POLICY, Some(body)).await
}

async fn act(app: &Router, token: &str, id: &str, kind: &str) -> (StatusCode, String) {
    send(
        app,
        token,
        "POST",
        &format!("/api/v1/admin/accounts/{id}/action"),
        Some(json!({ "type": kind, "text": "" })),
    )
    .await
}

async fn detail(app: &Router, token: &str, id: &str) -> Value {
    let (status, body) = send(
        app,
        token,
        "GET",
        &format!("/api/v1/admin/accounts/{id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "account detail: {body}");
    json_of(&body)
}

async fn strikes(app: &Router, token: &str, id: &str) -> Vec<Value> {
    let (status, body) = send(
        app,
        token,
        "GET",
        &format!("/api/v1/admin/accounts/{id}/strikes"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "strikes: {body}");
    serde_json::from_str(&body).expect("strike list")
}

/// Three silences reach the third step of a three-step policy.
#[tokio::test]
async fn three_silences_escalate() {
    run_db_test(|store: Store, app: Router| async move {
        let pool = store.pool();
        let moderator = staff(pool, "esc_mod").await;
        let target = create_account(pool, "esc_target").await;

        let (status, body) = put_policy(
            &app,
            &moderator,
            json!({
                "enabled": true,
                "window_days": 90,
                "steps": [
                    { "strikes": 1, "action": "warn" },
                    { "strikes": 2, "action": "silence", "duration_days": 7 },
                    { "strikes": 3, "action": "suspend" }
                ]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "policy write: {body}");

        // The first silence is strike one: the policy's first step only warns, so the
        // account is silenced and stays silenced.
        assert_eq!(
            act(&app, &moderator, &target, "silence").await.0,
            StatusCode::OK
        );
        let row = detail(&app, &moderator, &target).await;
        assert_eq!(row["strike_count"], 1);
        assert_eq!(row["silenced"], true);
        assert_eq!(row["suspended"], false);

        // Strike two is the silence step, which the account is already under: nothing
        // changes, and the audit row says the step was reached.
        assert_eq!(
            act(&app, &moderator, &target, "silence").await.0,
            StatusCode::OK
        );
        // The third silence is strike three, and the suspension step now applies.
        assert_eq!(
            act(&app, &moderator, &target, "silence").await.0,
            StatusCode::OK
        );

        let row = detail(&app, &moderator, &target).await;
        assert_eq!(row["strike_count"], 3, "three strikes: {row}");
        assert_eq!(row["suspended"], true, "strike three suspends: {row}");

        let listed = strikes(&app, &moderator, &target).await;
        assert_eq!(listed.len(), 3);
        assert!(listed.iter().all(|strike| strike["live"] == true));
        assert!(listed.iter().all(|strike| strike["action"] == "silence"));

        // The policy and the count are named in the trail, so "why is this account
        // suspended" is answered by a row rather than by arithmetic.
        let detail_json: Option<Value> = sqlx::query_scalar(
            "SELECT detail FROM audit_log WHERE action = 'moderation_escalated' \
                 AND target_id = $1 AND detail->>'strikes' = '3'",
        )
        .bind(&target)
        .fetch_optional(pool)
        .await
        .expect("audit read");
        let detail_json = detail_json.expect("an escalation audit row");
        assert_eq!(detail_json["policy"], "default");
        assert_eq!(detail_json["applied"], true);

        // The person is told which strike brought the suspension, in the notification the
        // action already writes.
        let note: Option<String> = sqlx::query_scalar(
            "SELECT note FROM notification WHERE account_id = $1 \
                 AND moderation_action = 'suspend' ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&target)
        .fetch_optional(pool)
        .await
        .expect("notification read");
        let note = note.expect("a suspension notification");
        assert!(
            note.contains("strike 3"),
            "the note names the strike: {note}"
        );
    })
    .await;
}

/// A strike older than the window does not count, though the row stays.
#[tokio::test]
async fn expired_strike_does_not_count() {
    run_db_test(|store: Store, app: Router| async move {
        let pool = store.pool();
        let moderator = staff(pool, "exp_mod").await;
        let target = create_account(pool, "exp_target").await;

        let (status, _) = put_policy(
            &app,
            &moderator,
            json!({
                "enabled": true,
                "window_days": 30,
                "steps": [{ "strikes": 2, "action": "suspend" }]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // A strike from outside the window: written, still readable, not counted.
        sqlx::query(
            "INSERT INTO moderation_strike (id, account_id, action, reason, created_at, expires_at) \
             VALUES ('expired-strike', $1, 'silence', 'old', now() - interval '60 days', \
                 now() - interval '30 days')",
        )
        .bind(&target)
        .execute(pool)
        .await
        .expect("insert expired strike");

        assert_eq!(act(&app, &moderator, &target, "silence").await.0, StatusCode::OK);
        let row = detail(&app, &moderator, &target).await;
        assert_eq!(
            row["strike_count"], 1,
            "the expired strike is not counted: {row}"
        );
        assert_eq!(row["suspended"], false, "one live strike is below the step");
        assert_eq!(
            strikes(&app, &moderator, &target).await.len(),
            2,
            "the expired strike is still listed"
        );
    }).await;
}

/// Disabling the policy stops escalation without deleting strikes.
#[tokio::test]
async fn disabling_the_policy_keeps_the_history() {
    run_db_test(|store: Store, app: Router| async move {
        let pool = store.pool();
        let moderator = staff(pool, "off_mod").await;
        let target = create_account(pool, "off_target").await;

        let (status, _) = put_policy(
            &app,
            &moderator,
            json!({
                "enabled": false,
                "window_days": 90,
                "steps": [{ "strikes": 1, "action": "suspend" }]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        for _ in 0..3 {
            assert_eq!(
                act(&app, &moderator, &target, "silence").await.0,
                StatusCode::OK
            );
        }
        let row = detail(&app, &moderator, &target).await;
        assert_eq!(row["strike_count"], 3, "strikes are still recorded: {row}");
        assert_eq!(
            row["suspended"], false,
            "a disabled policy escalates nothing"
        );
        assert!(row["next_escalation"].is_null(), "no next step: {row}");
        assert_eq!(strikes(&app, &moderator, &target).await.len(), 3);
    })
    .await;
}

/// A step that would take less away than the account has already lost is skipped.
#[tokio::test]
async fn a_weaker_step_does_not_lift_a_suspension() {
    run_db_test(|store: Store, app: Router| async move {
        let pool = store.pool();
        let moderator = staff(pool, "weak_mod").await;
        let target = create_account(pool, "weak_target").await;

        let (status, _) = put_policy(
            &app,
            &moderator,
            json!({
                "enabled": true,
                "window_days": 90,
                "steps": [{ "strikes": 1, "action": "silence" }]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The suspension is strike one, and the policy's only step is a silence: it would
        // mean less than the suspension already in force, so it is refused.
        assert_eq!(
            act(&app, &moderator, &target, "suspend").await.0,
            StatusCode::OK
        );

        let row = detail(&app, &moderator, &target).await;
        assert_eq!(row["suspended"], true, "the suspension stands: {row}");
        assert_eq!(
            row["silenced"], false,
            "the weaker step was not applied: {row}"
        );

        let skipped: Option<bool> = sqlx::query_scalar(
            "SELECT (detail->>'applied')::boolean FROM audit_log \
             WHERE action = 'moderation_escalated' AND target_id = $1",
        )
        .bind(&target)
        .fetch_optional(pool)
        .await
        .expect("audit read");
        assert_eq!(
            skipped,
            Some(false),
            "the escalation is recorded as skipped, not silently dropped"
        );
    })
    .await;
}

/// A policy that cannot be reasoned about is refused, and the step is named.
#[tokio::test]
async fn an_invalid_policy_is_refused_with_the_step_named() {
    run_db_test(|store: Store, app: Router| async move {
        let moderator = staff(store.pool(), "bad_mod").await;

        let (status, body) = put_policy(
            &app,
            &moderator,
            json!({
                "enabled": true,
                "window_days": 90,
                "steps": [
                    { "strikes": 5, "action": "silence" },
                    { "strikes": 2, "action": "suspend" }
                ]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body.contains("step 2"),
            "the offending step is named: {body}"
        );

        // The stored policy is untouched: a refused edit is not a half-applied one.
        let (status, body) = send(&app, &moderator, "GET", POLICY, None).await;
        assert_eq!(status, StatusCode::OK);
        let policy = json_of(&body);
        assert_eq!(policy["steps"].as_array().expect("steps").len(), 2);
        assert_eq!(
            policy["steps"][0]["strikes"], 3,
            "still the defaults: {policy}"
        );

        // An unknown action is refused the same way.
        let (status, body) = put_policy(
            &app,
            &moderator,
            json!({
                "enabled": true,
                "window_days": 90,
                "steps": [
                    { "strikes": 1, "action": "silence" },
                    { "strikes": 2, "action": "exile" }
                ]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains("step 2"), "{body}");
    })
    .await;
}

/// The account payload carries the count and the next step, so a moderator reads the
/// pattern without opening the audit log.
#[tokio::test]
async fn the_account_payload_reports_the_next_step() {
    run_db_test(|store: Store, app: Router| async move {
        let pool = store.pool();
        let moderator = staff(pool, "next_mod").await;
        let target = create_account(pool, "next_target").await;

        // No policy write at all: the defaults an untouched instance runs on.
        let (status, body) = send(&app, &moderator, "GET", POLICY, None).await;
        assert_eq!(status, StatusCode::OK);
        let policy = json_of(&body);
        assert_eq!(
            policy["enabled"], true,
            "escalation is on by default: {policy}"
        );
        assert_eq!(policy["window_days"], 90);
        assert_eq!(policy["name"], "default");

        let row = detail(&app, &moderator, &target).await;
        assert_eq!(row["strike_count"], 0);
        assert_eq!(row["next_escalation"]["strikes"], 3, "{row}");
        assert_eq!(row["next_escalation"]["action"], "silence");
        assert_eq!(row["next_escalation"]["duration_days"], 7);

        // One silence: still two strikes short, so the next step is unchanged.
        assert_eq!(
            act(&app, &moderator, &target, "silence").await.0,
            StatusCode::OK
        );
        let row = detail(&app, &moderator, &target).await;
        assert_eq!(row["strike_count"], 1);
        assert_eq!(row["next_escalation"]["strikes"], 3, "{row}");

        // Two more, and the account is at the step: the next one is the suspension.
        for _ in 0..2 {
            assert_eq!(
                act(&app, &moderator, &target, "silence").await.0,
                StatusCode::OK
            );
        }
        let row = detail(&app, &moderator, &target).await;
        assert_eq!(row["strike_count"], 3, "{row}");
        assert_eq!(row["next_escalation"]["strikes"], 5, "{row}");
        assert_eq!(row["next_escalation"]["action"], "suspend");
    })
    .await;
}

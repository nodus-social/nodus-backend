//! Which role an account may learn about itself.
//!
//! The web's staff gate used to probe `/api/v2/admin/accounts` to find out whether to draw
//! the Administration door. That endpoint is `admin:read`-scoped, and the SPA's own grant is
//! `read write follow`, so it answered 403 for every account — including the bootstrap
//! administrator. The account's own document now carries the role, which is a read of the
//! subject the token names rather than a privileged probe.
//!
//! These tests pin the four corners of that shape: a staff account's own document carries
//! the role; a plain account's carries none; a public read gains Mastodon's `role` and never
//! the nodus spelling; and the admin endpoint stays admin-scoped.

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use support::{create_account, create_token, json_of, run_db_test, send, send_anon};

const VERIFY: &str = "/api/v1/accounts/verify_credentials";
const ADMIN_ACCOUNTS: &str = "/api/v2/admin/accounts";

async fn set_role(pool: &PgPool, id: &str, role: &str) {
    nodus_server_store::accounts::set_staff_role(pool, id, role)
        .await
        .expect("grant role");
}

#[tokio::test]
async fn a_read_only_token_learns_its_own_staff_role() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "staff").await;
        set_role(&pool, &account, "admin").await;
        // The SPA's grant is `read write follow`: the role is about the token's own
        // subject, so the narrowest read scope must be enough to learn it.
        let token = create_token(&pool, &account, &["read"]).await;

        let (status, body) = send(&app, &token, "GET", VERIFY, None).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let me = json_of(&body);
        assert_eq!(me["staff_role"], json!("admin"), "body was {body}");
        // Mastodon's spelling of the same fact, so a Mastodon client reads a role too.
        assert_eq!(me["role"], json!({ "name": "Admin" }), "body was {body}");
    })
    .await;
}

#[tokio::test]
async fn a_regular_account_learns_no_role() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "plain").await;
        let token = create_token(&pool, &account, &["read"]).await;

        let (status, body) = send(&app, &token, "GET", VERIFY, None).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let me = json_of(&body);
        assert_eq!(me["role"], Value::Null, "body was {body}");
        assert_eq!(
            me.get("staff_role"),
            Some(&Value::Null),
            "a non-staff account has no role to report, not \"none\": {body}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_public_account_read_keeps_its_role_shape() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let moderator = create_account(&pool, "moderator").await;
        set_role(&pool, &moderator, "moderator").await;
        let plain = create_account(&pool, "member").await;

        // Mastodon publishes `role` on every account document, so a staff account's public
        // read may say what it already says on the instance's staff page. The nodus field
        // is this account's own business and must not appear on somebody else's read.
        let (status, body) = send_anon(&app, "GET", &format!("/api/v1/accounts/{moderator}")).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let public = json_of(&body);
        assert_eq!(
            public["role"],
            json!({ "name": "Moderator" }),
            "body was {body}"
        );
        assert_eq!(
            public.get("staff_role"),
            Some(&Value::Null),
            "body was {body}"
        );

        let (status, body) = send_anon(&app, "GET", &format!("/api/v1/accounts/{plain}")).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let public = json_of(&body);
        assert_eq!(public["role"], Value::Null, "body was {body}");
        assert_eq!(
            public.get("staff_role"),
            Some(&Value::Null),
            "body was {body}"
        );
    })
    .await;
}

#[tokio::test]
async fn the_admin_probe_is_still_admin_scoped() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "probe").await;
        set_role(&pool, &account, "admin").await;
        let token = create_token(&pool, &account, &["read"]).await;

        // Not relaxed: the gate is right, and a client has no business probing it to learn
        // about staff. The account's own document is the supported way to know.
        let (status, body) = send(&app, &token, "GET", ADMIN_ACCOUNTS, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body was {body}");
        assert!(
            json_of(&body)["error"]
                .as_str()
                .unwrap_or_default()
                .contains("admin:read"),
            "body was {body}"
        );
    })
    .await;
}

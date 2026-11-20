//! The v1 filter surface, adapted onto the v2 filter rows.
//!
//! The SDK posts these forms (`phrase`, repeated `context[]`, `irreversible`,
//! `whole_word`), so the success path is exercised through the form encoder as well as
//! the JSON row it produces. The refusals — anonymous, missing scope, unknown id — are
//! named here because a 401/403/404 answered nowhere else is the bug this replaces.

use axum::http::StatusCode;

mod support;

use support::{create_account, create_token, json_of, run_db_test, send, send_anon, send_form};

#[tokio::test]
async fn a_v1_filter_is_created_read_updated_and_deleted_over_the_v2_rows() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let alice = create_account(pool, "filters_v1").await;
        let token = create_token(pool, &alice, &["read:filters", "write:filters"]).await;

        let (status, body) = send_form(
            &app,
            &token,
            "POST",
            "/api/v1/filters",
            &[
                ("phrase", "spoilers"),
                ("context[]", "home"),
                ("context[]", "public"),
                ("irreversible", "true"),
                ("whole_word", "true"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create: {body}");
        let filter = json_of(&body);
        let id = filter["id"].as_str().expect("filter id").to_owned();
        assert_eq!(filter["phrase"], "spoilers");
        assert_eq!(filter["irreversible"], true);
        assert_eq!(filter["whole_word"], true);
        let context: Vec<&str> = filter["context"]
            .as_array()
            .expect("context")
            .iter()
            .map(|value| value.as_str().unwrap_or_default())
            .collect();
        assert_eq!(context, vec!["home", "public"]);

        // The same row is visible through v2: one store, two shapes.
        let (status, body) = send(&app, &token, "GET", "/api/v2/filters", None).await;
        assert_eq!(status, StatusCode::OK, "v2 list: {body}");
        let v2 = json_of(&body);
        assert_eq!(v2[0]["id"], id);
        assert_eq!(v2[0]["title"], "spoilers");
        assert_eq!(v2[0]["filter_action"], "hide");
        assert_eq!(v2[0]["keywords"][0]["keyword"], "spoilers");

        let (status, body) = send(&app, &token, "GET", "/api/v1/filters", None).await;
        assert_eq!(status, StatusCode::OK, "list: {body}");
        assert_eq!(json_of(&body)[0]["id"], id);

        let (status, body) = send_form(
            &app,
            &token,
            "PUT",
            &format!("/api/v1/filters/{id}"),
            &[
                ("phrase", "spoilers and leaks"),
                ("context[]", "home"),
                ("irreversible", "false"),
                ("whole_word", "false"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "update: {body}");
        let filter = json_of(&body);
        assert_eq!(filter["phrase"], "spoilers and leaks");
        assert_eq!(filter["irreversible"], false);
        assert_eq!(filter["whole_word"], false);

        let (status, body) = send(
            &app,
            &token,
            "DELETE",
            &format!("/api/v1/filters/{id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "delete: {body}");

        let (status, body) = send(&app, &token, "GET", "/api/v1/filters", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json_of(&body), serde_json::json!([]));
    })
    .await;
}

#[tokio::test]
async fn v1_filters_refuse_anonymous_callers_missing_scopes_and_unknown_ids() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let alice = create_account(pool, "filters_v1_refusal").await;
        let reader = create_token(pool, &alice, &["read:filters"]).await;
        let writer = create_token(pool, &alice, &["read:filters", "write:filters"]).await;

        let (status, _) = send_anon(&app, "GET", "/api/v1/filters").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _) = send_form(
            &app,
            &reader,
            "POST",
            "/api/v1/filters",
            &[("phrase", "read only")],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = send_form(
            &app,
            &writer,
            "PUT",
            "/api/v1/filters/01unknownfilter",
            &[("phrase", "nothing")],
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = send(
            &app,
            &writer,
            "DELETE",
            "/api/v1/filters/01unknownfilter",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    })
    .await;
}

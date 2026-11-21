//! What a peer's `Like` and `EmojiReact` do, read back the way a reader sees it.

mod support;

#[path = "reactions/sign.rs"]
mod sign;

use axum::http::StatusCode;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use sqlx::PgPool;

use sign::{generate_keypair, post_signed_inbox, seed_signer, SIGNER};

fn like(status_url: &str, id: &str) -> Value {
    json!({
        "id": format!("{SIGNER}/likes/{id}"),
        "type": "Like",
        "actor": SIGNER,
        "object": status_url,
    })
}

fn emoji_react(status_url: &str, id: &str, content: &str) -> Value {
    json!({
        "id": format!("{SIGNER}/reactions/{id}"),
        "type": "EmojiReact",
        "actor": SIGNER,
        "object": status_url,
        "content": content,
    })
}

fn undo(inner: &Value, id: &str) -> Value {
    json!({
        "id": format!("{SIGNER}/undos/{id}"),
        "type": "Undo",
        "actor": SIGNER,
        "object": inner.clone(),
    })
}

/// The reactions stored on a status, as a reader would see them.
async fn stored_reactions(pool: &PgPool, status_id: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT reaction FROM status_reaction WHERE status_id = $1")
        .bind(status_id)
        .fetch_all(pool)
        .await
        .expect("read reactions")
}

async fn favourite_count(pool: &PgPool, status_id: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM favourite WHERE status_id = $1")
        .bind(status_id)
        .fetch_one(pool)
        .await
        .expect("count favourites")
}

/// A local account with one status, and a live key for the peer that will react.
async fn seed(pool: &PgPool, visibility: &str) -> (String, String, RsaPrivateKey) {
    let author = support::create_account(pool, "author").await;
    let status =
        support::create_status(pool, &author, "a post to react to", visibility, &[], &[]).await;
    let (key, pem) = generate_keypair();
    seed_signer(pool, SIGNER, &pem).await;
    let url = format!("https://social.test/statuses/{status}");
    (status, url, key)
}

#[tokio::test]
async fn a_peer_like_stores_the_favourite_glyph_reaction() {
    support::run_db_test(|store, app| async move {
        let (status, url, key) = seed(store.pool(), "public").await;
        let (code, body) = post_signed_inbox(&app, &key, &like(&url, "1")).await;
        assert_eq!(
            code,
            StatusCode::ACCEPTED,
            "a signed Like must verify: {body}"
        );

        assert_eq!(
            stored_reactions(store.pool(), &status).await,
            vec!["⭐".to_owned()],
            "a Like must be stored as the favourite glyph"
        );
        assert_eq!(
            favourite_count(store.pool(), &status).await,
            1,
            "a Like is still a favourite for the readers that count them"
        );

        let (code, body) =
            support::send_anon(&app, "GET", &format!("/api/v1/statuses/{status}")).await;
        let dto = support::json_of(&support::expect_ok(code, &body, "status"));
        assert_eq!(
            dto["favourites_count"], 1,
            "the status must report the peer like"
        );

        let (code, body) =
            support::send_anon(&app, "GET", &format!("/api/v1/statuses/{status}/reactions")).await;
        let counts = support::json_of(&support::expect_ok(code, &body, "reactions"));
        assert_eq!(counts, json!([{ "reaction": "⭐", "count": 1 }]));
    })
    .await;
}

#[tokio::test]
async fn a_duplicate_like_keeps_one_reaction_and_one_favourite() {
    support::run_db_test(|store, app| async move {
        let (status, url, key) = seed(store.pool(), "public").await;
        let activity = like(&url, "1");
        for _ in 0..2 {
            let (code, body) = post_signed_inbox(&app, &key, &activity).await;
            assert_eq!(code, StatusCode::ACCEPTED, "retry must be accepted: {body}");
        }
        assert_eq!(stored_reactions(store.pool(), &status).await.len(), 1);
        assert_eq!(favourite_count(store.pool(), &status).await, 1);
        let notices: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM notification WHERE kind = 'favourite' AND status_id = $1",
        )
        .bind(&status)
        .fetch_one(store.pool())
        .await
        .expect("count notifications");

        assert_eq!(notices, 1, "a retried Like must not notify twice");
    })
    .await;
}

#[tokio::test]
async fn undoing_a_like_removes_its_reaction_and_favourite() {
    support::run_db_test(|store, app| async move {
        let (status, url, key) = seed(store.pool(), "public").await;
        post_signed_inbox(&app, &key, &like(&url, "1")).await;
        assert_eq!(
            favourite_count(store.pool(), &status).await,
            1,
            "the like must land before its undo is tested"
        );
        let (code, body) = post_signed_inbox(&app, &key, &undo(&like(&url, "1"), "1")).await;
        assert_eq!(
            code,
            StatusCode::ACCEPTED,
            "a signed Undo must verify: {body}"
        );
        assert_eq!(
            stored_reactions(store.pool(), &status).await,
            Vec::<String>::new()
        );
        assert_eq!(favourite_count(store.pool(), &status).await, 0);
    })
    .await;
}

#[tokio::test]
async fn an_emoji_react_stores_its_content_and_replaces_a_previous_glyph() {
    support::run_db_test(|store, app| async move {
        let (status, url, key) = seed(store.pool(), "public").await;
        let (code, body) = post_signed_inbox(&app, &key, &emoji_react(&url, "1", "👍")).await;
        assert_eq!(code, StatusCode::ACCEPTED, "EmojiReact must verify: {body}");
        assert_eq!(
            stored_reactions(store.pool(), &status).await,
            vec!["👍".to_owned()]
        );
        assert_eq!(
            favourite_count(store.pool(), &status).await,
            0,
            "a custom reaction is not a favourite"
        );

        post_signed_inbox(&app, &key, &emoji_react(&url, "2", ":ferris:")).await;
        assert_eq!(
            stored_reactions(store.pool(), &status).await,
            vec![":ferris:".to_owned()],
            "one account holds one reaction, as the local reaction path does"
        );
    })
    .await;
}

#[tokio::test]
async fn undoing_an_emoji_react_removes_it() {
    support::run_db_test(|store, app| async move {
        let (status, url, key) = seed(store.pool(), "public").await;
        post_signed_inbox(&app, &key, &emoji_react(&url, "1", "👍")).await;
        assert_eq!(
            stored_reactions(store.pool(), &status).await,
            vec!["👍".to_owned()],
            "the reaction must land before its undo is tested"
        );
        let (code, body) =
            post_signed_inbox(&app, &key, &undo(&emoji_react(&url, "1", "👍"), "1")).await;
        assert_eq!(
            code,
            StatusCode::ACCEPTED,
            "Undo(EmojiReact) must verify: {body}"
        );
        assert_eq!(
            stored_reactions(store.pool(), &status).await,
            Vec::<String>::new()
        );
    })
    .await;
}

#[tokio::test]
async fn a_reaction_on_a_status_the_actor_cannot_see_is_not_stored() {
    support::run_db_test(|store, app| async move {
        let (status, url, key) = seed(store.pool(), "private").await;
        let (code, body) = post_signed_inbox(&app, &key, &emoji_react(&url, "1", "👍")).await;
        assert_eq!(
            code,
            StatusCode::ACCEPTED,
            "the delivery is acknowledged even when it is refused: {body}"
        );
        assert!(
            stored_reactions(store.pool(), &status).await.is_empty(),
            "an actor that cannot view the post cannot react to it"
        );
    })
    .await;
}

#[tokio::test]
async fn a_suspended_actor_cannot_react() {
    support::run_db_test(|store, app| async move {
        let (status, url, key) = seed(store.pool(), "public").await;
        nodus_server_store::remote_moderation::upsert(
            store.pool(),
            &nodus_server_store::remote_moderation::NewRemoteModeration {
                actor_uri: SIGNER,
                action: nodus_server_store::remote_moderation::SUSPEND,
                reason: Some("test"),
                expires_at: None,
                created_by: None,
            },
        )
        .await
        .expect("suspend actor");
        post_signed_inbox(&app, &key, &emoji_react(&url, "1", "👍")).await;
        assert!(
            stored_reactions(store.pool(), &status).await.is_empty(),
            "a suspended account's activity is acknowledged and dropped"
        );
    })
    .await;
}

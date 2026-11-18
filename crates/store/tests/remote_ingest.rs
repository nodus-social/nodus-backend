use chrono::Utc;
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount, RemoteAccount};
use nodus_server_store::blocks;
use nodus_server_store::delivery;
use nodus_server_store::media::{self, RemoteAttachment};
use nodus_server_store::statuses::{self, NewRemoteStatus, NewStatus};
use sqlx::PgPool;

async fn seed_account(pool: &PgPool, username: &str) -> String {
    accounts::insert(
        pool,
        &NewAccount {
            username,
            display_name: username,
            note: "",
            bot: false,
            locked: false,
        },
    )
    .await
    .expect("insert account")
    .id
}

async fn seed_remote(pool: &PgPool, uri: &str) -> String {
    accounts::upsert_remote(
        pool,
        &RemoteAccount {
            uri,
            username: uri.rsplit('/').next().unwrap_or("remote"),
            domain: "remote.test",
            display_name: "Remote",
            note: "",
            avatar_url: None,
            header_url: None,
            inbox_url: None,
            shared_inbox_url: None,
            public_key_pem: None,
            locked: false,
            bot: false,
        },
    )
    .await
    .expect("upsert remote account")
    .id
}

async fn ingest(pool: &PgPool, account_id: &str, uri: &str) -> statuses::StatusRow {
    let id = Id::new().to_string();
    statuses::upsert_remote(
        pool,
        &NewRemoteStatus {
            id: &id,
            account_id,
            uri,
            content: "before",
            content_html: "<p>before</p>",
            spoiler_text: "",
            sensitive: false,
            visibility: "public",
            in_reply_to_id: None,
            in_reply_to_account_id: None,
            created_at: Utc::now(),
        },
    )
    .await
    .expect("insert remote status")
}

fn local_status<'a>(id: &'a str, account_id: &'a str, content: &'a str) -> NewStatus<'a> {
    NewStatus {
        id,
        account_id,
        content,
        content_html: content,
        content_source: Some(content),
        content_format: "html",
        spoiler_text: "",
        visibility: "public",
        sensitive: false,
        in_reply_to_id: None,
        in_reply_to_account_id: None,
        reblog_of_id: None,
        language: None,
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn mentions_and_tags_are_replaced_rather_than_duplicated(pool: PgPool) {
    let alice = seed_account(&pool, "alice").await;
    let eve = seed_remote(&pool, "https://remote.test/users/eve").await;
    let row = ingest(&pool, &eve, "https://remote.test/notes/1").await;

    statuses::replace_mentions(&pool, &row.id, &[alice.clone(), eve.clone()])
        .await
        .expect("store mentions");
    statuses::replace_tags(&pool, &row.id, &["rust".to_owned(), "fedi".to_owned()])
        .await
        .expect("store tags");

    let mut mentions = statuses::mentions_of(&pool, &row.id)
        .await
        .expect("read mentions");
    mentions.sort();
    let mut expected = vec![alice.clone(), eve.clone()];
    expected.sort();
    assert_eq!(mentions, expected);
    assert_eq!(
        statuses::tags_of(&pool, &row.id).await.expect("read tags"),
        vec!["fedi".to_owned(), "rust".to_owned()]
    );

    statuses::replace_mentions(&pool, &row.id, std::slice::from_ref(&alice))
        .await
        .expect("replace mentions");
    assert_eq!(
        statuses::mentions_of(&pool, &row.id)
            .await
            .expect("read mentions"),
        vec![alice]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn an_edit_refreshes_a_remote_note_and_stamps_edited_at(pool: PgPool) {
    let eve = seed_remote(&pool, "https://remote.test/users/eve").await;
    let row = ingest(&pool, &eve, "https://remote.test/notes/1").await;
    assert!(row.edited_at.is_none());

    let updated = statuses::update_remote_content(
        &pool,
        "https://remote.test/notes/1",
        &eve,
        "after",
        "<p>after</p>",
        "cw",
        true,
    )
    .await
    .expect("update")
    .expect("known note");

    assert_eq!(updated.content, "after");
    assert_eq!(updated.content_html, "<p>after</p>");
    assert_eq!(updated.spoiler_text, "cw");
    assert!(updated.sensitive);
    assert!(updated.edited_at.is_some());
    assert_eq!(
        updated.visibility, "public",
        "an edit must not re-address it"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_local_row_cannot_be_edited_or_deleted_through_the_remote_paths(pool: PgPool) {
    let alice = seed_account(&pool, "alice").await;
    let id = Id::new().to_string();
    statuses::create(&pool, &local_status(&id, &alice, "mine"), &[], &[], &[])
        .await
        .expect("create local status");
    let uri = "https://social.test/users/alice/statuses/1";
    sqlx::query("UPDATE status SET uri = $1 WHERE id = $2")
        .bind(uri)
        .bind(&id)
        .execute(&pool)
        .await
        .expect("give the local row a URI");

    assert!(
        statuses::update_remote_content(&pool, uri, &alice, "x", "x", "", false)
            .await
            .expect("update")
            .is_none()
    );
    assert!(!statuses::delete_remote(&pool, uri, &alice)
        .await
        .expect("delete"));
    let still_there: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT deleted_at FROM status WHERE id = $1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("read deleted_at");
    assert!(still_there.is_none());

    let actor_uri = "https://social.test/users/alice";
    sqlx::query("UPDATE account SET uri = $1 WHERE id = $2")
        .bind(actor_uri)
        .bind(&alice)
        .execute(&pool)
        .await
        .expect("give the local account a URI");
    assert!(
        accounts::update_remote_profile(&pool, actor_uri, &accounts::RemoteProfile::default())
            .await
            .expect("update profile")
            .is_none(),
        "a local profile must not be reachable through the remote path"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn deleting_a_remote_actor_soft_deletes_every_note_it_posted(pool: PgPool) {
    let eve = seed_remote(&pool, "https://remote.test/users/eve").await;
    let mallory = seed_remote(&pool, "https://remote.test/users/mallory").await;
    let first = ingest(&pool, &eve, "https://remote.test/notes/1").await;
    let second = ingest(&pool, &eve, "https://remote.test/notes/2").await;
    let other = ingest(&pool, &mallory, "https://remote.test/notes/3").await;

    assert_eq!(
        statuses::delete_remote_actor(&pool, &eve)
            .await
            .expect("delete actor"),
        2
    );
    assert!(statuses::by_id(&pool, &first.id)
        .await
        .expect("lookup")
        .is_none());
    assert!(statuses::by_id(&pool, &second.id)
        .await
        .expect("lookup")
        .is_none());
    assert!(statuses::by_id(&pool, &other.id)
        .await
        .expect("lookup")
        .is_some());
    assert!(accounts::by_id(&pool, &eve)
        .await
        .expect("lookup")
        .is_some());
    assert_eq!(
        statuses::delete_remote_actor(&pool, &eve)
            .await
            .expect("second delete"),
        0,
        "deleting twice must not fail or count the same rows again"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn remote_attachments_are_recorded_as_urls(pool: PgPool) {
    let eve = seed_remote(&pool, "https://remote.test/users/eve").await;
    let row = ingest(&pool, &eve, "https://remote.test/notes/1").await;

    media::replace_remote(
        &pool,
        &row.id,
        &eve,
        true,
        &[RemoteAttachment {
            url: "https://remote.test/media/1.png",
            content_type: "image/jpeg",
            description: "a picture",
            width: Some(640),
            height: Some(480),
        }],
    )
    .await
    .expect("store attachment");

    let stored = media::by_status(&pool, &row.id)
        .await
        .expect("read attachments");
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].remote_url.as_deref(),
        Some("https://remote.test/media/1.png")
    );
    assert_eq!(stored[0].content_type, "image/jpeg");
    assert_eq!(stored[0].description, "a picture");
    assert!(stored[0].sensitive);
    assert_eq!(stored[0].processing_state, "ready");
    assert_eq!(stored[0].size, 0);

    media::replace_remote(&pool, &row.id, &eve, true, &[])
        .await
        .expect("clear attachments");
    assert!(media::by_status(&pool, &row.id)
        .await
        .expect("read attachments")
        .is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn a_block_stops_queueing_deliveries_to_that_host(pool: PgPool) {
    let alice = seed_account(&pool, "alice").await;
    blocks::record_remote_block(&pool, "https://blocked.test/users/a")
        .await
        .expect("record block");
    blocks::record_remote_block(&pool, "https://blocked.test/users/a")
        .await
        .expect("recording the same block twice is harmless");

    assert_eq!(
        blocks::blocked_hosts(&pool).await.expect("blocked hosts"),
        vec!["blocked.test".to_owned()]
    );

    let activity = serde_json::json!({
        "id": "https://social.test/users/alice/statuses/1/activity",
        "type": "Create",
        "actor": "https://social.test/users/alice",
        "object": { "id": "https://social.test/users/alice/statuses/1" },
    });
    let inboxes = vec![
        "https://blocked.test/users/a/inbox".to_owned(),
        "https://open.test/inbox".to_owned(),
    ];
    assert_eq!(
        delivery::enqueue(&pool, &alice, &activity, &inboxes)
            .await
            .expect("enqueue"),
        1
    );
    let pending = delivery::pending(&pool, 10).await.expect("pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].inbox_url, "https://open.test/inbox");

    let blocked_only = vec!["https://blocked.test/users/a/inbox".to_owned()];
    assert_eq!(
        delivery::enqueue(&pool, &alice, &activity, &blocked_only)
            .await
            .expect("enqueue"),
        0
    );
}

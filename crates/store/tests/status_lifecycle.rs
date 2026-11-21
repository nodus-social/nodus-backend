use chrono::Utc;
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount, RemoteAccount};
use nodus_server_store::social;
use nodus_server_store::statuses::{self, NewRemoteStatus, NewStatus};
use nodus_server_store::Store;
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

fn make_new_status<'a>(
    id: &'a str,
    account_id: &'a str,
    content: &'a str,
    in_reply_to_id: Option<&'a str>,
    in_reply_to_account_id: Option<&'a str>,
    reblog_of_id: Option<&'a str>,
) -> NewStatus<'a> {
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
        in_reply_to_id,
        in_reply_to_account_id,
        reblog_of_id,
        language: None,
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn replies_count_is_maintained_across_create_insert_upsert_and_delete(pool: PgPool) {
    let alice = seed_account(&pool, "alice").await;
    let bob = seed_account(&pool, "bob").await;

    let parent_id = Id::new().to_string();
    statuses::create(
        &pool,
        &make_new_status(&parent_id, &alice, "root", None, None, None),
        &[],
        &[],
        &[],
    )
    .await
    .expect("create root");

    // 1. statuses::create reply increments replies_count
    let reply1_id = Id::new().to_string();
    statuses::create(
        &pool,
        &make_new_status(
            &reply1_id,
            &bob,
            "reply 1",
            Some(&parent_id),
            Some(&alice),
            None,
        ),
        &[],
        &[],
        &[],
    )
    .await
    .expect("create reply 1");

    let parent = statuses::by_id(&pool, &parent_id).await.unwrap().unwrap();
    assert_eq!(parent.replies_count, 1);

    // 2. statuses::insert reply increments replies_count
    let reply2_id = Id::new().to_string();
    statuses::insert(
        &pool,
        &make_new_status(
            &reply2_id,
            &bob,
            "reply 2",
            Some(&parent_id),
            Some(&alice),
            None,
        ),
    )
    .await
    .expect("insert reply 2");

    let parent = statuses::by_id(&pool, &parent_id).await.unwrap().unwrap();
    assert_eq!(parent.replies_count, 2);

    // 3. statuses::upsert_remote increments once and does not double-count on conflict update
    let remote = accounts::upsert_remote(
        &pool,
        &RemoteAccount {
            uri: "https://remote.test/users/carol",
            username: "carol",
            domain: "remote.test",
            display_name: "Carol",
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
    .expect("upsert remote account");

    let remote_reply_id = Id::new().to_string();
    let remote_reply = NewRemoteStatus {
        id: &remote_reply_id,
        account_id: &remote.id,
        uri: "https://remote.test/notes/1",
        content: "remote reply",
        content_html: "<p>remote reply</p>",
        spoiler_text: "",
        sensitive: false,
        visibility: "public",
        in_reply_to_id: Some(&parent_id),
        in_reply_to_account_id: Some(&alice),
        created_at: Utc::now(),
    };
    statuses::upsert_remote(&pool, &remote_reply)
        .await
        .expect("upsert remote reply");
    statuses::upsert_remote(&pool, &remote_reply)
        .await
        .expect("re-upsert remote reply");

    let parent = statuses::by_id(&pool, &parent_id).await.unwrap().unwrap();
    assert_eq!(parent.replies_count, 3);

    // 4. delete_owned decrements replies_count
    assert!(statuses::delete_owned(&pool, &reply1_id, &bob)
        .await
        .expect("delete reply 1"));
    let parent = statuses::by_id(&pool, &parent_id).await.unwrap().unwrap();
    assert_eq!(parent.replies_count, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_owned_cleans_timeline_entries_and_all_counters(pool: PgPool) {
    let alice = seed_account(&pool, "alice").await;
    let bob = seed_account(&pool, "bob").await;
    social::follow(&pool, &bob, &alice, true, false)
        .await
        .expect("bob follows alice");

    let root_id = Id::new().to_string();
    statuses::create(
        &pool,
        &make_new_status(&root_id, &alice, "hello", None, None, None),
        &[],
        &[],
        &[],
    )
    .await
    .expect("create root");

    let reply_id = Id::new().to_string();
    statuses::create(
        &pool,
        &make_new_status(
            &reply_id,
            &bob,
            "nice post",
            Some(&root_id),
            Some(&alice),
            None,
        ),
        &[],
        &[],
        &[],
    )
    .await
    .expect("create reply");

    let reblog = statuses::reblog(&pool, &bob, &root_id)
        .await
        .expect("reblog")
        .expect("reblog created");

    let timeline_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM timeline_entry WHERE status_id = $1")
            .bind(&reply_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(timeline_count >= 1);

    // Delete Bob's reply -> timeline_entry removed, Bob's statuses_count = 0, root's replies_count = 0
    assert!(statuses::delete_owned(&pool, &reply_id, &bob)
        .await
        .expect("delete reply"));

    let remaining_entries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM timeline_entry WHERE status_id = $1")
            .bind(&reply_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining_entries, 0);

    let bob_row = Store::from_pool(pool.clone())
        .account(&bob)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bob_row.statuses_count, 0);

    let root_row = statuses::by_id(&pool, &root_id).await.unwrap().unwrap();
    assert_eq!(root_row.replies_count, 0);
    assert_eq!(root_row.reblogs_count, 1);

    // Delete Bob's reblog via delete_owned -> timeline_entry removed, root's reblogs_count = 0
    assert!(statuses::delete_owned(&pool, &reblog.id, &bob)
        .await
        .expect("delete reblog"));
    let reblog_entries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM timeline_entry WHERE status_id = $1")
            .bind(&reblog.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reblog_entries, 0);

    let root_row = statuses::by_id(&pool, &root_id).await.unwrap().unwrap();
    assert_eq!(root_row.reblogs_count, 0);

    let bob_row = Store::from_pool(pool.clone())
        .account(&bob)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bob_row.statuses_count, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn reblog_prevents_duplicate_active_boosts_for_same_account(pool: PgPool) {
    let alice = seed_account(&pool, "alice").await;
    let bob = seed_account(&pool, "bob").await;

    let status_id = Id::new().to_string();
    statuses::create(
        &pool,
        &make_new_status(&status_id, &alice, "boostable", None, None, None),
        &[],
        &[],
        &[],
    )
    .await
    .expect("create status");

    let first = statuses::reblog(&pool, &bob, &status_id)
        .await
        .expect("first reblog")
        .expect("reblog row");
    let second = statuses::reblog(&pool, &bob, &status_id)
        .await
        .expect("second reblog")
        .expect("existing reblog row");

    assert_eq!(first.id, second.id);

    let active_reblogs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM status WHERE reblog_of_id = $1 AND account_id = $2 AND deleted_at IS NULL",
    )
    .bind(&status_id)
    .bind(&bob)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active_reblogs, 1);

    let original = statuses::by_id(&pool, &status_id).await.unwrap().unwrap();
    assert_eq!(original.reblogs_count, 1);

    // After deleting the boost, boosting again creates a fresh reblog and keeps count at 1.
    assert!(statuses::delete_owned(&pool, &first.id, &bob)
        .await
        .expect("delete boost"));
    let original = statuses::by_id(&pool, &status_id).await.unwrap().unwrap();
    assert_eq!(original.reblogs_count, 0);

    let third = statuses::reblog(&pool, &bob, &status_id)
        .await
        .expect("reblog after delete")
        .expect("new reblog row");
    assert_ne!(third.id, first.id);

    let original = statuses::by_id(&pool, &status_id).await.unwrap().unwrap();
    assert_eq!(original.reblogs_count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn context_excludes_deleted_immediate_parent(pool: PgPool) {
    let alice = seed_account(&pool, "alice").await;

    let grandparent_id = Id::new().to_string();
    statuses::create(
        &pool,
        &make_new_status(&grandparent_id, &alice, "grandparent", None, None, None),
        &[],
        &[],
        &[],
    )
    .await
    .expect("create grandparent");

    let parent_id = Id::new().to_string();
    statuses::create(
        &pool,
        &make_new_status(
            &parent_id,
            &alice,
            "parent",
            Some(&grandparent_id),
            Some(&alice),
            None,
        ),
        &[],
        &[],
        &[],
    )
    .await
    .expect("create parent");

    let child_id = Id::new().to_string();
    statuses::create(
        &pool,
        &make_new_status(
            &child_id,
            &alice,
            "child",
            Some(&parent_id),
            Some(&alice),
            None,
        ),
        &[],
        &[],
        &[],
    )
    .await
    .expect("create child");

    assert!(statuses::delete_owned(&pool, &parent_id, &alice)
        .await
        .expect("delete parent"));

    let (ancestors, descendants) = statuses::context(&pool, &child_id).await.expect("context");
    assert!(
        ancestors.is_empty(),
        "deleted immediate parent must not appear in ancestors: {ancestors:?}"
    );
    assert!(descendants.is_empty());
}

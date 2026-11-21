//! The batched read seam, against a live database. Four properties carry this module and are what these tests prove: results are keyed by the id asked for (a missing row is absent, not padded), the batched shape answers exactly what the per-row calls it replaces answer, the essential ops share one snapshot, and an optional op may fail without taking the page down. Each test takes a schema of its own, the same isolation every other database suite here uses.

use nodus_server_core::Id;
use nodus_server_store::accounts;
use nodus_server_store::media;
use nodus_server_store::social;
use nodus_server_store::statuses;
use nodus_server_store::Store;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

async fn setup() -> Option<(Store, PgPool, String)> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect to postgres");

    // Lower case, because `search_path` folds unquoted identifiers: a name with capitals would land in `public` instead.
    let schema = format!("pgtest_hydrate_{}", Id::new()).to_lowercase();
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&admin)
        .await
        .expect("create the test schema");
    let separator = if url.contains('?') { '&' } else { '?' };
    let schema_url = format!("{url}{separator}options=-csearch_path%3D{schema}%2Cpublic");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&schema_url)
        .await
        .expect("connect the isolated pool");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    let store = Store::connect(&schema_url, 4)
        .await
        .expect("connect the store");
    Some((store, pool, schema))
}

async fn cleanup(pool: &PgPool, schema: &str) {
    sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(pool)
        .await
        .expect("drop the test schema");
}

/// Seeds through raw SQL: the hydration ops only read accounts by id, so the fixture needs the required columns (id, username) and nothing else.
async fn account(pool: &PgPool, username: &str) -> String {
    let id = Id::new().to_string();
    sqlx::query("INSERT INTO account (id, username) VALUES ($1, $2)")
        .bind(&id)
        .bind(username)
        .execute(pool)
        .await
        .expect("seed account");
    id
}

/// The hydration ops only read a status by id, so the fixture needs the required columns and nothing else; going through `statuses::insert` would derive columns no assertion here touches.
async fn status(pool: &PgPool, author: &str, content: &str) -> String {
    let id = Id::new().to_string();
    sqlx::query("INSERT INTO status (id, account_id, content, content_html, visibility) VALUES ($1, $2, $3, $3, 'public')")
    .bind(&id)
    .bind(author)
    .bind(content)
    .execute(pool)
    .await
    .expect("seed status");
    id
}

/// Same reasoning as `status`: the reader only needs the attachment row, so seed the required columns (the rest default like `media::insert` leaves them).
async fn attachment(pool: &PgPool, author: &str, status_id: &str) {
    sqlx::query("INSERT INTO media_attachment (id, account_id, status_id, digest, content_type, size) VALUES ($1, $2, $3, $4, 'image/png', 128)")
    .bind(Id::new().to_string())
    .bind(author)
    .bind(status_id)
    .bind(Id::new().to_string())
    .execute(pool)
    .await
    .expect("seed attachment");
}

/// A requested account or status with no row is absent, not padded (a relationship is keyed for every target, as the scalar call answers). A page of three essential ops still reads one snapshot.
#[tokio::test]
async fn maps_are_keyed_by_input_and_the_page_reads_one_snapshot() {
    let Some((store, pool, schema)) = setup().await else {
        return;
    };
    let alice = account(&pool, "alice").await;
    let bob = account(&pool, "bob").await;
    let with_media = status(&pool, &alice, "with media").await;
    let without_media = status(&pool, &alice, "without media").await;
    attachment(&pool, &alice, &with_media).await;

    let accounts = vec![alice.clone(), "no-such-account".to_owned()];
    let statuses = vec![
        with_media.clone(),
        without_media.clone(),
        "no-such-id".to_owned(),
    ];
    let outcome = store
        .batch()
        .accounts(&accounts)
        .media_by_status(&statuses)
        .relationships(&alice, &[bob.clone(), "no-such-account".to_owned()])
        .run()
        .await
        .expect("run the batch");

    assert_eq!(outcome.accounts.len(), 1, "a missing id adds no row");
    assert!(outcome.accounts.contains_key(&alice));
    assert_eq!(
        outcome.media_by_status.get(&with_media).map(Vec::len),
        Some(1)
    );
    assert_eq!(outcome.media_by_status.len(), 1, "an empty group is absent");
    assert!(!outcome.media_by_status.contains_key(&without_media));
    assert_eq!(
        outcome.relationships.len(),
        2,
        "every requested target gets a relationship"
    );
    assert!(outcome.relationships.contains_key(&bob));
    assert_eq!(
        outcome.snapshots_opened, 1,
        "a page comes from one point in time"
    );

    cleanup(&pool, &schema).await;
}

/// The batched shape answers exactly what the per-row calls it replaces answer.
#[tokio::test]
async fn a_mixed_batch_matches_the_per_row_calls() {
    let Some((store, pool, schema)) = setup().await else {
        return;
    };
    let alice = account(&pool, "alice").await;
    let bob = account(&pool, "bob").await;
    // Both directions plus a mute and a block set every flag the relationship query builds.
    social::follow(&pool, &alice, &bob, false, true)
        .await
        .expect("follow");
    social::follow(&pool, &bob, &alice, true, false)
        .await
        .expect("follow back");
    social::mute(&pool, &alice, &bob, false)
        .await
        .expect("mute");
    social::block(&pool, &alice, &bob).await.expect("block");

    let post = status(&pool, &bob, "post").await;
    attachment(&pool, &bob, &post).await;
    statuses::set_reaction(&pool, &post, &alice, "⭐")
        .await
        .expect("react");
    statuses::set_reaction(&pool, &post, &bob, "⭐")
        .await
        .expect("react");
    statuses::set_reaction(&pool, &post, &bob, "👍")
        .await
        .expect("react");

    let accounts = vec![alice.clone(), bob.clone()];
    let ids = vec![post.clone()];
    let outcome = store
        .batch()
        .accounts(&accounts)
        .media_by_status(&ids)
        .reactions(&ids)
        .relationships(&alice, &accounts)
        .run()
        .await
        .expect("run the batch");

    for id in &accounts {
        let per_row = accounts::by_id(&pool, id)
            .await
            .expect("per-row")
            .expect("exists");
        assert_eq!(
            format!("{:?}", outcome.accounts.get(id)),
            format!("{:?}", Some(per_row)),
            "account {id} differs"
        );
    }
    let per_row = media::by_status(&pool, &post).await.expect("per-row media");
    let batched = format!("{:?}", outcome.media_by_status.get(&post));
    assert_eq!(
        batched,
        format!("{:?}", Some(&per_row)),
        "attachments differ"
    );
    let per_row = statuses::reactions(&pool, &post)
        .await
        .expect("per-row reactions");
    let batched = format!("{:?}", outcome.reactions.expect("reactions op").get(&post));
    assert_eq!(batched, format!("{:?}", Some(&per_row)), "reactions differ");
    let per_row = social::relationship(&pool, &alice, &bob)
        .await
        .expect("per-row relationship");
    let batched = format!("{:?}", outcome.relationships.get(&bob));
    assert_eq!(
        batched,
        format!("{:?}", Some(&per_row)),
        "relationship differs"
    );

    cleanup(&pool, &schema).await;
}

/// A failing optional op is reported in its slot, and the essential page survives.
#[tokio::test]
async fn an_optional_op_failure_leaves_the_essential_results_intact() {
    let Some((store, pool, schema)) = setup().await else {
        return;
    };
    let alice = account(&pool, "alice").await;
    // A deterministic error for the optional op: its table is gone, the account table is not.
    sqlx::query("DROP TABLE status_reaction CASCADE")
        .execute(&pool)
        .await
        .expect("drop table");

    let outcome = store
        .batch()
        .accounts(std::slice::from_ref(&alice))
        .reactions(std::slice::from_ref(&alice))
        .run()
        .await
        .expect("an optional failure must not fail the page");

    assert!(outcome.accounts.contains_key(&alice));
    let error = outcome.reactions.expect_err("the reaction op failed");
    assert_eq!(
        error.code(),
        Some("42P01"),
        "the failure is reported, not hidden"
    );

    cleanup(&pool, &schema).await;
}

use nodus_server_core::limits::{CLIENT_METADATA_MAX_BYTES, CLIENT_METADATA_MAX_KEYS};
use nodus_server_store::accounts::{self, ClientMetadataStoreError, NewAccount};
use serde_json::{json, Map, Value};
use sqlx::PgPool;

async fn create_account(pool: &PgPool, username: &str) -> String {
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

#[sqlx::test(migrations = "./migrations")]
async fn client_metadata_defaults_to_empty_and_supports_fine_grained_crud(pool: PgPool) {
    let alice = create_account(&pool, "alice").await;
    let bob = create_account(&pool, "bob").await;

    let initial = accounts::client_metadata_all(&pool, &alice)
        .await
        .expect("query initial metadata")
        .expect("account exists");
    assert!(initial.is_empty());

    // Patch multiple keys including nested nulls that must be preserved inside values.
    let mut patch = Map::new();
    patch.insert(
        "nodus-top-banner".to_owned(),
        json!({
            "segments": [
                { "media_id": "01j1", "url": "https://cdn.test/1.png", "caption": null },
                { "media_id": "01j2", "url": "https://cdn.test/2.png" }
            ],
            "split": "horizontal"
        }),
    );
    patch.insert(
        "nodus-nav-layout".to_owned(),
        json!({
            "left": ["home", "notifications"],
            "right": ["bookmarks"],
            "submenu": ["lists", "filters"]
        }),
    );
    patch.insert("thirdparty.theme".to_owned(), json!("solarized-dark"));

    let updated = accounts::client_metadata_patch(&pool, &alice, &patch)
        .await
        .expect("patch metadata");
    assert_eq!(updated.len(), 3);
    assert_eq!(
        updated["nodus-top-banner"]["segments"][0]["caption"],
        Value::Null
    );

    // Bob remains isolated.
    let bob_meta = accounts::client_metadata_all(&pool, &bob)
        .await
        .expect("query bob metadata")
        .expect("bob exists");
    assert!(bob_meta.is_empty());

    // Fetch single key and subset of keys.
    let banner = accounts::client_metadata_get_key(&pool, &alice, "nodus-top-banner")
        .await
        .expect("get key")
        .expect("key exists");
    assert_eq!(banner["split"], "horizontal");
    assert!(
        accounts::client_metadata_get_key(&pool, &alice, "nodus-left-image")
            .await
            .expect("get missing key")
            .is_none()
    );

    let subset = accounts::client_metadata_get_keys(
        &pool,
        &alice,
        &[
            "nodus-nav-layout".to_owned(),
            "missing-key".to_owned(),
            "thirdparty.theme".to_owned(),
        ],
    )
    .await
    .expect("get subset")
    .expect("account exists");
    assert_eq!(subset.len(), 2);
    assert_eq!(subset["thirdparty.theme"], "solarized-dark");
    assert!(!subset.contains_key("nodus-top-banner"));

    // Patch with null deletes only that top-level key.
    let mut delete_patch = Map::new();
    delete_patch.insert("thirdparty.theme".to_owned(), Value::Null);
    let after_null = accounts::client_metadata_patch(&pool, &alice, &delete_patch)
        .await
        .expect("null patch");
    assert_eq!(after_null.len(), 2);
    assert!(!after_null.contains_key("thirdparty.theme"));
    assert!(after_null.contains_key("nodus-top-banner"));

    // Set single key.
    let after_set = accounts::client_metadata_set_key(
        &pool,
        &alice,
        "nodus-left-image",
        json!({ "url": "https://cdn.test/left.png" }),
    )
    .await
    .expect("set single key");
    assert_eq!(after_set.len(), 3);

    // Delete specific keys.
    let after_delete = accounts::client_metadata_delete_keys(
        &pool,
        &alice,
        &["nodus-left-image".to_owned(), "nonexistent".to_owned()],
    )
    .await
    .expect("delete keys");
    assert_eq!(after_delete.len(), 2);
    assert!(!after_delete.contains_key("nodus-left-image"));

    // Replace replaces entire object and omits top-level nulls.
    let mut replacement = Map::new();
    replacement.insert(
        "nodus-right-image".to_owned(),
        json!("https://cdn.test/r.png"),
    );
    replacement.insert("ignored-null".to_owned(), Value::Null);
    let replaced = accounts::client_metadata_replace(&pool, &alice, &replacement)
        .await
        .expect("replace");
    assert_eq!(replaced.len(), 1);
    assert_eq!(replaced["nodus-right-image"], "https://cdn.test/r.png");

    // Clear removes all keys.
    accounts::client_metadata_clear(&pool, &alice)
        .await
        .expect("clear");
    let after_clear = accounts::client_metadata_all(&pool, &alice)
        .await
        .expect("read after clear")
        .expect("account exists");
    assert!(after_clear.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn client_metadata_enforces_limits_and_concurrent_updates_do_not_clobber(pool: PgPool) {
    let alice = create_account(&pool, "alice").await;

    // Concurrent single-key writes must preserve every key.
    let mut handles = Vec::new();
    for i in 0..8 {
        let pool_clone = pool.clone();
        let account_id = alice.clone();
        handles.push(tokio::spawn(async move {
            accounts::client_metadata_set_key(
                &pool_clone,
                &account_id,
                &format!("concurrent-key-{i}"),
                json!(i),
            )
            .await
            .expect("concurrent set_key")
        }));
    }
    for handle in handles {
        handle.await.expect("join");
    }
    let stored = accounts::client_metadata_all(&pool, &alice)
        .await
        .expect("read all")
        .expect("account exists");
    assert_eq!(stored.len(), 8);

    // Clear and test key count limit.
    accounts::client_metadata_clear(&pool, &alice)
        .await
        .expect("clear");

    let mut too_many = Map::new();
    for i in 0..=CLIENT_METADATA_MAX_KEYS {
        too_many.insert(format!("k-{i}"), json!(true));
    }
    let err = accounts::client_metadata_patch(&pool, &alice, &too_many)
        .await
        .expect_err("should reject exceeding max keys");
    assert!(matches!(err, ClientMetadataStoreError::Validation(_)));

    // Test payload byte limit.
    let big_string = "x".repeat(CLIENT_METADATA_MAX_BYTES);
    let err = accounts::client_metadata_set_key(&pool, &alice, "big", json!(big_string))
        .await
        .expect_err("should reject exceeding max bytes");
    assert!(matches!(err, ClientMetadataStoreError::Validation(_)));
}

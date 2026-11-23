//! The personal domain-block table: one row per pair, gone with its account.

use nodus_server_store::account_blocks::{self, BlockOptions};
use nodus_server_store::accounts::{self, NewAccount};

async fn local_account(pool: &sqlx::PgPool, label: &str) -> String {
    accounts::insert(
        pool,
        &NewAccount {
            username: &format!("blocktest_{label}"),
            display_name: label,
            note: "",
            bot: false,
            locked: false,
        },
    )
    .await
    .expect("account")
    .id
}

#[sqlx::test(migrations = "./migrations")]
async fn a_personal_block_is_unique_per_account_and_cascades(pool: sqlx::PgPool) {
    let account = local_account(&pool, "owner").await;
    let other = local_account(&pool, "other").await;

    account_blocks::add(
        &pool,
        &account,
        "Blocked.Test",
        BlockOptions {
            reject_media: true,
            reject_reports: false,
        },
    )
    .await
    .expect("first add");
    // The same host in another case is the same row, updated rather than duplicated.
    account_blocks::add(
        &pool,
        &account,
        "blocked.test.",
        BlockOptions {
            reject_media: false,
            reject_reports: true,
        },
    )
    .await
    .expect("second add");

    let rows = account_blocks::list(&pool, &account).await.expect("list");
    assert_eq!(rows.len(), 1, "one row per (account, host): {rows:?}");
    assert_eq!(rows[0].host, "blocked.test");
    assert!(rows[0].reject_reports);
    assert!(!rows[0].reject_media);
    assert!(account_blocks::blocks(&pool, &account, "blocked.test")
        .await
        .expect("exists"));
    assert!(!account_blocks::blocks(&pool, &other, "blocked.test")
        .await
        .expect("other account"));

    // Another account's identical block is its own row, and removing one leaves the
    // other alone.
    account_blocks::add(&pool, &other, "blocked.test", BlockOptions::default())
        .await
        .expect("other add");
    assert!(account_blocks::remove(&pool, &account, "blocked.test")
        .await
        .expect("remove"));
    assert_eq!(
        account_blocks::list(&pool, &account).await.unwrap().len(),
        0
    );
    assert_eq!(account_blocks::list(&pool, &other).await.unwrap().len(), 1);

    // Deleting the account takes its blocks with it.
    sqlx::query("DELETE FROM account WHERE id = $1")
        .bind(&other)
        .execute(&pool)
        .await
        .expect("delete account");
    assert_eq!(account_blocks::list(&pool, &other).await.unwrap().len(), 0);
}

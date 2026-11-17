use nodus_server_store::accounts::{self, NewAccount, RemoteAccount};
use nodus_server_store::moderation::{self, Action};
use nodus_server_store::social;
use sqlx::PgPool;

async fn seed_local_and_remote_accounts(pool: &PgPool) -> (String, String) {
    let local = accounts::insert(
        pool,
        &NewAccount {
            username: "Alice",
            display_name: "Alice",
            note: "local user",
            bot: false,
            locked: false,
        },
    )
    .await
    .expect("insert local account");

    sqlx::query(
        "INSERT INTO account_credential (account_id, email, password_hash) VALUES ($1, $2, $3)",
    )
    .bind(&local.id)
    .bind("Alice@Example.Test")
    .bind("hash")
    .execute(pool)
    .await
    .expect("insert local account credential");

    let remote = accounts::upsert_remote(
        pool,
        &RemoteAccount {
            uri: "https://remote.example/users/bob",
            username: "Bob",
            domain: "Remote.Example",
            display_name: "Bob",
            note: "remote user",
            avatar_url: None,
            header_url: None,
            inbox_url: Some("https://remote.example/users/bob/inbox"),
            shared_inbox_url: None,
            public_key_pem: None,
            locked: false,
            bot: false,
        },
    )
    .await
    .expect("upsert remote account");

    (local.id, remote.id)
}

#[sqlx::test(migrations = "./migrations")]
async fn admin_accounts_decodes_citext_username_domain_and_email(pool: PgPool) {
    let (local_id, remote_id) = seed_local_and_remote_accounts(&pool).await;

    let all = moderation::admin_accounts(&pool, false, false, 20)
        .await
        .expect("admin_accounts should decode citext columns");

    assert_eq!(all.len(), 2);
    let local = all.iter().find(|row| row.account.id == local_id).unwrap();
    assert_eq!(local.account.username, "Alice");
    assert_eq!(local.account.domain, None);
    assert_eq!(local.email.as_deref(), Some("Alice@Example.Test"));

    let remote = all.iter().find(|row| row.account.id == remote_id).unwrap();
    assert_eq!(remote.account.username, "Bob");
    assert_eq!(remote.account.domain.as_deref(), Some("Remote.Example"));
    assert_eq!(remote.email, None);

    moderation::apply_action(&pool, &local_id, Action::Reject)
        .await
        .expect("reject local account")
        .expect("local account exists");

    let pending = moderation::admin_accounts(&pool, true, true, 20)
        .await
        .expect("admin_accounts(local=true, pending=true) should decode citext columns");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].account.id, local_id);
    assert_eq!(pending[0].account.username, "Alice");
}

#[sqlx::test(migrations = "./migrations")]
async fn apply_action_decodes_citext_username_and_domain(pool: PgPool) {
    let (local_id, remote_id) = seed_local_and_remote_accounts(&pool).await;

    let rejected = moderation::apply_action(&pool, &local_id, Action::Reject)
        .await
        .expect("reject should decode AccountRow")
        .expect("account exists");
    assert_eq!(rejected.username, "Alice");
    assert!(!rejected.approved);

    let approved = moderation::apply_action(&pool, &local_id, Action::Approve)
        .await
        .expect("approve should decode AccountRow")
        .expect("account exists");
    assert!(approved.approved);

    let silenced = moderation::apply_action(&pool, &remote_id, Action::Silence)
        .await
        .expect("silence should decode AccountRow")
        .expect("account exists");
    assert_eq!(silenced.username, "Bob");
    assert_eq!(silenced.domain.as_deref(), Some("Remote.Example"));
    assert!(silenced.silenced_at.is_some());

    let suspended = moderation::apply_action(&pool, &remote_id, Action::Suspend)
        .await
        .expect("suspend should decode AccountRow")
        .expect("account exists");
    assert!(suspended.suspended_at.is_some());

    let enabled = moderation::apply_action(&pool, &remote_id, Action::Enable)
        .await
        .expect("enable should decode AccountRow")
        .expect("account exists");
    assert!(enabled.approved);
    assert!(enabled.silenced_at.is_none());
    assert!(enabled.suspended_at.is_none());

    let missing = moderation::apply_action(&pool, "nonexistent-account-id", Action::Suspend)
        .await
        .expect("missing account query should succeed");
    assert!(missing.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn relations_decodes_citext_username_and_domain_for_blocks_and_mutes(pool: PgPool) {
    let (local_id, remote_id) = seed_local_and_remote_accounts(&pool).await;

    let other_local = accounts::insert(
        &pool,
        &NewAccount {
            username: "Carol",
            display_name: "Carol",
            note: "other local",
            bot: false,
            locked: false,
        },
    )
    .await
    .expect("insert second local account");

    social::block(&pool, &local_id, &remote_id)
        .await
        .expect("block remote account");
    social::mute(&pool, &local_id, &other_local.id, true)
        .await
        .expect("mute local account");

    let blocked = social::relations(&pool, &local_id, "block")
        .await
        .expect("relations(block) should decode AccountRow");
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].id, remote_id);
    assert_eq!(blocked[0].username, "Bob");
    assert_eq!(blocked[0].domain.as_deref(), Some("Remote.Example"));

    let muted = social::relations(&pool, &local_id, "mute")
        .await
        .expect("relations(mute) should decode AccountRow");
    assert_eq!(muted.len(), 1);
    assert_eq!(muted[0].id, other_local.id);
    assert_eq!(muted[0].username, "Carol");
    assert_eq!(muted[0].domain, None);
}

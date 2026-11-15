use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::social::{self, FollowOutcome};
use sqlx::PgPool;

async fn create_account(pool: &PgPool, username: &str, locked: bool) -> String {
    accounts::insert(
        pool,
        &NewAccount {
            username,
            display_name: username,
            note: "",
            bot: false,
            locked,
        },
    )
    .await
    .expect("insert account")
    .id
}

async fn assert_counts_match_follow_table(pool: &PgPool, account_id: &str) {
    let account = accounts::by_id(pool, account_id)
        .await
        .expect("fetch account")
        .expect("account exists");
    let actual_followers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM follow WHERE target_account_id = $1 AND state = 'accepted'",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .expect("count followers");
    let actual_following: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM follow WHERE account_id = $1 AND state = 'accepted'",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .expect("count following");

    assert_eq!(
        account.followers_count, actual_followers,
        "followers_count drifted for {account_id}"
    );
    assert_eq!(
        account.following_count, actual_following,
        "following_count drifted for {account_id}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn block_deletes_pending_follow_requests_in_both_directions(pool: PgPool) {
    let alice = create_account(&pool, "alice", true).await;
    let bob = create_account(&pool, "bob", true).await;
    let carol = create_account(&pool, "carol", false).await;

    // Pending requests in both directions between alice and bob.
    assert_eq!(
        social::follow(&pool, &bob, &alice, true, false)
            .await
            .expect("bob follow request to alice"),
        FollowOutcome::Requested
    );
    assert_eq!(
        social::follow(&pool, &alice, &bob, true, false)
            .await
            .expect("alice follow request to bob"),
        FollowOutcome::Requested
    );

    // Carol has an accepted follow to alice that must remain untouched.
    assert_eq!(
        social::follow(&pool, &carol, &alice, true, false)
            .await
            .expect("carol follow request to alice"),
        FollowOutcome::Requested
    );
    assert!(
        social::accept_follow(&pool, &alice, &carol)
            .await
            .expect("alice accepts carol")
    );

    social::block(&pool, &alice, &bob)
        .await
        .expect("alice blocks bob");

    let bob_to_alice = social::relationship(&pool, &bob, &alice)
        .await
        .expect("relationship bob -> alice");
    assert!(!bob_to_alice.requested);
    assert!(!bob_to_alice.following);

    let alice_to_bob = social::relationship(&pool, &alice, &bob)
        .await
        .expect("relationship alice -> bob");
    assert!(alice_to_bob.blocked);
    assert!(!alice_to_bob.requested);
    assert!(!alice_to_bob.following);

    // Neither pending request may survive to be accepted later.
    assert!(
        !social::accept_follow(&pool, &alice, &bob)
            .await
            .expect("accept_follow alice <- bob")
    );
    assert!(
        !social::accept_follow(&pool, &bob, &alice)
            .await
            .expect("accept_follow bob <- alice")
    );

    assert_counts_match_follow_table(&pool, &alice).await;
    assert_counts_match_follow_table(&pool, &bob).await;
    assert_counts_match_follow_table(&pool, &carol).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn block_recomputes_follow_counts_on_accepted_and_mixed_follows(pool: PgPool) {
    let alice = create_account(&pool, "alice", true).await;
    let bob = create_account(&pool, "bob", false).await;
    let carol = create_account(&pool, "carol", false).await;

    // bob -> alice (pending -> accepted)
    social::follow(&pool, &bob, &alice, true, false)
        .await
        .expect("bob requests alice");
    assert!(social::accept_follow(&pool, &alice, &bob).await.unwrap());

    // carol -> alice (pending -> accepted)
    social::follow(&pool, &carol, &alice, true, false)
        .await
        .expect("carol requests alice");
    assert!(social::accept_follow(&pool, &alice, &carol).await.unwrap());

    // alice -> bob (accepted)
    assert_eq!(
        social::follow(&pool, &alice, &bob, true, false)
            .await
            .expect("alice follows bob"),
        FollowOutcome::Following
    );

    // Simulate pre-existing counter drift on alice/bob; block must recompute via count(*).
    sqlx::query("UPDATE account SET followers_count = 99, following_count = 99 WHERE id = ANY($1)")
        .bind(&[alice.clone(), bob.clone()][..])
        .execute(&pool)
        .await
        .expect("seed counter drift");

    social::block(&pool, &alice, &bob)
        .await
        .expect("alice blocks bob");

    let alice_row = accounts::by_id(&pool, &alice).await.unwrap().unwrap();
    let bob_row = accounts::by_id(&pool, &bob).await.unwrap().unwrap();
    assert_eq!(alice_row.followers_count, 1);
    assert_eq!(alice_row.following_count, 0);
    assert_eq!(bob_row.followers_count, 0);
    assert_eq!(bob_row.following_count, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_follows_unfollows_accepts_and_blocks_keep_counters_in_sync(pool: PgPool) {
    let target = create_account(&pool, "target", false).await;
    let locked_target = create_account(&pool, "locked_target", true).await;

    let mut followers = Vec::new();
    for i in 0..16 {
        followers.push(create_account(&pool, &format!("follower_{i}"), false).await);
    }

    // 1. Concurrent follows into the same target account must not lose counter updates.
    let mut handles = Vec::new();
    for follower in &followers {
        let pool = pool.clone();
        let follower = follower.clone();
        let target = target.clone();
        handles.push(tokio::spawn(async move {
            social::follow(&pool, &follower, &target, true, false)
                .await
                .expect("concurrent follow");
        }));
    }
    for handle in handles {
        handle.await.expect("join follow task");
    }
    assert_counts_match_follow_table(&pool, &target).await;
    let target_row = accounts::by_id(&pool, &target).await.unwrap().unwrap();
    assert_eq!(target_row.followers_count, 16);

    // 2. Mix concurrent unfollows, new pending->accepted follows, and blocks on the same accounts.
    for follower in &followers[..8] {
        assert_eq!(
            social::follow(&pool, follower, &locked_target, true, false)
                .await
                .expect("pending follow"),
            FollowOutcome::Requested
        );
    }

    let mut mixed = Vec::new();
    for (idx, follower) in followers.iter().enumerate() {
        let pool = pool.clone();
        let follower = follower.clone();
        let target = target.clone();
        let locked_target = locked_target.clone();
        mixed.push(tokio::spawn(async move {
            if idx % 3 == 0 {
                social::block(&pool, &target, &follower)
                    .await
                    .expect("concurrent block");
            } else if idx % 2 == 0 {
                social::unfollow(&pool, &follower, &target)
                    .await
                    .expect("concurrent unfollow");
            }
            if idx < 8 {
                let _ = social::accept_follow(&pool, &locked_target, &follower)
                    .await
                    .expect("concurrent accept_follow");
                if idx % 4 == 0 {
                    social::block(&pool, &locked_target, &follower)
                        .await
                        .expect("concurrent block on locked_target");
                }
            }
        }));
    }
    for handle in mixed {
        handle.await.expect("join mixed task");
    }

    assert_counts_match_follow_table(&pool, &target).await;
    assert_counts_match_follow_table(&pool, &locked_target).await;
    for follower in &followers {
        assert_counts_match_follow_table(&pool, follower).await;
    }
}

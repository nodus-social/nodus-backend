//! IP blocks: matching happens at the stored truncation, and expiry is a read filter.

use nodus_server_store::ip_block;

#[sqlx::test(migrations = "./migrations")]
async fn an_expiring_block_stops_matching_when_it_lapses(pool: sqlx::PgPool) {
    let ip = ip_block::normalize("203.0.113.7").expect("address");
    assert_eq!(ip, "203.0.113.0/24");
    ip_block::insert(&pool, &ip, ip_block::NO_ACCESS, "abuse", Some(1))
        .await
        .expect("insert");

    assert!(ip_block::no_access(&pool, "203.0.113.0/24")
        .await
        .expect("before expiry"));
    assert_eq!(
        ip_block::verdict(&pool, "203.0.113.0/24")
            .await
            .expect("verdict"),
        Some(ip_block::NO_ACCESS.to_owned())
    );
    assert_eq!(ip_block::list(&pool).await.expect("list").len(), 1);

    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;

    assert!(!ip_block::no_access(&pool, "203.0.113.0/24")
        .await
        .expect("after expiry"));
    assert_eq!(
        ip_block::verdict(&pool, "203.0.113.0/24")
            .await
            .expect("verdict"),
        None
    );
    assert!(ip_block::list(&pool).await.expect("list").is_empty());
    // Expiry filters; it does not delete. The row is the record of what was done.
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM ip_block")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_wider_block_covers_a_session_prefix_and_strongest_wins(pool: sqlx::PgPool) {
    let wide = ip_block::normalize("203.0.0.0/16").expect("cidr");
    ip_block::insert(&pool, &wide, ip_block::SIGN_UP_REQUIRES_APPROVAL, "", None)
        .await
        .expect("insert wide");
    let narrow = ip_block::normalize("203.0.113.9").expect("host");
    ip_block::insert(&pool, &narrow, ip_block::NO_ACCESS, "", None)
        .await
        .expect("insert narrow");

    assert_eq!(
        ip_block::verdict(&pool, "203.0.113.0/24")
            .await
            .expect("verdict"),
        Some(ip_block::NO_ACCESS.to_owned())
    );
    // A neighbouring /24 is covered by the /16 but not by the /24 block.
    assert_eq!(
        ip_block::verdict(&pool, "203.0.114.0/24")
            .await
            .expect("verdict"),
        Some(ip_block::SIGN_UP_REQUIRES_APPROVAL.to_owned())
    );
    assert!(!ip_block::no_access(&pool, "203.0.114.0/24")
        .await
        .expect("neighbour"));
}

#[sqlx::test(migrations = "./migrations")]
async fn the_same_network_cannot_be_blocked_twice(pool: sqlx::PgPool) {
    let ip = ip_block::normalize("198.51.100.4").expect("address");
    ip_block::insert(&pool, &ip, ip_block::SIGN_UP_BLOCK, "", None)
        .await
        .expect("first");
    assert!(ip_block::insert(&pool, &ip, ip_block::NO_ACCESS, "", None)
        .await
        .is_err());
}


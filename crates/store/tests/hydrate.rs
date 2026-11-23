//! The batched read seam, against a live database. Four properties carry this module: results are keyed by the id asked for (a missing row is absent, not padded), the batched shape returns the same values the per-row calls return, the essentials run in one transaction Postgres itself reports as `repeatable read`/`read only`, and an optional op runs after that transaction commits, so its failure cannot take the page down.

#[path = "hydrate/support.rs"]
mod support;

use nodus_server_store::hydrate::{
    MentionRow, PictureSize, ProfilePictures, StatusDecorations, TransactionSettings,
};
use nodus_server_store::media;
use nodus_server_store::social::{self, Relationship};
use nodus_server_store::statuses::{self, ReactionCount, StatusEmoji};
use nodus_server_store::Store;
use support::{account, attachment, cleanup, execute, setup, shorten_statement_timeout, status};

/// A requested account or status with no row is absent, not padded; a relationship is keyed for every target, exactly as the scalar call answers. The transaction is asked, from inside it, what isolation it runs under.
#[tokio::test]
async fn reads_one_repeatable_read_transaction_and_keys_by_input() {
    let Some((store, pool, schema)) = setup().await else {
        return;
    };
    let alice = account(&pool, "alice").await;
    let bob = account(&pool, "bob").await;
    let with_media = status(&pool, &alice, "with media").await;
    let without_media = status(&pool, &alice, "without media").await;
    attachment(&pool, &alice, &with_media).await;

    let outcome = store
        .batch()
        .accounts(&[alice.clone(), "no-such-account".to_owned()])
        .media_by_status(&[
            with_media.clone(),
            without_media.clone(),
            "no-such-id".to_owned(),
        ])
        .relationships(&alice, &[bob.clone(), "no-such-account".to_owned()])
        .transaction_settings()
        .run()
        .await
        .expect("run the batch");

    assert_eq!(outcome.accounts.len(), 1, "a missing id adds no row");
    assert!(outcome.accounts.contains_key(&alice));
    assert_eq!(
        outcome.media_by_status.get(&with_media).map(Vec::len),
        Some(1)
    );
    assert!(!outcome.media_by_status.contains_key(&without_media));
    assert_eq!(outcome.relationships.len(), 2, "every target is keyed");
    let unflagged = Some(&Relationship::default());
    for target in [&bob, &"no-such-account".to_owned()] {
        assert_eq!(outcome.relationships.get(target), unflagged, "never absent");
    }
    assert_eq!(
        outcome.transaction_settings,
        Some(TransactionSettings {
            isolation: "repeatable read".to_owned(),
            read_only: "on".to_owned(),
        }),
        "Postgres, not the seam's bookkeeping, says which transaction this page ran in"
    );

    cleanup(&pool, &schema).await;
}

/// The batched shape answers exactly what the per-row calls it replaces answer, compared as values rather than as formatted strings. Both follow directions plus a mute and a block set every flag the relationship query builds.
#[tokio::test]
async fn a_mixed_batch_matches_the_per_row_calls() {
    let Some((store, pool, schema)) = setup().await else {
        return;
    };
    let alice = account(&pool, "alice").await;
    let bob = account(&pool, "bob").await;
    social::follow(&pool, &alice, &bob, true, true)
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
    statuses::set_reaction(&pool, &post, &bob, "👍")
        .await
        .expect("react");

    let targets = vec![alice.clone(), bob.clone()];
    let ids = vec![post.clone()];
    let outcome = store
        .batch()
        .accounts(&targets)
        .media_by_status(&ids)
        .reactions(&ids)
        .relationships(&alice, &targets)
        .run()
        .await
        .expect("run the batch");

    for id in &targets {
        let per_row = Store::from_pool(pool.clone())
            .account(id)
            .await
            .expect("per-row");
        assert_eq!(outcome.accounts.get(id), per_row.as_ref(), "account {id}");
    }
    let per_row = media::by_status(&pool, &post).await.expect("per-row media");
    assert_eq!(outcome.media_by_status.get(&post), Some(&per_row));
    let per_row = statuses::reactions(&pool, &post)
        .await
        .expect("per-row reactions");
    let reactions = outcome.reactions.expect("reactions op");
    assert_eq!(reactions.get(&post), Some(&per_row));
    let per_row = social::relationship(&pool, &alice, &bob)
        .await
        .expect("per-row relationship");
    assert_eq!(
        outcome.relationships.get(&bob),
        Some(&per_row),
        "follow, reblogs, notify, mute, block and followed-by all agree"
    );

    cleanup(&pool, &schema).await;
}

/// A decorated status comes back with the rows that were inserted, and a bare one is absent rather than an empty entry.
#[tokio::test]
async fn decorations_carry_the_values_that_were_inserted() {
    let Some((store, pool, schema)) = setup().await else {
        return;
    };
    let alice = account(&pool, "alice").await;
    let bob = account(&pool, "bob").await;
    let decorated = status(&pool, &alice, "decorated").await;
    let bare = status(&pool, &alice, "bare").await;
    execute(
        &pool,
        "INSERT INTO status_tag (status_id, tag) VALUES ($1, 'rust')",
        &[&decorated],
    )
    .await;
    execute(
        &pool,
        "INSERT INTO status_emoji (status_id, shortcode, url, position) VALUES ($1, 'blob', 'https://cdn.example/blob.png', 0)",
        &[&decorated],
    )
    .await;
    execute(
        &pool,
        "INSERT INTO status_mention (status_id, account_id) VALUES ($1, $2)",
        &[&decorated, &bob],
    )
    .await;

    let outcome = store
        .batch()
        .decorations(&[decorated.clone(), bare.clone()])
        .run()
        .await
        .expect("run the batch");

    assert_eq!(
        outcome.decorations.get(&decorated),
        Some(&StatusDecorations {
            tags: vec!["rust".to_owned()],
            emojis: vec![StatusEmoji {
                shortcode: "blob".to_owned(),
                url: "https://cdn.example/blob.png".to_owned(),
            }],
            mentions: vec![MentionRow {
                id: bob.clone(),
                username: "bob".to_owned(),
                domain: None,
            }],
        }),
        "exactly the tag, emoji and mention that were inserted"
    );
    assert_eq!(
        outcome.decorations.get(&bare),
        None,
        "a bare status is absent, not padded with empty vectors"
    );

    cleanup(&pool, &schema).await;
}

/// The optional op runs after the essential transaction has committed: the essentials come back while the reactions table is still locked, and only the reactions slot fails. Were the ordering reversed — reactions first, or inside the essential transaction — the cancelled statement would abort that transaction and `run` would return `Err` with no page at all.
#[tokio::test]
async fn optional_ops_run_after_the_essential_transaction_commits() {
    let Some((store, pool, schema)) = setup().await else {
        return;
    };
    let alice = account(&pool, "alice").await;
    let post = status(&pool, &alice, "post").await;
    statuses::set_reaction(&pool, &post, &alice, "⭐")
        .await
        .expect("react");
    shorten_statement_timeout(store.pool()).await;

    // A separate connection holds the reactions table; the batch's own connections are short on statement_timeout, so its reaction query is cancelled rather than left waiting.
    let mut locker = pool.acquire().await.expect("hold the locker");
    execute(&mut *locker, "BEGIN", &[]).await;
    execute(
        &mut *locker,
        "LOCK TABLE status_reaction IN ACCESS EXCLUSIVE MODE",
        &[],
    )
    .await;

    let outcome = store
        .batch()
        .accounts(std::slice::from_ref(&alice))
        .reactions(std::slice::from_ref(&post))
        .run()
        .await
        .expect("the essentials still commit");
    // Both assertions run while the lock is held: the page's authors are readable, so the essential transaction committed before the blocked statement was attempted.
    assert!(outcome.accounts.contains_key(&alice), "the page survived");
    let error = outcome.reactions.expect_err("the locked query failed");
    assert_eq!(
        error.code(),
        Some("57014"),
        "cancelled, not silently skipped"
    );

    execute(&mut *locker, "COMMIT", &[]).await;
    let outcome = store
        .batch()
        .accounts(std::slice::from_ref(&alice))
        .reactions(std::slice::from_ref(&post))
        .run()
        .await
        .expect("re-run after the release");
    assert_eq!(
        outcome.reactions.expect("reactions after the release"),
        [(
            post.clone(),
            vec![ReactionCount {
                reaction: "⭐".to_owned(),
                count: 1,
            }],
        )]
        .into_iter()
        .collect(),
        "the same op answers once the table is free"
    );

    cleanup(&pool, &schema).await;
}

/// A profile picture's shape comes from the variant row its reference names: the highest
/// edge wins, a bare reference means its slot's layer, and a picture with no variant — a
/// remote account, a missing render — is absent rather than a square placeholder.
#[tokio::test]
async fn profile_pictures_read_the_named_layer_and_leave_unrendered_pictures_absent() {
    let Some((store, pool, schema)) = setup().await else {
        return;
    };
    let alice = account(&pool, "alice").await;
    let remote = account(&pool, "remote").await;
    let unrendered = account(&pool, "unrendered").await;
    execute(
        &pool,
        "INSERT INTO media_attachment (id, account_id, digest, content_type, size) \
         VALUES ('avatar-media', $1, 'avatar-digest', 'image/png', 1), \
                ('header-media', $1, 'header-digest', 'image/png', 1)",
        &[&alice],
    )
    .await;
    execute(
        &pool,
        "UPDATE account SET avatar_ref = 'avatar-media/avatar', header_ref = 'header-media' \
         WHERE id = $1",
        &[&alice],
    )
    .await;
    execute(
        &pool,
        "UPDATE account SET avatar_url = 'https://remote.example/avatar.png' WHERE id = $1",
        &[&remote],
    )
    .await;
    execute(
        &pool,
        "UPDATE account SET avatar_ref = 'gone-media/avatar' WHERE id = $1",
        &[&unrendered],
    )
    .await;
    for (media_id, layer, max_edge, width, height) in [
        ("avatar-media", "avatar", 100, 100, 100),
        ("avatar-media", "avatar", 400, 400, 300),
        ("avatar-media", "preview", 800, 800, 600),
        ("header-media", "header", 1500, 1500, 500),
    ] {
        media::upsert_variant(
            &pool,
            &media::VariantRow {
                media_id: media_id.to_owned(),
                layer: layer.to_owned(),
                max_edge,
                object_key: format!("media/{media_id}/{layer}"),
                content_type: "image/webp".to_owned(),
                digest: format!("{media_id}-{max_edge}"),
                size: 1,
                width: Some(width),
                height: Some(height),
                expires_at: None,
                created_at: chrono::Utc::now(),
            },
        )
        .await
        .expect("insert variant");
    }

    let outcome = store
        .batch()
        .profile_pictures(&[
            alice.clone(),
            remote.clone(),
            unrendered.clone(),
            "no-such-account".to_owned(),
        ])
        .run()
        .await
        .expect("run the batch");

    assert_eq!(
        outcome.profile_pictures.get(&alice),
        Some(&ProfilePictures {
            avatar: Some(PictureSize {
                width: 400,
                height: 300,
            }),
            header: Some(PictureSize {
                width: 1500,
                height: 500,
            }),
        }),
        "the named avatar layer's highest edge, and the bare header reference's header layer"
    );
    assert_eq!(
        outcome.profile_pictures.get(&remote),
        None,
        "remote picture"
    );
    assert_eq!(
        outcome.profile_pictures.get(&unrendered),
        None,
        "a reference with no variant row is absent, not 1x1"
    );
    assert!(!outcome.profile_pictures.contains_key("no-such-account"));

    cleanup(&pool, &schema).await;
}

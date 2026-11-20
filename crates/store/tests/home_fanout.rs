//! The home fan-out: which followers a status is materialised into, and in what order.
//!
//! Both sides of the same transaction are pinned here: `statuses::fan_out_home` writes
//! `timeline_entry`, and `statuses::home_fanout_accounts` is the keyset query the cache
//! push (`api::home::fan_out`) and the cache eviction (`api::home::hide`) page through.
//! A bug on either side is silent: a missed follower sees no new post, a duplicated one
//! gets two cache writes, and neither shows up as an error anywhere.

use nodus_server_core::limits::BIG_ACCOUNT_THRESHOLD;
use nodus_server_core::{Id, PageParams};
use nodus_server_store::accounts::{self, NewAccount, RemoteAccount};
use nodus_server_store::social;
use nodus_server_store::statuses::{self, NewStatus};
use sqlx::PgPool;

/// `PIPELINE_BATCH` in `crates/api/src/home.rs:67`, the page size the fan-out loop asks
/// `home_fanout_accounts` for. The store crate cannot import the API crate (the API
/// depends on the store), so the number is repeated here on purpose: if the two ever
/// drift, this test's page-boundary case is the one that notices.
const PIPELINE_BATCH: i64 = 500;

async fn seed_local(pool: &PgPool, username: &str) -> String {
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

/// An accepted follow, through the real write path so `followers_count` is maintained.
async fn follow(pool: &PgPool, follower: &str, target: &str) {
    social::follow(pool, follower, target, true, false)
        .await
        .expect("follow");
}

/// Publishes a status and returns its id, fan-out included.
async fn publish(pool: &PgPool, account_id: &str, visibility: &str, mentions: &[String]) -> String {
    let id = Id::new().to_string();
    statuses::create(
        pool,
        &NewStatus {
            id: &id,
            account_id,
            content: "post",
            content_html: "<p>post</p>",
            content_source: Some("post"),
            content_format: "html",
            spoiler_text: "",
            visibility,
            sensitive: false,
            in_reply_to_id: None,
            in_reply_to_account_id: None,
            reblog_of_id: None,
            language: None,
        },
        &[],
        mentions,
        &[],
    )
    .await
    .expect("create status");
    id
}

/// The accounts `timeline_entry` holds for one status, sorted.
async fn entry_accounts(pool: &PgPool, status_id: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT account_id FROM timeline_entry \
          WHERE status_id = $1 AND kind = 'home' ORDER BY account_id",
    )
    .bind(status_id)
    .fetch_all(pool)
    .await
    .expect("read timeline_entry")
}

/// The home page ids for `account_id`, in the order the endpoint promises: newest first.
async fn home_page_ids(pool: &PgPool, account_id: &str) -> Vec<String> {
    statuses::home_page(pool, account_id, PageParams::default())
        .await
        .expect("home page")
        .items
        .into_iter()
        .map(|row| row.id)
        .collect()
}

/// The batches `api::home::fan_out` would push, and how many queries it took.
///
/// Mirrors the loop in `crates/api/src/home.rs:788-812`: stop on an empty batch *without*
/// pushing it, stop after a short batch, otherwise keep the last id as the cursor. The
/// query count therefore includes the one trailing empty page a page-sized result forces.
async fn follower_batches(pool: &PgPool, author: &str) -> (Vec<Vec<String>>, usize) {
    let mut batches = Vec::new();
    let mut queries = 0;
    let mut after: Option<String> = None;
    loop {
        let batch = statuses::home_fanout_accounts(
            pool,
            author,
            after.as_deref(),
            PIPELINE_BATCH,
            Some(BIG_ACCOUNT_THRESHOLD),
        )
        .await
        .expect("list followers");
        queries += 1;
        if batch.is_empty() {
            break;
        }
        let complete = i64::try_from(batch.len()).unwrap_or(i64::MAX) < PIPELINE_BATCH;
        after = batch.last().cloned();
        batches.push(batch);
        if complete {
            break;
        }
    }
    (batches, queries)
}

#[sqlx::test(migrations = "./migrations")]
async fn fanout_lists_followers_in_ascending_account_id_order_and_delivers_both_authors(
    pool: PgPool,
) {
    let alice = seed_local(&pool, "alice").await;
    let bob = seed_local(&pool, "bob").await;
    let reader = seed_local(&pool, "reader").await;
    let zoe = seed_local(&pool, "zoe").await;
    follow(&pool, &reader, &alice).await;
    follow(&pool, &zoe, &alice).await;
    follow(&pool, &reader, &bob).await;

    let alice_first = publish(&pool, &alice, "public", &[]).await;
    let alice_second = publish(&pool, &alice, "public", &[]).await;
    let bob_only = publish(&pool, &bob, "public", &[]).await;

    // The query promises `ORDER BY f.account_id ASC` (statuses.rs:547). Say it in the
    // assertion, not just in this comment: the caller uses the last id as its keyset
    // cursor, so an unordered batch would silently skip or repeat followers.
    let mut expected = vec![reader.clone(), zoe.clone()];
    expected.sort();
    let (batches, _) = follower_batches(&pool, &alice).await;
    assert_eq!(batches.len(), 1, "two followers fit in one page");
    assert_eq!(batches[0], expected, "ascending account id, both followers");

    // Reader follows both authors, so both authors' public statuses are on the page.
    let mut want = vec![alice_first, alice_second, bob_only];
    want.sort();
    want.reverse();
    assert_eq!(
        home_page_ids(&pool, &reader).await,
        want,
        "every public status of both authors, newest id first"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn no_followers_yields_no_batch_and_a_reader_following_nobody_sees_nothing(pool: PgPool) {
    let loner = seed_local(&pool, "loner").await;
    let reader = seed_local(&pool, "reader").await;

    let status_id = publish(&pool, &loner, "public", &[]).await;

    // Author with no followers: only the author's own row exists, and the batcher gets
    // an empty page — the caller returns before pushing anything, so no empty-group
    // command is ever emitted.
    assert_eq!(entry_accounts(&pool, &status_id).await, vec![loner.clone()]);
    let (batches, _) = follower_batches(&pool, &loner).await;
    assert!(
        batches.is_empty(),
        "an author with no followers must not produce a command, got {batches:?}"
    );

    // Follower of nobody: the post exists, but this account was never a target.
    assert!(
        home_page_ids(&pool, &reader).await.is_empty(),
        "an account that follows nobody has an empty home timeline"
    );
    assert!(entry_accounts(&pool, &status_id)
        .await
        .iter()
        .all(|account| account != &reader));
}

#[sqlx::test(migrations = "./migrations")]
async fn private_reaches_accepted_followers_while_direct_reaches_no_timeline_entry(pool: PgPool) {
    let author = seed_local(&pool, "author").await;
    let fan = seed_local(&pool, "fan").await;
    let outsider = seed_local(&pool, "outsider").await;
    follow(&pool, &fan, &author).await;

    let private_id = publish(&pool, &author, "private", &[]).await;
    let mut expected = vec![author.clone(), fan.clone()];
    expected.sort();
    assert_eq!(
        entry_accounts(&pool, &private_id).await,
        expected,
        "followers-only means exactly the accepted followers plus the author"
    );
    assert!(
        !entry_accounts(&pool, &private_id).await.contains(&outsider),
        "private must not reach a non-follower"
    );
    assert_eq!(
        home_page_ids(&pool, &fan).await,
        vec![private_id.clone()],
        "the follower's home timeline carries the private status"
    );
    assert!(home_page_ids(&pool, &outsider).await.is_empty());

    // Direct: the follower is also the mention, and still must not get a home row.
    // `home_page` excludes direct outright (statuses.rs:461-462, 475) and the mention is
    // delivered by the notification path; a timeline row would be one no reader may see.
    let direct_id = publish(&pool, &author, "direct", std::slice::from_ref(&fan)).await;
    assert!(
        entry_accounts(&pool, &direct_id).await.is_empty(),
        "a direct status gets no timeline_entry at all, not even for the mentioned follower"
    );
    let mentioned: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM status_mention WHERE status_id = $1 AND account_id = $2)",
    )
    .bind(&direct_id)
    .bind(&fan)
    .fetch_one(&pool)
    .await
    .expect("read status_mention");
    assert!(mentioned, "the mention is what carries the direct status");
    assert!(
        !home_page_ids(&pool, &fan).await.contains(&direct_id),
        "direct never appears in a home timeline"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_remote_follower_is_included_even_though_it_has_no_home_timeline(pool: PgPool) {
    let author = seed_local(&pool, "author").await;
    let remote = seed_remote(&pool, "https://remote.test/users/rhea").await;
    follow(&pool, &remote, &author).await;

    // Neither query filters on `account.local` (statuses.rs:539-553 and :921-933), so a
    // remote follower is both listed and materialised. That is dead weight — no remote
    // account ever reads `/timelines/home` here — but it is not a privacy leak, and this
    // test records today's behaviour so excluding remote followers later is a deliberate
    // decision with a failing test to update, not an accident.
    let (batches, _) = follower_batches(&pool, &author).await;
    assert_eq!(batches, vec![vec![remote.clone()]]);

    let status_id = publish(&pool, &author, "public", &[]).await;
    let mut expected = vec![author, remote];
    expected.sort();
    assert_eq!(entry_accounts(&pool, &status_id).await, expected);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_re_follow_yields_one_command_and_one_timeline_row(pool: PgPool) {
    let author = seed_local(&pool, "author").await;
    let reader = seed_local(&pool, "reader").await;

    follow(&pool, &reader, &author).await;
    follow(&pool, &reader, &author).await;
    social::unfollow(&pool, &reader, &author)
        .await
        .expect("unfollow");
    follow(&pool, &reader, &author).await;

    let follow_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM follow WHERE target_account_id = $1")
            .bind(&author)
            .fetch_one(&pool)
            .await
            .expect("count follows");
    assert_eq!(follow_rows, 1, "the pair index holds one follow row");

    let (batches, _) = follower_batches(&pool, &author).await;
    assert_eq!(
        batches,
        vec![vec![reader.clone()]],
        "one follower, one command"
    );

    let status_id = publish(&pool, &author, "public", &[]).await;
    assert_eq!(entry_accounts(&pool, &status_id).await, {
        let mut both = vec![author, reader];
        both.sort();
        both
    });
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM timeline_entry WHERE status_id = $1 AND kind = 'home'",
    )
    .bind(&status_id)
    .fetch_one(&pool)
    .await
    .expect("count entries");
    assert_eq!(rows, 2, "author plus exactly one follower row");
}

#[sqlx::test(migrations = "./migrations")]
async fn keyset_pagination_visits_every_follower_exactly_once(pool: PgPool) {
    let author = seed_local(&pool, "author").await;

    // 501 followers, one past a full page, with fixed-width ids so the expected keyset
    // order is computable and every id is unique by construction.
    sqlx::query(
        "INSERT INTO account (id, username, display_name, note, local) \
         SELECT 'reader' || lpad(i::text, 4, '0'), 'reader' || i::text, '', '', true \
           FROM generate_series(1, 501) AS i",
    )
    .execute(&pool)
    .await
    .expect("seed followers");
    sqlx::query(
        "INSERT INTO follow (id, account_id, target_account_id, state, reblogs, notify) \
         SELECT 'follow' || lpad(i::text, 4, '0'), 'reader' || lpad(i::text, 4, '0'), $1, \
                'accepted', true, false \
           FROM generate_series(1, 501) AS i",
    )
    .bind(&author)
    .execute(&pool)
    .await
    .expect("seed follows");
    sqlx::query("UPDATE account SET followers_count = 501 WHERE id = $1")
        .bind(&author)
        .execute(&pool)
        .await
        .expect("set followers_count");

    let expected: Vec<String> = (1..=501).map(|i| format!("reader{i:04}")).collect();

    let (batches, queries) = follower_batches(&pool, &author).await;
    assert_eq!(
        queries, 2,
        "500 plus 1: two queries, no trailing empty page"
    );
    assert_eq!(
        batches.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![500, 1],
        "one full page and a short page"
    );
    let seen: Vec<String> = batches.into_iter().flatten().collect();
    assert_eq!(
        seen, expected,
        "every follower exactly once, in ascending account id order: no skip, no repeat"
    );

    // Exactly one page of followers: the loop must make its one extra (empty) query but
    // must not turn that page into a command.
    sqlx::query("DELETE FROM follow WHERE account_id = 'reader0501'")
        .execute(&pool)
        .await
        .expect("drop the odd follower");
    sqlx::query("UPDATE account SET followers_count = 500 WHERE id = $1")
        .bind(&author)
        .execute(&pool)
        .await
        .expect("fix followers_count");
    let (batches, queries) = follower_batches(&pool, &author).await;
    assert_eq!(
        queries, 2,
        "a page-sized result forces one look-ahead query"
    );
    assert_eq!(batches.len(), 1, "the empty look-ahead is not a command");
    assert_eq!(batches[0], expected[..500], "the same 500 followers, once");
}

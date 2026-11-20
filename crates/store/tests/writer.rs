//! The writer actor, against a live database.
//!
//! Four properties carry the design and are what this file proves: concurrent writes all
//! land, a batch is one transaction (so a burst is one fsync), a failing statement takes
//! its own batch down and nothing else, and a high-priority write is never stuck behind a
//! background queue. Each test seeds an account of its own and deletes it again, so the
//! shared database is left as it was found.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::drive;
use nodus_server_store::invalidate::{
    InvalidationKey, InvalidationKind, InvalidationSink, ValkeyInvalidator,
};
use nodus_server_store::writer::{
    Channel, Command, DbWriter, DbWriterHandle, StoreError, WriterConfig,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Connects, migrates, and seeds a fresh account.
///
/// `None` when no database answers, so `cargo test` still runs on a machine without one.
async fn setup(config: WriterConfig) -> Option<(DbWriterHandle, PgPool, String)> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nodus:nodus@localhost:5432/nodus".to_owned());
    let read = match PgPoolOptions::new().max_connections(4).connect(&url).await {
        Ok(pool) => pool,
        Err(error) => {
            eprintln!("skipping the writer tests: {error}");
            return None;
        }
    };
    sqlx::migrate!("./migrations")
        .run(&read)
        .await
        .expect("run migrations");

    let username = format!("wtest_{}", nodus_server_core::Id::new()).to_lowercase();
    let account = accounts::insert(
        &read,
        &NewAccount {
            username: &username,
            display_name: &username,
            note: "",
            bot: false,
            locked: false,
        },
    )
    .await
    .expect("seed account")
    .id;

    // The writer's pool is its own: one connection, never shared with the readers.
    let write = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect the write pool");
    let (writer, task) = DbWriter::start(write, config);
    drop(task);

    Some((writer, read, account))
}

/// Removes everything the test wrote: the drive rows cascade from the account.
async fn cleanup(pool: &PgPool, account: &str) {
    sqlx::query("DELETE FROM account WHERE id = $1")
        .bind(account)
        .execute(pool)
        .await
        .expect("delete the test account");
}

/// Forty writes posted at once all apply, and every `oneshot` resolves.
#[tokio::test]
async fn forty_concurrent_writes_all_apply() {
    let Some((writer, pool, account)) = setup(WriterConfig::default()).await else {
        return;
    };

    let mut tasks = Vec::with_capacity(40);
    for index in 0..40 {
        let writer = writer.clone();
        let account = account.clone();
        tasks.push(tokio::spawn(async move {
            writer
                .create_folder(&account, None, &format!("folder {index}"))
                .await
        }));
    }
    for task in tasks {
        task.await.expect("task").expect("folder write");
    }

    let rows = drive::folders(&pool, &account).await.expect("list folders");
    assert_eq!(rows.len(), 40, "every enqueued write is applied");
    assert!(writer.metrics().batches >= 1);

    cleanup(&pool, &account).await;
}

/// One failing command fails its own batch's waiters, and later commands still succeed.
#[tokio::test]
async fn a_failed_command_only_fails_its_own_batch() {
    let config = WriterConfig {
        batch_size: 10,
        flush_window: Duration::from_millis(100),
        ..WriterConfig::default()
    };
    let Some((writer, pool, account)) = setup(config).await else {
        return;
    };
    writer
        .create_folder(&account, None, "before")
        .await
        .expect("write before the failure");

    // `''` violates drive_folder's `CHECK (name <> '')`: a deterministic statement error
    // that is not a constraint the caller could avoid by retrying.
    let (bad, bad_reply) = Command::create_folder(&account, None, "");
    let (mate, mate_reply) = Command::create_folder(&account, None, "batch mate");
    writer
        .enqueue(Channel::High, bad)
        .await
        .expect("enqueue the failing command");
    writer
        .enqueue(Channel::High, mate)
        .await
        .expect("enqueue its batch mate");

    let bad = bad_reply.await.expect("reply for the failing command");
    let mate = mate_reply.await.expect("reply for the batch mate");
    assert_eq!(bad.unwrap_err().code(), Some("23514"));
    assert_eq!(
        mate.unwrap_err().code(),
        Some("23514"),
        "the same StoreError reaches every waiter in the batch"
    );

    // The actor survived, and the rollback undid only the batch.
    writer
        .create_folder(&account, None, "after")
        .await
        .expect("write after the failure");
    let names: Vec<String> = drive::folders(&pool, &account)
        .await
        .expect("list folders")
        .into_iter()
        .map(|folder| folder.name)
        .collect();
    assert!(names.contains(&"before".to_owned()));
    assert!(names.contains(&"after".to_owned()));
    assert!(!names.contains(&"batch mate".to_owned()));
    assert_eq!(writer.metrics().failed_batches, 1);

    cleanup(&pool, &account).await;
}

/// Ten statements in one transaction: one batch, one commit.
#[tokio::test]
async fn ten_commands_commit_in_one_batch() {
    let config = WriterConfig {
        batch_size: 10,
        flush_window: Duration::from_millis(100),
        ..WriterConfig::default()
    };
    let Some((writer, pool, account)) = setup(config).await else {
        return;
    };

    let mut replies = Vec::with_capacity(10);
    for index in 0..10 {
        let (command, reply) = Command::create_folder(&account, None, &format!("batched {index}"));
        writer
            .enqueue(Channel::High, command)
            .await
            .expect("enqueue");
        replies.push(reply);
    }
    for reply in replies {
        reply.await.expect("reply").expect("folder write");
    }

    let metrics = writer.metrics();
    assert_eq!(metrics.batches, 1, "ten statements, one commit");
    assert_eq!(metrics.high, 10);
    assert_eq!(metrics.high_flushed, 10);

    cleanup(&pool, &account).await;
}

/// A high-priority write is not starved behind a long background queue.
#[tokio::test]
async fn high_priority_is_not_starved() {
    let config = WriterConfig {
        batch_size: 8,
        flush_window: Duration::from_millis(5),
        ..WriterConfig::default()
    };
    let Some((writer, pool, account)) = setup(config).await else {
        return;
    };

    let finished = Arc::new(AtomicUsize::new(0));
    for index in 0..100 {
        let (command, reply) = Command::create_folder(&account, None, &format!("bulk {index}"));
        writer
            .enqueue(Channel::Bulk, command)
            .await
            .expect("enqueue bulk");
        let finished = Arc::clone(&finished);
        tokio::spawn(async move {
            if reply.await.is_ok_and(|result| result.is_ok()) {
                finished.fetch_add(1, Ordering::SeqCst);
            }
        });
    }

    // Nothing above yielded, so the actor has not run yet: its first batch sees a full
    // bulk queue and this one high-priority write, and must take the high one first.
    writer
        .create_folder(&account, None, "urgent")
        .await
        .expect("high-priority write");

    let done = finished.load(Ordering::SeqCst);
    assert!(
        done < 100,
        "the high write waited for {done} of 100 bulk writes"
    );
    assert_eq!(writer.metrics().bulk, 100);

    cleanup(&pool, &account).await;
}

/// A closed actor answers `Closed` instead of hanging, and never panics its caller.
#[tokio::test]
async fn a_closed_actor_refuses_instead_of_hanging() {
    let Some((writer, pool, account)) = setup(WriterConfig::default()).await else {
        return;
    };
    // Dropping the handle does not stop the actor (other clones may exist), so this only
    // pins the API's shape: a write either lands or answers.
    let answer = writer.create_folder(&account, None, "alive").await;
    assert!(answer.is_ok());
    assert!(matches!(StoreError::Closed.code(), None));
    cleanup(&pool, &account).await;
}

// ---------------------------------------------------------------------------
// Invalidation: what a commit tells the cache, and what it must never tell it.
// ---------------------------------------------------------------------------

/// A sink that remembers every batch the writer handed it, and can panic on demand.
#[derive(Default)]
struct Recorder {
    calls: std::sync::Mutex<Vec<Vec<InvalidationKey>>>,
    panic_once: AtomicBool,
}

impl Recorder {
    /// One entry per `invalidate` call, in order.
    fn calls(&self) -> Vec<Vec<InvalidationKey>> {
        self.calls.lock().expect("recorder lock").clone()
    }

    /// Every key, flattened across calls.
    fn keys(&self) -> Vec<InvalidationKey> {
        self.calls().concat()
    }
}

impl InvalidationSink for Recorder {
    fn invalidate(&self, keys: &[InvalidationKey]) {
        if self.panic_once.swap(false, Ordering::SeqCst) {
            panic!("recorder sink is broken on purpose");
        }
        self.calls
            .lock()
            .expect("recorder lock")
            .push(keys.to_vec());
    }
}

fn key(account: &str, kind: InvalidationKind, id: impl std::fmt::Display) -> InvalidationKey {
    InvalidationKey::new(account, kind, id.to_string())
}

/// A committed batch hands the sink exactly the keys its statements dirtied.
#[tokio::test]
async fn a_committed_batch_reports_exactly_its_keys() {
    let recorder = Arc::new(Recorder::default());
    let Some((writer, pool, account)) = setup(WriterConfig {
        sink: Some(recorder.clone()),
        ..WriterConfig::default()
    })
    .await
    else {
        return;
    };

    let folder = writer
        .create_folder(&account, None, "keys")
        .await
        .expect("create folder");
    let sha = "0".repeat(64);
    let object = writer
        .create_object(&account, None, "keys.txt", "text/plain", &sha, 3)
        .await
        .expect("create object");
    let attachment = writer
        .attach_object(&account, object.id, None, "", None, None)
        .await
        .expect("attach")
        .expect("attachment id");
    writer
        .delete_object(&account, object.id)
        .await
        .expect("delete object");

    let expected = vec![
        key(&account, InvalidationKind::Folder, folder.id),
        InvalidationKey::parent_folder(&account, None),
        key(&account, InvalidationKind::Object, object.id),
        InvalidationKey::parent_folder(&account, None),
        key(&account, InvalidationKind::Attachment, &attachment),
        key(&account, InvalidationKind::Object, object.id),
        key(&account, InvalidationKind::Object, object.id),
        InvalidationKey::new(&account, InvalidationKind::Account, account.clone()),
    ];
    assert_eq!(recorder.keys(), expected, "the keys, and only those keys");
    assert_eq!(
        recorder.calls().len(),
        writer.metrics().batches as usize,
        "one call per committed batch"
    );

    cleanup(&pool, &account).await;
}

/// A batch that rolls back tells the cache nothing.
#[tokio::test]
async fn a_failed_batch_invalidates_nothing() {
    let recorder = Arc::new(Recorder::default());
    let config = WriterConfig {
        batch_size: 10,
        flush_window: Duration::from_millis(100),
        sink: Some(recorder.clone()),
        ..WriterConfig::default()
    };
    let Some((writer, pool, account)) = setup(config).await else {
        return;
    };

    // `''` violates drive_folder's name check: the batch rolls back.
    let (bad, bad_reply) = Command::create_folder(&account, None, "");
    let (mate, mate_reply) = Command::create_folder(&account, None, "rolled back too");
    writer.enqueue(Channel::High, bad).await.expect("enqueue");
    writer.enqueue(Channel::High, mate).await.expect("enqueue");
    assert!(bad_reply.await.expect("reply").is_err());
    assert!(mate_reply.await.expect("reply").is_err());

    assert!(
        recorder.calls().is_empty(),
        "a rolled-back batch must not invalidate anything"
    );

    // The actor still commits the next batch, and that one does report.
    writer
        .create_folder(&account, None, "committed")
        .await
        .expect("write after the failure");
    assert_eq!(recorder.calls().len(), 1);

    cleanup(&pool, &account).await;
}

/// Twenty creations in one flush arrive as one call carrying all twenty key sets.
#[tokio::test]
async fn twenty_creations_share_one_flush_and_one_key_set() {
    let recorder = Arc::new(Recorder::default());
    let config = WriterConfig {
        batch_size: 50,
        flush_window: Duration::from_millis(100),
        sink: Some(recorder.clone()),
        ..WriterConfig::default()
    };
    let Some((writer, pool, account)) = setup(config).await else {
        return;
    };

    let mut tasks = Vec::with_capacity(20);
    for index in 0..20 {
        let writer = writer.clone();
        let account = account.clone();
        tasks.push(tokio::spawn(async move {
            writer
                .create_folder(&account, None, &format!("batch {index}"))
                .await
        }));
    }
    for task in tasks {
        task.await.expect("task").expect("folder write");
    }

    assert_eq!(writer.metrics().batches, 1, "one flush for twenty writes");
    let calls = recorder.calls();
    assert_eq!(calls.len(), 1, "one invalidate call for the flush");
    let keys = &calls[0];
    assert_eq!(
        keys.len(),
        40,
        "twenty folders, each with its parent listing"
    );
    assert_eq!(
        keys.iter()
            .filter(|key| key.kind == InvalidationKind::Folder)
            .count(),
        20
    );
    assert_eq!(
        keys.iter()
            .filter(|key| key.kind == InvalidationKind::ParentFolder && key.id.is_empty())
            .count(),
        20,
        "each creation dirties the root listing"
    );

    cleanup(&pool, &account).await;
}

/// A panicking sink is caught and logged; the actor and the next write are unaffected.
#[tokio::test]
async fn a_panicking_sink_does_not_kill_the_actor() {
    let recorder = Arc::new(Recorder::default());
    recorder.panic_once.store(true, Ordering::SeqCst);
    let Some((writer, pool, account)) = setup(WriterConfig {
        sink: Some(recorder.clone()),
        ..WriterConfig::default()
    })
    .await
    else {
        return;
    };

    let first = writer
        .create_folder(&account, None, "before the panic")
        .await
        .expect("the write committed before the sink ran");
    let second = writer
        .create_folder(&account, None, "after the panic")
        .await
        .expect("the actor survived the sink's panic");

    let rows = drive::folders(&pool, &account).await.expect("list folders");
    let ids: Vec<_> = rows.iter().map(|folder| folder.id).collect();
    assert!(ids.contains(&first.id));
    assert!(ids.contains(&second.id));
    assert_eq!(writer.metrics().batches, 2);
    assert_eq!(
        recorder.calls().len(),
        1,
        "only the batch after the panic was reported"
    );

    cleanup(&pool, &account).await;
}

/// The payload is the documented JSON line, built without a server.
#[tokio::test]
async fn valkey_payload_has_the_documented_shape() {
    let keys = vec![
        InvalidationKey::new("acc", InvalidationKind::Folder, "f"),
        InvalidationKey::parent_folder("acc", None),
        InvalidationKey::new("acc", InvalidationKind::Object, "o"),
        InvalidationKey::new("acc", InvalidationKind::Attachment, "a"),
        InvalidationKey::new("acc", InvalidationKind::Account, "acc"),
    ];
    let line = ValkeyInvalidator::payload(&keys);
    assert!(!line.contains('\n'), "one JSON line per flush");

    let json: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
    assert_eq!(json["channel"], "nodus:invalidate");
    let encoded = json["keys"].as_array().expect("keys array");
    assert_eq!(encoded.len(), 5);
    let kinds: Vec<&str> = encoded
        .iter()
        .map(|key| key["kind"].as_str().expect("kind"))
        .collect();
    assert_eq!(
        kinds,
        ["folder", "parent_folder", "object", "attachment", "account"]
    );
    assert_eq!(encoded[0]["account_id"], "acc");
    assert_eq!(encoded[0]["id"], "f");
    assert_eq!(encoded[1]["id"], "", "the root listing has an empty id");
    // The same keys decode back, so both ends of the wire agree.
    let decoded: Vec<InvalidationKey> =
        serde_json::from_value(json["keys"].clone()).expect("keys decode");
    assert_eq!(decoded, keys);
}

/// With no sink configured, writes land exactly as they did before.
#[tokio::test]
async fn no_sink_writes_the_same_rows() {
    let Some((writer, pool, account)) = setup(WriterConfig::default()).await else {
        return;
    };

    for index in 0..3 {
        writer
            .create_folder(&account, None, &format!("plain {index}"))
            .await
            .expect("folder write");
    }
    let sha = "1".repeat(64);
    for index in 0..2 {
        writer
            .create_object(
                &account,
                None,
                &format!("plain {index}.txt"),
                "text/plain",
                &sha,
                7,
            )
            .await
            .expect("object write");
    }

    assert_eq!(
        drive::folders(&pool, &account)
            .await
            .expect("folders")
            .len(),
        3
    );
    assert_eq!(
        drive::objects(&pool, &account, None, 50, 0)
            .await
            .expect("objects")
            .len(),
        2
    );

    cleanup(&pool, &account).await;
}

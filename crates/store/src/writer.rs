//! The single writer: one task, one connection, one transaction per batch.
//!
//! Every write in the process goes through [`DbWriterHandle`], which posts a [`Command`]
//! onto one of two queues and awaits a `oneshot` for the answer. One actor owns the only
//! write pool (`max_connections(1)`), so there is no lock contention on the row level and
//! no deadlock between two writers — the actor is the lock.
//!
//! Batching is what makes this cheap. The actor drains whatever is already queued (up to
//! [`WriterConfig::batch_size`], waiting at most [`WriterConfig::flush_window`] for more)
//! and runs the whole batch in **one transaction**: N statements commit with one WAL
//! fsync. A command whose answer depends on the row it just wrote (`INSERT … RETURNING
//! id`) is answered from the batch's own result, never with a second query.
//!
//! Two channels, `high` then `bulk`, selected with `biased;`: a queue of background writes
//! can never hold a request's write behind it, because the high queue is polled first
//! every time the actor collects a batch.
//!
//! A failed statement aborts its transaction, and the rollback takes the rest of the
//! batch with it: every waiter in that batch is failed with the same [`StoreError`], and
//! the actor keeps running. That is the price of one fsync per batch, and it is why a
//! write that is expected to fail (a stale id) is answered as `Ok(false)` by the command
//! rather than as an error — see [`DbWriterHandle::rename_folder`].

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::drive::{self, DriveFolder, DriveObject, MoveError, ProcessingState, Visibility};
use crate::invalidate::{InvalidationKey, InvalidationKind, InvalidationSink};

/// How much the actor may hold, and how it packs a batch.
#[derive(Clone)]
pub struct WriterConfig {
    /// Commands the high-priority queue may hold before senders wait.
    pub high_capacity: usize,
    /// Commands the background queue may hold before senders wait.
    pub bulk_capacity: usize,
    /// Most statements in one transaction. Each batch is one fsync.
    pub batch_size: usize,
    /// How long to keep collecting before flushing a batch that is not yet full.
    pub flush_window: Duration,
    /// Where a committed batch's invalidation keys go. `None` means nobody is told —
    /// the default, so a deployment without a cache behaves exactly as before.
    pub sink: Option<Arc<dyn InvalidationSink>>,
}

impl std::fmt::Debug for WriterConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WriterConfig")
            .field("high_capacity", &self.high_capacity)
            .field("bulk_capacity", &self.bulk_capacity)
            .field("batch_size", &self.batch_size)
            .field("flush_window", &self.flush_window)
            .field("sink", &self.sink.as_ref().map(|_| "<sink>"))
            .finish()
    }
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            high_capacity: 64,
            bulk_capacity: 512,
            batch_size: 50,
            flush_window: Duration::from_millis(25),
            sink: None,
        }
    }
}

/// A write that failed, flattened so one error can be handed to every waiter in a batch.
///
/// [`sqlx::Error`] is not `Clone`, and a failed batch must tell all of its waiters the
/// same thing: the fields are copied out once, and the error is cloned to each waiter.
#[derive(Debug, Clone, thiserror::Error)]
pub enum StoreError {
    /// The database refused the statement. `code` is the SQLSTATE, when there is one.
    #[error("database error: {message}")]
    Db {
        code: Option<String>,
        constraint: Option<String>,
        message: String,
    },
    /// A folder move into its own subtree, refused before anything was written.
    #[error("a folder cannot be moved into itself or its own descendant")]
    Cycle,
    /// The actor is gone: every sender was dropped, or its task ended.
    #[error("the write actor is not running")]
    Closed,
}

impl StoreError {
    /// The SQLSTATE, when the failure came from the database.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Db { code, .. } => code.as_deref(),
            Self::Cycle | Self::Closed => None,
        }
    }

    /// True for SQLSTATE 23503, the composite foreign key saying "not in this account".
    #[must_use]
    pub fn is_foreign_key_violation(&self) -> bool {
        self.code() == Some("23503")
    }
}

impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> Self {
        match error {
            sqlx::Error::Database(database) => Self::Db {
                code: database.code().map(std::borrow::Cow::into_owned),
                constraint: database.constraint().map(str::to_owned),
                message: database.message().to_owned(),
            },
            other => Self::Db {
                code: None,
                constraint: None,
                message: other.to_string(),
            },
        }
    }
}

impl From<MoveError> for StoreError {
    fn from(error: MoveError) -> Self {
        match error {
            MoveError::Cycle => Self::Cycle,
            MoveError::NotFound => Self::Db {
                code: None,
                constraint: None,
                message: "folder not found".to_owned(),
            },
            MoveError::Db(error) => Self::from(error),
        }
    }
}

/// A snapshot of what the actor has done so far.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriterMetrics {
    /// Commands accepted on the high queue.
    pub high: u64,
    /// Commands accepted on the background queue.
    pub bulk: u64,
    /// High-queue commands written to the database (their batches committed).
    pub high_flushed: u64,
    /// Background commands written to the database.
    pub bulk_flushed: u64,
    /// Transactions committed.
    pub batches: u64,
    /// Transactions rolled back because a statement in them failed.
    pub failed_batches: u64,
}

#[derive(Debug, Default)]
struct Metrics {
    high: AtomicU64,
    bulk: AtomicU64,
    high_flushed: AtomicU64,
    bulk_flushed: AtomicU64,
    batches: AtomicU64,
    failed_batches: AtomicU64,
}

impl Metrics {
    fn snapshot(&self) -> WriterMetrics {
        WriterMetrics {
            high: self.high.load(Ordering::Relaxed),
            bulk: self.bulk.load(Ordering::Relaxed),
            high_flushed: self.high_flushed.load(Ordering::Relaxed),
            bulk_flushed: self.bulk_flushed.load(Ordering::Relaxed),
            batches: self.batches.load(Ordering::Relaxed),
            failed_batches: self.failed_batches.load(Ordering::Relaxed),
        }
    }
}

/// Which queue a command goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// A request is waiting on the answer.
    High,
    /// Background work that can wait behind a burst.
    Bulk,
}

impl Channel {
    const fn label(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Bulk => "bulk",
        }
    }
}

/// One write, and the channel its caller is waiting on.
///
/// The enum is written out rather than boxed into a future because a future cannot be
/// batched, cannot be inspected, and cannot be tested on its own: each variant names the
/// statement, its parameters, and the type it answers with.
#[derive(Debug)]
pub enum Command {
    CreateFolder {
        account: String,
        parent: Option<Uuid>,
        name: String,
        reply: oneshot::Sender<Result<DriveFolder, StoreError>>,
    },
    RenameFolder {
        account: String,
        id: Uuid,
        name: String,
        reply: oneshot::Sender<Result<bool, StoreError>>,
    },
    MoveFolder {
        account: String,
        id: Uuid,
        parent: Option<Uuid>,
        reply: oneshot::Sender<Result<bool, StoreError>>,
    },
    DeleteFolder {
        account: String,
        id: Uuid,
        reply: oneshot::Sender<Result<Vec<String>, StoreError>>,
    },
    CreateObject {
        account: String,
        folder: Option<Uuid>,
        filename: String,
        mime_type: String,
        sha256: String,
        byte_size: i64,
        reply: oneshot::Sender<Result<DriveObject, StoreError>>,
    },
    RenameObject {
        account: String,
        id: Uuid,
        filename: String,
        reply: oneshot::Sender<Result<bool, StoreError>>,
    },
    MoveObject {
        account: String,
        id: Uuid,
        folder: Option<Uuid>,
        reply: oneshot::Sender<Result<bool, StoreError>>,
    },
    SetVisibility {
        account: String,
        id: Uuid,
        visibility: Visibility,
        reply: oneshot::Sender<Result<bool, StoreError>>,
    },
    SetState {
        account: String,
        id: Uuid,
        state: ProcessingState,
        reply: oneshot::Sender<Result<bool, StoreError>>,
    },
    DeleteObject {
        account: String,
        id: Uuid,
        reply: oneshot::Sender<Result<Option<String>, StoreError>>,
    },
    AttachObject {
        account: String,
        object_id: Uuid,
        status_id: Option<String>,
        alt_text: String,
        focus: Option<String>,
        blurhash: Option<String>,
        reply: oneshot::Sender<Result<Option<String>, StoreError>>,
    },
}

impl Command {
    /// Builds a create command and the receiver its answer arrives on.
    #[must_use]
    pub fn create_folder(
        account: &str,
        parent: Option<Uuid>,
        name: &str,
    ) -> (Self, oneshot::Receiver<Result<DriveFolder, StoreError>>) {
        let (reply, receiver) = oneshot::channel();
        (
            Self::CreateFolder {
                account: account.to_owned(),
                parent,
                name: name.to_owned(),
                reply,
            },
            receiver,
        )
    }

    #[must_use]
    pub fn rename_folder(
        account: &str,
        id: Uuid,
        name: &str,
    ) -> (Self, oneshot::Receiver<Result<bool, StoreError>>) {
        let (reply, receiver) = oneshot::channel();
        (
            Self::RenameFolder {
                account: account.to_owned(),
                id,
                name: name.to_owned(),
                reply,
            },
            receiver,
        )
    }

    #[must_use]
    pub fn move_folder(
        account: &str,
        id: Uuid,
        parent: Option<Uuid>,
    ) -> (Self, oneshot::Receiver<Result<bool, StoreError>>) {
        let (reply, receiver) = oneshot::channel();
        (
            Self::MoveFolder {
                account: account.to_owned(),
                id,
                parent,
                reply,
            },
            receiver,
        )
    }

    #[must_use]
    pub fn delete_folder(
        account: &str,
        id: Uuid,
    ) -> (Self, oneshot::Receiver<Result<Vec<String>, StoreError>>) {
        let (reply, receiver) = oneshot::channel();
        (
            Self::DeleteFolder {
                account: account.to_owned(),
                id,
                reply,
            },
            receiver,
        )
    }

    #[must_use]
    #[allow(clippy::too_many_arguments, reason = "one row, one column each")]
    pub fn create_object(
        account: &str,
        folder: Option<Uuid>,
        filename: &str,
        mime_type: &str,
        sha256: &str,
        byte_size: i64,
    ) -> (Self, oneshot::Receiver<Result<DriveObject, StoreError>>) {
        let (reply, receiver) = oneshot::channel();
        (
            Self::CreateObject {
                account: account.to_owned(),
                folder,
                filename: filename.to_owned(),
                mime_type: mime_type.to_owned(),
                sha256: sha256.to_owned(),
                byte_size,
                reply,
            },
            receiver,
        )
    }

    #[must_use]
    pub fn rename_object(
        account: &str,
        id: Uuid,
        filename: &str,
    ) -> (Self, oneshot::Receiver<Result<bool, StoreError>>) {
        let (reply, receiver) = oneshot::channel();
        (
            Self::RenameObject {
                account: account.to_owned(),
                id,
                filename: filename.to_owned(),
                reply,
            },
            receiver,
        )
    }

    #[must_use]
    pub fn move_object(
        account: &str,
        id: Uuid,
        folder: Option<Uuid>,
    ) -> (Self, oneshot::Receiver<Result<bool, StoreError>>) {
        let (reply, receiver) = oneshot::channel();
        (
            Self::MoveObject {
                account: account.to_owned(),
                id,
                folder,
                reply,
            },
            receiver,
        )
    }

    #[must_use]
    pub fn set_visibility(
        account: &str,
        id: Uuid,
        visibility: Visibility,
    ) -> (Self, oneshot::Receiver<Result<bool, StoreError>>) {
        let (reply, receiver) = oneshot::channel();
        (
            Self::SetVisibility {
                account: account.to_owned(),
                id,
                visibility,
                reply,
            },
            receiver,
        )
    }

    #[must_use]
    pub fn set_state(
        account: &str,
        id: Uuid,
        state: ProcessingState,
    ) -> (Self, oneshot::Receiver<Result<bool, StoreError>>) {
        let (reply, receiver) = oneshot::channel();
        (
            Self::SetState {
                account: account.to_owned(),
                id,
                state,
                reply,
            },
            receiver,
        )
    }

    #[must_use]
    pub fn delete_object(
        account: &str,
        id: Uuid,
    ) -> (Self, oneshot::Receiver<Result<Option<String>, StoreError>>) {
        let (reply, receiver) = oneshot::channel();
        (
            Self::DeleteObject {
                account: account.to_owned(),
                id,
                reply,
            },
            receiver,
        )
    }

    #[must_use]
    pub fn attach_object(
        account: &str,
        object_id: Uuid,
        status_id: Option<&str>,
        alt_text: &str,
        focus: Option<&str>,
        blurhash: Option<&str>,
    ) -> (Self, oneshot::Receiver<Result<Option<String>, StoreError>>) {
        let (reply, receiver) = oneshot::channel();
        (
            Self::AttachObject {
                account: account.to_owned(),
                object_id,
                status_id: status_id.map(str::to_owned),
                alt_text: alt_text.to_owned(),
                focus: focus.map(str::to_owned),
                blurhash: blurhash.map(str::to_owned),
                reply,
            },
            receiver,
        )
    }

    /// Splits a command into the statement and the slot its answer will be sent to.
    fn into_parts(self) -> (Mutation, Reply) {
        match self {
            Self::CreateFolder {
                account,
                parent,
                name,
                reply,
            } => (
                Mutation::CreateFolder {
                    account,
                    parent,
                    name,
                },
                Reply::Folder(reply),
            ),
            Self::RenameFolder {
                account,
                id,
                name,
                reply,
            } => (
                Mutation::RenameFolder { account, id, name },
                Reply::Flag(reply),
            ),
            Self::MoveFolder {
                account,
                id,
                parent,
                reply,
            } => (
                Mutation::MoveFolder {
                    account,
                    id,
                    parent,
                },
                Reply::Flag(reply),
            ),
            Self::DeleteFolder { account, id, reply } => (
                Mutation::DeleteFolder { account, id },
                Reply::Digests(reply),
            ),
            Self::CreateObject {
                account,
                folder,
                filename,
                mime_type,
                sha256,
                byte_size,
                reply,
            } => (
                Mutation::CreateObject {
                    account,
                    folder,
                    filename,
                    mime_type,
                    sha256,
                    byte_size,
                },
                Reply::FolderObject(reply),
            ),
            Self::RenameObject {
                account,
                id,
                filename,
                reply,
            } => (
                Mutation::RenameObject {
                    account,
                    id,
                    filename,
                },
                Reply::Flag(reply),
            ),
            Self::MoveObject {
                account,
                id,
                folder,
                reply,
            } => (
                Mutation::MoveObject {
                    account,
                    id,
                    folder,
                },
                Reply::Flag(reply),
            ),
            Self::SetVisibility {
                account,
                id,
                visibility,
                reply,
            } => (
                Mutation::SetVisibility {
                    account,
                    id,
                    visibility,
                },
                Reply::Flag(reply),
            ),
            Self::SetState {
                account,
                id,
                state,
                reply,
            } => (
                Mutation::SetState { account, id, state },
                Reply::Flag(reply),
            ),
            Self::DeleteObject { account, id, reply } => {
                (Mutation::DeleteObject { account, id }, Reply::Digest(reply))
            }
            Self::AttachObject {
                account,
                object_id,
                status_id,
                alt_text,
                focus,
                blurhash,
                reply,
            } => (
                Mutation::AttachObject {
                    account,
                    object_id,
                    status_id,
                    alt_text,
                    focus,
                    blurhash,
                },
                Reply::Digest(reply),
            ),
        }
    }
}

/// A command with its reply slot removed: exactly what the actor executes.
enum Mutation {
    CreateFolder {
        account: String,
        parent: Option<Uuid>,
        name: String,
    },
    RenameFolder {
        account: String,
        id: Uuid,
        name: String,
    },
    MoveFolder {
        account: String,
        id: Uuid,
        parent: Option<Uuid>,
    },
    DeleteFolder {
        account: String,
        id: Uuid,
    },
    CreateObject {
        account: String,
        folder: Option<Uuid>,
        filename: String,
        mime_type: String,
        sha256: String,
        byte_size: i64,
    },
    RenameObject {
        account: String,
        id: Uuid,
        filename: String,
    },
    MoveObject {
        account: String,
        id: Uuid,
        folder: Option<Uuid>,
    },
    SetVisibility {
        account: String,
        id: Uuid,
        visibility: Visibility,
    },
    SetState {
        account: String,
        id: Uuid,
        state: ProcessingState,
    },
    DeleteObject {
        account: String,
        id: Uuid,
    },
    AttachObject {
        account: String,
        object_id: Uuid,
        status_id: Option<String>,
        alt_text: String,
        focus: Option<String>,
        blurhash: Option<String>,
    },
}

/// What one statement answered, held until the batch commits.
enum Outcome {
    Folder(DriveFolder),
    FolderObject(DriveObject),
    Flag(bool),
    Digest(Option<String>),
    Digests(Vec<String>),
}

/// Where one statement's answer goes once the batch commits (or fails).
enum Reply {
    Folder(oneshot::Sender<Result<DriveFolder, StoreError>>),
    FolderObject(oneshot::Sender<Result<DriveObject, StoreError>>),
    Flag(oneshot::Sender<Result<bool, StoreError>>),
    Digest(oneshot::Sender<Result<Option<String>, StoreError>>),
    Digests(oneshot::Sender<Result<Vec<String>, StoreError>>),
}

impl Reply {
    /// Tells the waiter the whole batch rolled back.
    fn fail(self, error: StoreError) {
        match self {
            Self::Folder(reply) => {
                let _ = reply.send(Err(error));
            }
            Self::FolderObject(reply) => {
                let _ = reply.send(Err(error));
            }
            Self::Flag(reply) => {
                let _ = reply.send(Err(error));
            }
            Self::Digest(reply) => {
                let _ = reply.send(Err(error));
            }
            Self::Digests(reply) => {
                let _ = reply.send(Err(error));
            }
        }
    }

    /// Tells the waiter what its statement wrote.
    fn send(self, outcome: Outcome) {
        match (self, outcome) {
            (Self::Folder(reply), Outcome::Folder(row)) => {
                let _ = reply.send(Ok(row));
            }
            (Self::FolderObject(reply), Outcome::FolderObject(row)) => {
                let _ = reply.send(Ok(row));
            }
            (Self::Flag(reply), Outcome::Flag(flag)) => {
                let _ = reply.send(Ok(flag));
            }
            (Self::Digest(reply), Outcome::Digest(digest)) => {
                let _ = reply.send(Ok(digest));
            }
            (Self::Digests(reply), Outcome::Digests(digests)) => {
                let _ = reply.send(Ok(digests));
            }
            // The statement and its reply slot are written in the same arm of
            // `into_parts`, so a pair that does not match is a bug in this file.
            (reply, _) => reply.fail(StoreError::Closed),
        }
    }
}

/// The actor's handle: post a command, await its answer.
///
/// Cloning is cheap and every clone is the same writer. A dropped handle never stops the
/// actor; only the last sender going away does.
#[derive(Debug, Clone)]
pub struct DbWriterHandle {
    high: mpsc::Sender<Command>,
    bulk: mpsc::Sender<Command>,
    metrics: Arc<Metrics>,
}

impl DbWriterHandle {
    /// Counts by queue and batches committed, as of now.
    #[must_use]
    pub fn metrics(&self) -> WriterMetrics {
        self.metrics.snapshot()
    }

    /// Posts a command without waiting for its answer.
    ///
    /// Backpressure is real: a full queue makes the caller wait rather than grow memory
    /// without bound. A closed actor is [`StoreError::Closed`], never a panic.
    pub async fn enqueue(&self, channel: Channel, command: Command) -> Result<(), StoreError> {
        let queue = match channel {
            Channel::High => &self.high,
            Channel::Bulk => &self.bulk,
        };
        match queue.try_send(command) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(command)) => {
                queue.send(command).await.map_err(|_| StoreError::Closed)?;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => return Err(StoreError::Closed),
        }
        let counter = match channel {
            Channel::High => &self.metrics.high,
            Channel::Bulk => &self.metrics.bulk,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Posts a command and waits for the actor's answer.
    pub async fn submit<T>(
        &self,
        channel: Channel,
        command: Command,
        reply: oneshot::Receiver<Result<T, StoreError>>,
    ) -> Result<T, StoreError> {
        self.enqueue(channel, command).await?;
        reply.await.unwrap_or(Err(StoreError::Closed))
    }

    /// Creates a folder under `parent`, or at the root when `parent` is `None`.
    pub async fn create_folder(
        &self,
        account: &str,
        parent: Option<Uuid>,
        name: &str,
    ) -> Result<DriveFolder, StoreError> {
        let (command, reply) = Command::create_folder(account, parent, name);
        self.submit(Channel::High, command, reply).await
    }

    /// Renames a folder. `Ok(false)` when the account has no such folder — a stale id is
    /// an answer, not a failure, so it does not roll back the rest of the batch.
    pub async fn rename_folder(
        &self,
        account: &str,
        id: Uuid,
        name: &str,
    ) -> Result<bool, StoreError> {
        let (command, reply) = Command::rename_folder(account, id, name);
        self.submit(Channel::High, command, reply).await
    }

    /// Re-parents a folder, refusing a cycle.
    ///
    /// `Ok(false)` when the folder is not in this account; [`StoreError::Cycle`] when the
    /// target is the folder itself or one of its descendants. The subtree check and the
    /// update run in the batch's transaction, so nothing can slip between them.
    pub async fn move_folder(
        &self,
        account: &str,
        id: Uuid,
        parent: Option<Uuid>,
    ) -> Result<bool, StoreError> {
        let (command, reply) = Command::move_folder(account, id, parent);
        self.submit(Channel::High, command, reply).await
    }

    /// Deletes a folder and its subtree, answering the digests that went with it.
    pub async fn delete_folder(&self, account: &str, id: Uuid) -> Result<Vec<String>, StoreError> {
        let (command, reply) = Command::delete_folder(account, id);
        self.submit(Channel::High, command, reply).await
    }

    /// Records a file the caller has already written to the blob store under `sha256`.
    #[allow(clippy::too_many_arguments, reason = "one row, one column each")]
    pub async fn create_object(
        &self,
        account: &str,
        folder: Option<Uuid>,
        filename: &str,
        mime_type: &str,
        sha256: &str,
        byte_size: i64,
    ) -> Result<DriveObject, StoreError> {
        let (command, reply) =
            Command::create_object(account, folder, filename, mime_type, sha256, byte_size);
        self.submit(Channel::High, command, reply).await
    }

    /// Renames a file. `Ok(false)` when the account has no such file.
    pub async fn rename_object(
        &self,
        account: &str,
        id: Uuid,
        filename: &str,
    ) -> Result<bool, StoreError> {
        let (command, reply) = Command::rename_object(account, id, filename);
        self.submit(Channel::High, command, reply).await
    }

    /// Files a file into `folder`, or at the root when `folder` is `None`.
    pub async fn move_object(
        &self,
        account: &str,
        id: Uuid,
        folder: Option<Uuid>,
    ) -> Result<bool, StoreError> {
        let (command, reply) = Command::move_object(account, id, folder);
        self.submit(Channel::High, command, reply).await
    }

    /// Sets who may fetch a file.
    pub async fn set_visibility(
        &self,
        account: &str,
        id: Uuid,
        visibility: Visibility,
    ) -> Result<bool, StoreError> {
        let (command, reply) = Command::set_visibility(account, id, visibility);
        self.submit(Channel::High, command, reply).await
    }

    /// Records how far an upload got.
    pub async fn set_state(
        &self,
        account: &str,
        id: Uuid,
        state: ProcessingState,
    ) -> Result<bool, StoreError> {
        let (command, reply) = Command::set_state(account, id, state);
        self.submit(Channel::High, command, reply).await
    }

    /// Deletes a file, answering its digest for the caller's byte accounting.
    pub async fn delete_object(
        &self,
        account: &str,
        id: Uuid,
    ) -> Result<Option<String>, StoreError> {
        let (command, reply) = Command::delete_object(account, id);
        self.submit(Channel::High, command, reply).await
    }

    /// Mints the `media_attachment` that shows a drive file in a post, zero-copy.
    pub async fn attach_object(
        &self,
        account: &str,
        object_id: Uuid,
        status_id: Option<&str>,
        alt_text: &str,
        focus: Option<&str>,
        blurhash: Option<&str>,
    ) -> Result<Option<String>, StoreError> {
        let (command, reply) =
            Command::attach_object(account, object_id, status_id, alt_text, focus, blurhash);
        self.submit(Channel::High, command, reply).await
    }
}

/// The actor itself: it owns the write pool and the two queues.
#[derive(Debug)]
pub struct DbWriter {
    pool: PgPool,
    config: WriterConfig,
    high: mpsc::Receiver<Command>,
    bulk: mpsc::Receiver<Command>,
    metrics: Arc<Metrics>,
}

impl DbWriter {
    /// Starts the actor on the current runtime and returns its handle.
    ///
    /// The handle may be cloned freely; the task ends when the last clone is dropped and
    /// both queues drain. The [`JoinHandle`] is the actor's, for a caller that wants to
    /// watch it exit.
    pub fn start(pool: PgPool, config: WriterConfig) -> (DbWriterHandle, JoinHandle<()>) {
        let (handle, writer, metrics) = Self::pair(pool, config);
        // `metrics` is already inside the handle; the actor shares the same counters.
        let task = tokio::spawn(writer.run());
        let _ = metrics;
        (handle, task)
    }

    /// Starts the actor on a thread of its own, with a current-thread runtime.
    ///
    /// For callers that build state outside a runtime — the API's `AppState` is built in
    /// `main` before the server takes the scheduler, and unit tests build it with no
    /// runtime at all. One thread owning the only write connection is what "single
    /// writer" means, so this is not a workaround: it is the same actor with a home.
    pub fn start_detached(pool: PgPool, config: WriterConfig) -> DbWriterHandle {
        let (handle, writer, metrics) = Self::pair(pool, config);
        let _ = metrics;
        std::thread::Builder::new()
            .name("db-writer".to_owned())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                match runtime {
                    Ok(runtime) => runtime.block_on(writer.run()),
                    Err(error) => tracing::error!(%error, "db writer runtime failed to start"),
                }
            })
            .map_or_else(
                |error| {
                    tracing::error!(%error, "db writer thread failed to start");
                },
                |_| {},
            );
        handle
    }

    fn pair(pool: PgPool, config: WriterConfig) -> (DbWriterHandle, Self, Arc<Metrics>) {
        let (high_tx, high) = mpsc::channel(config.high_capacity.max(1));
        let (bulk_tx, bulk) = mpsc::channel(config.bulk_capacity.max(1));
        let metrics = Arc::new(Metrics::default());
        let handle = DbWriterHandle {
            high: high_tx,
            bulk: bulk_tx,
            metrics: Arc::clone(&metrics),
        };
        let writer = Self {
            pool,
            config,
            high,
            bulk,
            metrics: Arc::clone(&metrics),
        };
        (handle, writer, metrics)
    }

    /// The loop: collect, flush, repeat. It ends only when both queues are closed.
    pub async fn run(mut self) {
        while let Some(batch) = self.collect().await {
            self.flush(batch).await;
        }
        tracing::debug!("db writer stopped: every sender dropped");
    }

    /// Waits for one command, then collects up to `batch_size` within `flush_window`.
    ///
    /// High is polled before bulk at every step, so a queued request write is in the very
    /// next batch however long the background queue is.
    async fn collect(&mut self) -> Option<Vec<(Channel, Command)>> {
        let first = tokio::select! {
            biased;
            Some(command) = self.high.recv() => (Channel::High, command),
            Some(command) = self.bulk.recv() => (Channel::Bulk, command),
            else => return None,
        };
        let mut batch = vec![first];
        let deadline = tokio::time::Instant::now() + self.config.flush_window;
        while batch.len() < self.config.batch_size {
            self.drain_ready(&mut batch);
            if batch.len() >= self.config.batch_size {
                break;
            }
            let sleep = tokio::time::sleep_until(deadline);
            tokio::pin!(sleep);
            tokio::select! {
                biased;
                Some(command) = self.high.recv() => batch.push((Channel::High, command)),
                Some(command) = self.bulk.recv() => batch.push((Channel::Bulk, command)),
                () = &mut sleep => break,
                else => break,
            }
        }
        Some(batch)
    }

    /// Moves everything already queued into the batch, high first.
    fn drain_ready(&mut self, batch: &mut Vec<(Channel, Command)>) {
        while batch.len() < self.config.batch_size {
            match self.high.try_recv() {
                Ok(command) => batch.push((Channel::High, command)),
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                    break
                }
            }
        }
        while batch.len() < self.config.batch_size {
            match self.bulk.try_recv() {
                Ok(command) => batch.push((Channel::Bulk, command)),
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                    break
                }
            }
        }
    }

    /// Runs one batch in one transaction, then answers every waiter.
    ///
    /// A statement that fails aborts the transaction: the whole batch rolls back and
    /// every waiter in it — including those whose statements had already succeeded — is
    /// told the same error. The actor itself never exits on a command error.
    async fn flush(&mut self, batch: Vec<(Channel, Command)>) {
        let started = Instant::now();
        let mut high = 0_usize;
        let mut bulk = 0_usize;
        for (channel, _) in &batch {
            match channel {
                Channel::High => high += 1,
                Channel::Bulk => bulk += 1,
            }
        }

        let mut transaction = match self.pool.begin().await {
            Ok(transaction) => transaction,
            Err(error) => {
                let error = StoreError::from(error);
                for (_, command) in batch {
                    let (_, reply) = command.into_parts();
                    reply.fail(error.clone());
                }
                self.metrics.failed_batches.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%error, "db writer could not begin a transaction");
                return;
            }
        };

        let mut pending: Vec<(Reply, Outcome, Vec<InvalidationKey>)> =
            Vec::with_capacity(batch.len());
        let mut failure: Option<StoreError> = None;
        for (_, command) in batch {
            let (mutation, reply) = command.into_parts();
            if let Some(error) = &failure {
                // Postgres aborted the transaction; this statement would only repeat
                // "current transaction is aborted".
                reply.fail(error.clone());
                continue;
            }
            match Self::execute(&mut transaction, mutation).await {
                Ok((outcome, keys)) => pending.push((reply, outcome, keys)),
                Err(error) => {
                    reply.fail(error.clone());
                    failure = Some(error);
                }
            }
        }

        match failure {
            Some(error) => {
                let _ = transaction.rollback().await;
                for (reply, _, _) in pending {
                    reply.fail(error.clone());
                }
                self.metrics.failed_batches.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%error, high, bulk, "db writer batch rolled back");
            }
            None => match transaction.commit().await {
                Ok(()) => {
                    // One call per committed batch, after the commit: nothing below this
                    // line may fail the batch, and a rolled-back batch invalidates nothing.
                    let mut keys = Vec::new();
                    for (_, _, dirty) in &pending {
                        keys.extend(dirty.iter().cloned());
                    }
                    self.invalidate(&keys);
                    for (reply, outcome, _) in pending {
                        reply.send(outcome);
                    }
                    self.metrics.batches.fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .high_flushed
                        .fetch_add(high as u64, Ordering::Relaxed);
                    self.metrics
                        .bulk_flushed
                        .fetch_add(bulk as u64, Ordering::Relaxed);
                    tracing::debug!(
                        high,
                        bulk,
                        ms = started.elapsed().as_millis(),
                        "writer flush"
                    );
                }
                Err(error) => {
                    let error = StoreError::from(error);
                    for (reply, _, _) in pending {
                        reply.fail(error.clone());
                    }
                    self.metrics.failed_batches.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(%error, high, bulk, "db writer commit failed");
                }
            },
        }
    }

    /// Tells the cache what a committed batch dirtied, without letting it matter.
    ///
    /// The sink is synchronous by contract, and the contract is the opposite of a queue:
    /// it must return quickly. A panic in it is caught and logged at error, because a bug
    /// in a cache adapter must not stop the one writer the process has.
    fn invalidate(&self, keys: &[InvalidationKey]) {
        let Some(sink) = self.config.sink.as_ref() else {
            return;
        };
        if keys.is_empty() {
            return;
        }
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| sink.invalidate(keys))) {
            let message = payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_owned())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_owned());
            tracing::error!(
                panic = %message,
                keys = keys.len(),
                "invalidation sink panicked; the write actor keeps running"
            );
        }
    }

    /// Runs one statement on the batch's connection.
    ///
    /// Every statement is the same SQL the direct-pool function in [`crate::drive`] runs;
    /// they share the `*_tx` helpers so the two paths cannot drift apart. The second half
    /// of the answer is the keys this statement dirtied, held until the batch commits.
    #[allow(
        clippy::too_many_lines,
        reason = "one arm per command, each arm the whole statement and its keys"
    )]
    async fn execute(
        transaction: &mut Transaction<'_, Postgres>,
        mutation: Mutation,
    ) -> Result<(Outcome, Vec<InvalidationKey>), StoreError> {
        let connection: &mut PgConnection = &mut *transaction;
        match mutation {
            Mutation::CreateFolder {
                account,
                parent,
                name,
            } => {
                let folder = drive::create_folder_tx(connection, &account, parent, &name)
                    .await
                    .map_err(StoreError::from)?;
                let keys = vec![
                    InvalidationKey::new(&account, InvalidationKind::Folder, folder.id.to_string()),
                    InvalidationKey::parent_folder(&account, parent),
                ];
                Ok((Outcome::Folder(folder), keys))
            }
            Mutation::RenameFolder { account, id, name } => {
                let parent = drive::folder_parent_tx(connection, &account, id).await?;
                let renamed = drive::rename_folder_tx(connection, &account, id, &name)
                    .await
                    .map_err(StoreError::from)?;
                // The parent listing carries the name, so a rename dirties both.
                let keys = if renamed {
                    vec![
                        InvalidationKey::new(&account, InvalidationKind::Folder, id.to_string()),
                        InvalidationKey::parent_folder(&account, parent.flatten()),
                    ]
                } else {
                    Vec::new()
                };
                Ok((Outcome::Flag(renamed), keys))
            }
            Mutation::MoveFolder {
                account,
                id,
                parent,
            } => {
                let from = drive::folder_parent_tx(connection, &account, id).await?;
                match drive::move_folder_tx(connection, &account, id, parent).await {
                    Ok(()) => {
                        // Both listings changed: the folder left one and joined another.
                        let keys = vec![
                            InvalidationKey::new(
                                &account,
                                InvalidationKind::Folder,
                                id.to_string(),
                            ),
                            InvalidationKey::parent_folder(&account, from.flatten()),
                            InvalidationKey::parent_folder(&account, parent),
                        ];
                        Ok((Outcome::Flag(true), keys))
                    }
                    Err(MoveError::NotFound) => Ok((Outcome::Flag(false), Vec::new())),
                    Err(error) => Err(StoreError::from(error)),
                }
            }
            Mutation::DeleteFolder { account, id } => {
                let parent = drive::folder_parent_tx(connection, &account, id).await?;
                let digests = drive::delete_folder_tx(connection, &account, id)
                    .await
                    .map_err(StoreError::from)?;
                // `None` means the folder was not in this account: nothing was deleted.
                let keys = parent.map_or_else(Vec::new, |parent| {
                    vec![
                        InvalidationKey::new(&account, InvalidationKind::Folder, id.to_string()),
                        InvalidationKey::parent_folder(&account, parent),
                    ]
                });
                Ok((Outcome::Digests(digests), keys))
            }
            Mutation::CreateObject {
                account,
                folder,
                filename,
                mime_type,
                sha256,
                byte_size,
            } => {
                let object = drive::create_object_tx(
                    connection, &account, folder, &filename, &mime_type, &sha256, byte_size,
                )
                .await
                .map_err(StoreError::from)?;
                let keys = vec![
                    InvalidationKey::new(&account, InvalidationKind::Object, object.id.to_string()),
                    InvalidationKey::parent_folder(&account, folder),
                ];
                Ok((Outcome::FolderObject(object), keys))
            }
            Mutation::RenameObject {
                account,
                id,
                filename,
            } => {
                let renamed = drive::rename_object_tx(connection, &account, id, &filename)
                    .await
                    .map_err(StoreError::from)?;
                let keys = if renamed {
                    vec![InvalidationKey::new(
                        &account,
                        InvalidationKind::Object,
                        id.to_string(),
                    )]
                } else {
                    Vec::new()
                };
                Ok((Outcome::Flag(renamed), keys))
            }
            Mutation::MoveObject {
                account,
                id,
                folder,
            } => {
                let from = drive::object_parent_tx(connection, &account, id).await?;
                let moved = drive::move_object_tx(connection, &account, id, folder)
                    .await
                    .map_err(StoreError::from)?;
                let keys = if moved {
                    vec![
                        InvalidationKey::new(&account, InvalidationKind::Object, id.to_string()),
                        InvalidationKey::parent_folder(&account, from.flatten()),
                        InvalidationKey::parent_folder(&account, folder),
                    ]
                } else {
                    Vec::new()
                };
                Ok((Outcome::Flag(moved), keys))
            }
            Mutation::SetVisibility {
                account,
                id,
                visibility,
            } => {
                let set = drive::set_visibility_tx(connection, &account, id, visibility)
                    .await
                    .map_err(StoreError::from)?;
                let keys = object_key(&account, id, set);
                Ok((Outcome::Flag(set), keys))
            }
            Mutation::SetState { account, id, state } => {
                let set = drive::set_state_tx(connection, &account, id, state)
                    .await
                    .map_err(StoreError::from)?;
                let keys = object_key(&account, id, set);
                Ok((Outcome::Flag(set), keys))
            }
            Mutation::DeleteObject { account, id } => {
                let digest = drive::delete_object_tx(connection, &account, id)
                    .await
                    .map_err(StoreError::from)?;
                // The account's used-bytes total changed with the row.
                let keys = if digest.is_some() {
                    vec![
                        InvalidationKey::new(&account, InvalidationKind::Object, id.to_string()),
                        InvalidationKey::new(&account, InvalidationKind::Account, account.clone()),
                    ]
                } else {
                    Vec::new()
                };
                Ok((Outcome::Digest(digest), keys))
            }
            Mutation::AttachObject {
                account,
                object_id,
                status_id,
                alt_text,
                focus,
                blurhash,
            } => {
                let attachment = drive::attach_object_tx(
                    connection,
                    &account,
                    object_id,
                    status_id.as_deref(),
                    &alt_text,
                    focus.as_deref(),
                    blurhash.as_deref(),
                )
                .await
                .map_err(StoreError::from)?;
                let keys = attachment.as_ref().map_or_else(Vec::new, |attachment| {
                    vec![
                        InvalidationKey::new(
                            &account,
                            InvalidationKind::Attachment,
                            attachment.clone(),
                        ),
                        InvalidationKey::new(
                            &account,
                            InvalidationKind::Object,
                            object_id.to_string(),
                        ),
                    ]
                });
                Ok((Outcome::Digest(attachment), keys))
            }
        }
    }
}

/// The key for a file whose row changed, or nothing when the statement wrote no row.
fn object_key(account: &str, id: Uuid, wrote: bool) -> Vec<InvalidationKey> {
    if wrote {
        vec![InvalidationKey::new(
            account,
            InvalidationKind::Object,
            id.to_string(),
        )]
    } else {
        Vec::new()
    }
}

impl Channel {
    /// The queue's name, for logs and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.label()
    }
}

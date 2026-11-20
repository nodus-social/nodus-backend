//! Byte serving for the media surface.
//!
//! The catalogue lives in the database and the bytes live on disk, so serving is its own
//! router rather than a part of the API: an instance can then keep answering API requests
//! while a large file is read, and the media process can be restarted, resized or moved to
//! another host without touching the process that answers JSON.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path as UrlPath, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Router;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::{Mutex, Notify};

use nodus_server_store::media::{self, VariantRow};
use nodus_server_store::media_nodes;
use nodus_storage::{ByteRange, RangeError};

use crate::cluster::{self, placement, Member};
use crate::hash::hex;
use crate::{CachePolicy, Layer};

/// The bytes a media catalogue id resolves to, and where they are kept.
pub struct Serving {
    pool: PgPool,
    root: PathBuf,
    variants: PathBuf,
    /// This process's name in the membership table.
    node: String,
    /// Shared secret the peers present on the internal routes. `None` disables them.
    cluster_token: Option<String>,
    /// One in-flight peer copy per digest. A burst of misses for the same bytes asks the
    /// peers once; every other request waits for that copy and re-reads the file, rather
    /// than each fetching and writing the same file.
    inflight: Mutex<HashMap<String, Arc<Notify>>>,
    /// Peers a unit test names directly. The placement needs a database and these tests
    /// have none, so the one route that reads membership takes its peer list from here
    /// when it is set. Never populated outside `cfg(test)`.
    #[cfg(test)]
    peers: Mutex<Option<Vec<Member>>>,
}

impl Serving {
    /// Serve from this database and these directories.
    #[must_use]
    pub fn new(
        pool: PgPool,
        root: PathBuf,
        variants: PathBuf,
        node: String,
        cluster_token: Option<String>,
    ) -> Self {
        Self {
            pool,
            root,
            variants,
            node,
            cluster_token,
            inflight: Mutex::new(HashMap::new()),
            #[cfg(test)]
            peers: Mutex::new(None),
        }
    }

    /// Whether the `/internal/*` routes are registered at all.
    #[must_use]
    pub const fn cluster_enabled(&self) -> bool {
        self.cluster_token.is_some()
    }

    /// Reads `digest` from the first peer that has it, writes it here, and returns it.
    ///
    /// Read repair: this node owns the digest but has not received the bytes yet, so a
    /// peer that already has them fills the gap while the client waits. The single-flight
    /// map means a burst of misses for one digest asks the peers once; the rest wait for
    /// that copy and re-read the file instead of each starting their own.
    pub async fn copy_from_peers(&self, digest: &str, peers: &[Member]) -> Option<Vec<u8>> {
        if !is_digest(digest) || peers.is_empty() {
            return None;
        }
        // A copy may have landed between the caller's read and this call.
        if let Ok(bytes) = tokio::fs::read(self.root.join(digest)).await {
            return Some(bytes);
        }
        let token = self.cluster_token.as_deref()?;
        let (notify, leader) = {
            let mut inflight = self.inflight.lock().await;
            if let Some(existing) = inflight.get(digest) {
                (Arc::clone(existing), false)
            } else {
                let notify = Arc::new(Notify::new());
                inflight.insert(digest.to_owned(), Arc::clone(&notify));
                (notify, true)
            }
        };
        if !leader {
            // The notify can fire between the lookup above and this registration, so the
            // wait is bounded: wake on the copy, or read whatever is on disk when the
            // budget runs out and let the caller fall through.
            let _ = tokio::time::timeout(PEER_BUDGET, notify.notified()).await;
            return tokio::fs::read(self.root.join(digest)).await.ok();
        }
        let copied = self.fetch_from(peers, token, digest).await;
        if let Some(bytes) = copied.as_deref() {
            if let Err(error) = write_atomically(&self.root, digest, bytes).await {
                tracing::warn!(%error, %digest, "could not keep bytes fetched from a peer");
            }
        }
        {
            let mut inflight = self.inflight.lock().await;
            inflight.remove(digest);
        }
        // After the write and after the entry is gone, so a waiter that wakes either
        // finds the file or becomes the next leader.
        notify.notify_waiters();
        copied
    }

    /// Asks the peers in order, each within [`cluster::PEER_DEADLINE`], all within
    /// [`PEER_BUDGET`]. A peer that is down or does not have the digest is skipped.
    async fn fetch_from(&self, peers: &[Member], token: &str, digest: &str) -> Option<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + PEER_BUDGET;
        for peer in peers {
            if peer.endpoint.is_empty() {
                continue;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                tracing::debug!(%digest, "the peer budget ran out before the next member");
                break;
            }
            match tokio::time::timeout(remaining, cluster::fetch(&peer.endpoint, token, digest))
                .await
            {
                Ok(Some(bytes)) => return Some(bytes),
                Ok(None) => {
                    tracing::debug!(peer = %peer.name, %digest, "a peer did not have the digest");
                }
                Err(_) => {
                    tracing::debug!(peer = %peer.name, %digest, "the peer budget ran out");
                    break;
                }
            }
        }
        None
    }

    /// Deletes `digest` here and on every other member.
    ///
    /// Every member is asked, not only the placement: a replica that stopped being the
    /// owner keeps its copy, and only a fan-out reaches it. Best effort, because the
    /// caller's answer is the same whether or not a peer was reachable.
    pub async fn delete_everywhere(&self, digest: &str, members: &[Member]) {
        remove_local(&self.root, digest).await;
        let Some(token) = self.cluster_token.as_deref() else {
            return;
        };
        for peer in members.iter().filter(|peer| peer.name != self.node) {
            if peer.endpoint.is_empty() {
                continue;
            }
            if !cluster::delete_peer(&peer.endpoint, token, digest).await {
                tracing::warn!(peer = %peer.name, %digest, "a peer did not confirm a media delete");
            }
        }
    }

    /// Spawns the replication of a digest that was just written here.
    ///
    /// Detached on purpose: the upload has already answered, and a peer that is down
    /// must not turn a stored upload into a failed one. Without a cluster token there is
    /// nobody to replicate to, so nothing is spawned at all.
    pub fn spawn_replication(self: &Arc<Self>, digest: &str) {
        if self.cluster_token.is_none() {
            return;
        }
        let serving = Arc::clone(self);
        let digest = digest.to_owned();
        tokio::spawn(async move {
            if let Some(peers) = serving.replication_peers(&digest).await {
                let Some(token) = serving.cluster_token.as_deref() else {
                    return;
                };
                serving.replicate_to(&digest, &peers, token).await;
            }
        });
    }

    /// Spawns replication to an explicit peer list, which is what the test above needs:
    /// the production path reads the membership from the database.
    #[doc(hidden)]
    pub fn spawn_replication_to(self: &Arc<Self>, digest: &str, peers: Vec<Member>) {
        let serving = Arc::clone(self);
        let digest = digest.to_owned();
        tokio::spawn(async move {
            let Some(token) = serving.cluster_token.as_deref() else {
                return;
            };
            serving.replicate_to(&digest, &peers, token).await;
        });
    }

    /// The placement members that should hold `digest`, this node excluded.
    ///
    /// `None` means "nothing to do": one member, no token, a membership read that
    /// failed, or a placement that names only this node. Single-node behaviour depends
    /// on that being cheap and silent.
    async fn replication_peers(self: &Arc<Self>, digest: &str) -> Option<Vec<Member>> {
        self.cluster_token.as_ref()?;
        let nodes = match media_nodes::members(&self.pool, cluster::MEMBER_MAX_AGE).await {
            Ok(nodes) => nodes,
            Err(error) => {
                tracing::warn!(%error, %digest, "could not read the membership to replicate");
                return None;
            }
        };
        if nodes.len() < 2 {
            return None;
        }
        let members: Vec<Member> = nodes
            .into_iter()
            .map(|node| Member {
                name: node.name,
                endpoint: node.endpoint,
            })
            .collect();
        let peers: Vec<Member> = placement(digest, &members, cluster::REPLICAS)
            .into_iter()
            .filter(|member| member.name != self.node && !member.endpoint.is_empty())
            .cloned()
            .collect();
        if peers.is_empty() {
            None
        } else {
            Some(peers)
        }
    }

    /// Sends one digest to each peer, retrying a failed send on a fixed schedule.
    ///
    /// The bytes are re-read from disk before every attempt: the task must never write a
    /// file this node no longer has, and the rename-into-place write means the read sees
    /// either the previous file or the whole new one. The whole loop is bounded by
    /// [`cluster::REPLICATION_BUDGET`], so a cluster of silent peers cannot leave a task
    /// per upload behind.
    async fn replicate_to(&self, digest: &str, peers: &[Member], token: &str) {
        let deadline = tokio::time::Instant::now() + cluster::REPLICATION_BUDGET;
        for peer in peers {
            let mut sent = false;
            let mut attempts = 0usize;
            for backoff in cluster::REPLICATION_BACKOFF {
                let Ok(bytes) = tokio::fs::read(self.root.join(digest)).await else {
                    tracing::debug!(%digest, "the local copy vanished before it was replicated");
                    return;
                };
                if hex(&Sha256::digest(&bytes)) != digest {
                    tracing::warn!(%digest, "the local copy does not hash to its digest");
                    return;
                }
                attempts += 1;
                if cluster::put(&peer.endpoint, token, digest, &bytes).await {
                    sent = true;
                    break;
                }
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                tokio::time::sleep(backoff.min(remaining)).await;
            }
            if !sent {
                tracing::warn!(
                    peer = %peer.name,
                    %digest,
                    attempts,
                    "could not replicate media to a peer"
                );
            }
        }
    }

    /// How many digests are mid-copy. A test uses this to prove the map does not leak an
    /// entry after a failed copy, which would make every later miss for it wait.
    #[doc(hidden)]
    pub async fn inflight_len(&self) -> usize {
        self.inflight.lock().await.len()
    }

    /// `/media/default-avatar.png`, `/media/{id}`, `/media/{id}/{layer}`.
    ///
    /// The `/internal/*` routes exist only when a cluster token is configured. With no
    /// token they are not registered at all, so they answer the same 404 an unknown path
    /// does rather than merely refusing the request.
    pub fn router(self: &Arc<Self>) -> Router {
        let public = Router::new()
            .route("/media/default-avatar.png", get(default_avatar))
            .route("/media/{id}", get(serve))
            .route("/media/{id}/{layer}", get(serve_variant))
            .with_state(self.clone());
        if self.cluster_token.is_none() {
            return public;
        }
        public.merge(self.internal_router())
    }

    fn internal_router(self: &Arc<Self>) -> Router {
        Router::new()
            .route(
                "/internal/media/{digest}",
                put(internal_put)
                    .get(internal_get)
                    .head(internal_head)
                    .delete(internal_delete),
            )
            .route("/internal/placement/{digest}", get(internal_placement))
            .layer(DefaultBodyLimit::max(MAX_INTERNAL_UPLOAD))
            .layer(middleware::from_fn_with_state(
                self.clone(),
                require_cluster_token,
            ))
            .with_state(self.clone())
    }
}

/// The picture an account shows before it chooses one.
const DEFAULT_AVATAR_SIZE: u32 = 400;
/// Neutral grey, so one picture works on both a light and a dark timeline.
const PLACEHOLDER_BACKGROUND: [u8; 4] = [214, 211, 209, 255];
const PLACEHOLDER_FIGURE: [u8; 4] = [168, 162, 158, 255];

/// `GET /media/default-avatar.png` — the picture every account starts with.
///
/// Generated rather than shipped as a file: the arithmetic is cheaper to keep correct than
/// a binary in the repository, and the shape can be tuned without a build-time image tool.
///
/// Only the picture has a default. An account with no banner answers an empty `header`, so
/// a client draws nothing there rather than a grey band pretending to be one.
pub async fn default_avatar() -> Response {
    static BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let bytes = BYTES.get_or_init(render_default_avatar);
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("image/png")),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=604800"),
            ),
        ],
        Body::from(bytes.clone()),
    )
        .into_response()
}

/// A square grey tile with a lighter head-and-shoulders silhouette.
fn render_default_avatar() -> Vec<u8> {
    let size = DEFAULT_AVATAR_SIZE;
    let centre = f64::from(size) / 2.0;
    let head_radius = f64::from(size) * 0.16;
    let head_centre = (centre, f64::from(size) * 0.38);
    let shoulders: [f64; 3] = [centre, f64::from(size) * 0.92, f64::from(size) * 0.30];

    let mut pixels = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let point = (f64::from(x) + 0.5, f64::from(y) + 0.5);
            let in_head = distance(point, head_centre) <= head_radius;
            let in_shoulders = distance(point, (shoulders[0], shoulders[1])) <= shoulders[2];
            let colour = if in_head || in_shoulders {
                PLACEHOLDER_FIGURE
            } else {
                PLACEHOLDER_BACKGROUND
            };
            pixels.extend_from_slice(&colour);
        }
    }

    let mut out = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(&mut out);
    use image::ImageEncoder as _;
    encoder
        .write_image(&pixels, size, size, image::ExtendedColorType::Rgba8)
        .expect("a generated RGBA buffer is a valid image");
    out
}

fn distance(a: (f64, f64), b: (f64, f64)) -> f64 {
    ((a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)).sqrt()
}

/// `GET /media/{id}` — original bytes, cached by digest.
///
/// A `Range` header is answered here exactly as it is on the internal route: both go through
/// [`slice`], so a client seeking in a large original gets one slice rather than the file.
pub async fn serve(
    State(serving): State<Arc<Serving>>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<String>,
) -> Response {
    original(&serving, &id, headers.get(header::RANGE)).await
}

/// The original for one id, shared by both public routes.
///
/// `serve_variant` falls back here when a layer is missing, so the range rules have to live
/// in one place that two handlers can reach rather than in the handler that happened to be
/// written first.
async fn original(
    serving: &Arc<Serving>,
    id: &str,
    range: Option<&HeaderValue>,
) -> Response {
    let Some(row) = catalogue(serving, id).await else {
        return not_found();
    };
    if suspended(serving, &row.account_id).await {
        return not_found();
    }
    if !row.original_pruned {
        let bytes = match tokio::fs::read(serving.root.join(&row.digest)).await {
            Ok(bytes) => Some(bytes),
            // A replica answers for bytes this node owns but has not written yet.
            Err(_) => copy_from_placement(serving, &row.digest).await,
        };
        if let Some(bytes) = bytes {
            return with_cache(
                bytes,
                &row.content_type,
                "public, max-age=31536000, immutable",
                range,
            );
        }
    }
    for layer in [Layer::Compressed, Layer::Preview] {
        if let Some(variant) = variant(serving, id, layer.as_str()).await {
            return variant_response(serving, variant, layer, range).await;
        }
    }
    not_found()
}

/// `GET /media/{id}/{layer}` — a generated preview/compressed/lossless variant.
pub async fn serve_variant(
    State(serving): State<Arc<Serving>>,
    headers: HeaderMap,
    UrlPath((id, layer)): UrlPath<(String, String)>,
) -> Response {
    let layer = match layer.as_str() {
        "preview" => Layer::Preview,
        "compressed" => Layer::Compressed,
        "lossless" => Layer::Lossless,
        _ => return not_found(),
    };
    // A variant is the same picture as its original, so a suspended account's media is
    // gone at every layer, not only at the one /media/{id} happens to answer.
    match catalogue(&serving, &id).await {
        Some(row) if suspended(&serving, &row.account_id).await => return not_found(),
        Some(_) => {}
        None => return not_found(),
    }
    if let Some(variant) = variant(&serving, &id, layer.as_str()).await {
        return variant_response(&serving, variant, layer, headers.get(header::RANGE)).await;
    }
    original(&serving, &id, headers.get(header::RANGE)).await
}

async fn catalogue(serving: &Serving, id: &str) -> Option<media::MediaRow> {
    match media::by_id(&serving.pool, id).await {
        Ok(row) => row,
        Err(error) => {
            tracing::error!(%error, %id, "the media catalogue could not be read");
            None
        }
    }
}

/// Whether the account that posted this media is suspended, in which case the bytes are
/// not served at all — a suspended account's pictures are part of what it posted.
async fn suspended(serving: &Serving, account_id: &str) -> bool {
    match nodus_server_store::accounts::is_deleted(&serving.pool, account_id).await {
        Ok(true) => return true,
        Ok(false) => {}
        Err(error) => tracing::error!(%error, "the account table could not be read"),
    }
    match nodus_server_store::remote_moderation::action_for_account(&serving.pool, account_id).await
    {
        Ok(action) => action.as_deref() == Some(nodus_server_store::remote_moderation::SUSPEND),
        Err(error) => {
            tracing::error!(%error, "the remote moderation table could not be read");
            false
        }
    }
}

async fn variant(serving: &Serving, id: &str, layer: &str) -> Option<VariantRow> {
    match media::variant(&serving.pool, id, layer).await {
        Ok(row) => row,
        Err(error) => {
            tracing::error!(%error, %id, %layer, "the media variants could not be read");
            None
        }
    }
}

async fn variant_response(
    serving: &Serving,
    variant: VariantRow,
    layer: Layer,
    range: Option<&HeaderValue>,
) -> Response {
    let Ok(bytes) = tokio::fs::read(serving.variants.join(&variant.digest)).await else {
        return not_found();
    };
    let cache = CachePolicy::default().cache_control(layer);
    with_cache(bytes, &variant.content_type, &cache, range)
}

/// A public answer: cached by digest, with the content type the catalogue recorded, and the
/// same slice rules the internal route follows.
///
/// The range is applied to whichever bytes this answer carries, so a client is never handed
/// a slice of a variant with the length of the original.
fn with_cache(
    bytes: Vec<u8>,
    content_type: &str,
    cache: &str,
    range: Option<&HeaderValue>,
) -> Response {
    let content_type = HeaderValue::from_str(content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    let cache = HeaderValue::from_str(cache)
        .unwrap_or_else(|_| HeaderValue::from_static("public, max-age=3600"));
    let mut response = sliced_response(slice(bytes, range));
    let out = response.headers_mut();
    out.insert(header::CONTENT_TYPE, content_type);
    out.insert(header::CACHE_CONTROL, cache);
    response
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Record not found").into_response()
}

/// The answer to a read that has already been passed between nodes once.
///
/// A distinct body from the ordinary miss, because an operator reading logs has to be able
/// to tell "nobody has this" from "this was refused so two nodes could not bounce it".
fn forwarded_too_far() -> Response {
    (StatusCode::NOT_FOUND, "forwarded too far").into_response()
}

/// The largest body an internal replica write will buffer. Originals are capped well
/// below this at upload; the limit here is defence against a peer that sends more.
const MAX_INTERNAL_UPLOAD: usize = 64 * 1024 * 1024;

/// How long a miss may spend asking peers in total. A cluster of dead nodes has to fall
/// through to the variant ladder and answer 404 quickly, not become a slow 404.
const PEER_BUDGET: Duration = Duration::from_secs(6);

/// The peers that should hold a digest, this node excluded, in placement order.
///
/// Returns nothing unless there is at least one other live member and a cluster token:
/// a single node must take exactly the path it took before placement existed.
async fn copy_from_placement(serving: &Serving, digest: &str) -> Option<Vec<u8>> {
    serving.cluster_token.as_ref()?;
    let nodes = match media_nodes::members(&serving.pool, cluster::MEMBER_MAX_AGE).await {
        Ok(nodes) => nodes,
        Err(error) => {
            tracing::error!(%error, %digest, "the media membership could not be read");
            return None;
        }
    };
    if nodes.len() < 2 {
        return None;
    }
    let members: Vec<Member> = nodes
        .into_iter()
        .map(|node| Member {
            name: node.name,
            endpoint: node.endpoint,
        })
        .collect();
    let peers: Vec<Member> = placement(digest, &members, cluster::REPLICAS)
        .into_iter()
        .filter(|member| member.name != serving.node)
        .cloned()
        .collect();
    if peers.is_empty() {
        return None;
    }
    serving.copy_from_peers(digest, &peers).await
}

/// Writes bytes beside the target and renames them into place.
///
/// The same path the internal PUT uses, so a reader of the directory (this process or a
/// peer fetching from it) sees either the previous state or the whole file, never a
/// half-written one under the digest's own name.
pub(crate) async fn write_atomically(
    root: &Path,
    digest: &str,
    bytes: &[u8],
) -> std::io::Result<()> {
    tokio::fs::create_dir_all(root).await?;
    let staged = root.join(format!(".{digest}.{}.part", ulid::Ulid::new()));
    if let Err(error) = tokio::fs::write(&staged, bytes).await {
        let _ = tokio::fs::remove_file(&staged).await;
        return Err(error);
    }
    if let Err(error) = tokio::fs::rename(&staged, root.join(digest)).await {
        let _ = tokio::fs::remove_file(&staged).await;
        return Err(error);
    }
    Ok(())
}

/// Removes one digest from this node, tolerating the file already being gone.
async fn remove_local(root: &Path, digest: &str) {
    match tokio::fs::remove_file(root.join(digest)).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(%error, %digest, "could not delete an internal media file");
        }
    }
}

/// What one digest resolves to, for an operator or a peer checking its own view.
///
/// `replicas` is the whole placement, best first, so it always starts with `owner`; with
/// `R = 2` it names the owner and the one node that should also hold the bytes. `local`
/// says whether this process is that owner.
#[derive(Debug, Serialize)]
struct PlacementView {
    owner: String,
    replicas: Vec<String>,
    local: bool,
}

/// Rejects anything but a lowercase SHA-256 hex digest.
///
/// The digest becomes a file name, so this is also what keeps `..` and a slash out of the
/// path: a peer cannot choose where a write lands.
fn is_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Constant-time comparison for the cluster token.
///
/// Length is compared first because a length difference is not a secret: the token's
/// length is fixed by configuration, not guessed byte by byte from the response time.
fn token_matches(expected: &str, presented: &str) -> bool {
    let (expected, presented) = (expected.as_bytes(), presented.as_bytes());
    if expected.len() != presented.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in expected.iter().zip(presented) {
        difference |= left ^ right;
    }
    difference == 0
}

/// Every `/internal/*` request carries the shared secret.
async fn require_cluster_token(
    State(serving): State<Arc<Serving>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let expected = serving.cluster_token.as_deref().unwrap_or_default();
    let presented = headers
        .get("x-nodus-cluster")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !token_matches(expected, presented) {
        return (StatusCode::UNAUTHORIZED, "Invalid cluster token").into_response();
    }
    next.run(request).await
}

/// `PUT /internal/media/{digest}` — a peer stores bytes this node owns.
///
/// The body is verified against the digest before anything is written, so a corrupt or
/// malicious send cannot occupy the address of content it does not match. The write lands
/// in the same directory as the target and is renamed into place, so a reader sees either
/// the previous state or the whole new file, never a partial one.
async fn internal_put(
    State(serving): State<Arc<Serving>>,
    UrlPath(digest): UrlPath<String>,
    body: Bytes,
) -> Response {
    if !is_digest(&digest) {
        return (
            StatusCode::BAD_REQUEST,
            "digest must be 64 lowercase hex characters",
        )
            .into_response();
    }
    if hex(&Sha256::digest(&body)) != digest {
        return (StatusCode::BAD_REQUEST, "digest does not match the body").into_response();
    }
    let target = serving.root.join(&digest);
    if tokio::fs::try_exists(&target).await.unwrap_or(false) {
        return StatusCode::OK.into_response();
    }
    match write_atomically(&serving.root, &digest, &body).await {
        Ok(()) => {
            // The answer is already earned: the bytes are on this node's disk. The
            // replicas are brought up to date behind it, so a dead peer cannot turn a
            // stored upload into a failed one.
            serving.spawn_replication(&digest);
            StatusCode::CREATED.into_response()
        }
        Err(error) => {
            tracing::error!(%error, %digest, "could not write an internal media file");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `GET /internal/media/{digest}` — raw bytes, with no catalogue check.
///
/// A peer may hold what this node does not: the miss is answered by fetching the digest
/// from its placement, and the answer says so with `X-Internal-Forwarded`. A request that
/// already carries that header is never forwarded again — two nodes that each believe the
/// other holds the digest would otherwise hand it back and forth until the budget ran out.
async fn internal_get(
    State(serving): State<Arc<Serving>>,
    UrlPath(digest): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    if !is_digest(&digest) {
        return not_found();
    }
    let (bytes, forwarded) = if headers.contains_key(cluster::FORWARDED_HEADER) {
        // This request has already been passed on once: answer from here or not at all.
        // Passing it on again is exactly how two nodes would keep bouncing it.
        match tokio::fs::read(serving.root.join(&digest)).await {
            Ok(bytes) => (bytes, false),
            Err(_) => return forwarded_too_far(),
        }
    } else {
        // Membership lives in a database these unit tests do not have, so a test names
        // the peers it wants asked. In production this is `None` and the placement
        // decides, which is the only path a real node ever takes.
        #[cfg(test)]
        let peers = serving.peers.lock().await.clone();
        #[cfg(not(test))]
        let peers: Option<Vec<Member>> = None;
        match internal_bytes(&serving, &digest, peers.as_deref()).await {
            Some(found) => found,
            None => return not_found(),
        }
    };
    internal_response(bytes, headers.get(header::RANGE), forwarded)
}

/// The bytes for an internal read: local when they are here, otherwise one fetch from a
/// peer. The bool is whether a peer served them.
///
/// `peers` is `None` in production, where the placement decides. A test names the peers
/// instead, because reading membership needs a database and these tests have none.
async fn internal_bytes(
    serving: &Serving,
    digest: &str,
    peers: Option<&[Member]>,
) -> Option<(Vec<u8>, bool)> {
    if let Ok(bytes) = tokio::fs::read(serving.root.join(digest)).await {
        return Some((bytes, false));
    }
    let fetched = match peers {
        Some(peers) => serving.copy_from_peers(digest, peers).await,
        None => copy_from_placement(serving, digest).await,
    }?;
    Some((fetched, true))
}

/// One `Range` header resolved against one body.
struct Sliced {
    status: StatusCode,
    body: Vec<u8>,
    /// The inclusive slice the body carries, when the answer is a 206.
    span: Option<(u64, u64)>,
    /// The length of the whole representation, which a 206 and a 416 both have to name.
    total: u64,
}

/// Resolves at most one `bytes=` range against `bytes`.
///
/// A header nothing can parse is ignored, which is what RFC 9110 asks for: the client gets
/// the whole representation rather than an error it cannot act on. Both the public and the
/// internal answer go through this, so a seek follows the same rules on either route.
fn slice(bytes: Vec<u8>, range_header: Option<&HeaderValue>) -> Sliced {
    let total = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let parsed = range_header
        .and_then(|value| value.to_str().ok())
        .map(ByteRange::parse);
    let unsatisfiable = Sliced {
        status: StatusCode::RANGE_NOT_SATISFIABLE,
        body: Vec::new(),
        span: None,
        total,
    };
    match parsed {
        None | Some(Err(RangeError::Malformed)) => Sliced {
            status: StatusCode::OK,
            body: bytes,
            span: None,
            total,
        },
        Some(Err(RangeError::Unsatisfiable)) => unsatisfiable,
        Some(Ok(range)) => match range.resolve(total) {
            Ok((start, end)) => match bytes
                .get(
                    usize::try_from(start).unwrap_or(usize::MAX)
                        ..=usize::try_from(end).unwrap_or(usize::MAX),
                )
                .map(<[u8]>::to_vec)
            {
                Some(kept) => Sliced {
                    status: StatusCode::PARTIAL_CONTENT,
                    body: kept,
                    span: Some((start, end)),
                    total,
                },
                None => unsatisfiable,
            },
            Err(_) => unsatisfiable,
        },
    }
}

/// The status and body of a sliced answer, with the headers a ranged client reads: the length
/// actually sent, and the slice — or, for a 416, the length of the whole object, which is the
/// only part of a refused answer a client can use.
fn sliced_response(sliced: Sliced) -> Response {
    let Sliced {
        status,
        body,
        span,
        total,
    } = sliced;
    let sent = u64::try_from(body.len()).unwrap_or(u64::MAX);
    let mut response = (status, Body::from(body)).into_response();
    let out = response.headers_mut();
    out.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Ok(value) = HeaderValue::from_str(&sent.to_string()) {
        out.insert(header::CONTENT_LENGTH, value);
    }
    let content_range = span
        .map(|(start, end)| format!("bytes {start}-{end}/{total}"))
        .or_else(|| {
            (status == StatusCode::RANGE_NOT_SATISFIABLE).then(|| format!("bytes */{total}"))
        });
    if let Some(value) = content_range.and_then(|text| HeaderValue::from_str(&text).ok()) {
        out.insert(header::CONTENT_RANGE, value);
    }
    response
}

/// The internal answer: octet-stream, an honest length, one range with its 206/416, and
/// the forwarded marker when the bytes came from a peer.
fn internal_response(
    bytes: Vec<u8>,
    range_header: Option<&HeaderValue>,
    forwarded: bool,
) -> Response {
    let mut response = sliced_response(slice(bytes, range_header));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if forwarded {
        response
            .headers_mut()
            .insert(cluster::FORWARDED_HEADER, HeaderValue::from_static("1"));
    }
    response
}

/// `HEAD /internal/media/{digest}` — presence without reading the file.
async fn internal_head(
    State(serving): State<Arc<Serving>>,
    UrlPath(digest): UrlPath<String>,
) -> Response {
    if !is_digest(&digest) {
        return not_found();
    }
    match tokio::fs::metadata(serving.root.join(&digest)).await {
        Ok(metadata) if metadata.is_file() => StatusCode::OK.into_response(),
        _ => not_found(),
    }
}

/// `DELETE /internal/media/{digest}` — fan out to every member, and stay idempotent
/// because a peer may retry a delete and the absence of the file is the outcome it wants
/// either way.
///
/// Every member is asked rather than only the placement: an old replica can predate a
/// membership change and keep bytes nobody would ever route to again. A peer that already
/// received this delete passes it on with the fan-out marker, so the request does not
/// bounce between nodes.
async fn internal_delete(
    State(serving): State<Arc<Serving>>,
    UrlPath(digest): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    if is_digest(&digest) {
        let members = if headers.contains_key(cluster::NO_FANOUT_HEADER) {
            Vec::new()
        } else {
            match media_nodes::members(&serving.pool, cluster::MEMBER_MAX_AGE).await {
                Ok(nodes) => nodes
                    .into_iter()
                    .map(|node| Member {
                        name: node.name,
                        endpoint: node.endpoint,
                    })
                    .collect(),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        %digest,
                        "could not read the membership to fan out a delete"
                    );
                    Vec::new()
                }
            }
        };
        serving.delete_everywhere(&digest, &members).await;
    }
    StatusCode::NO_CONTENT.into_response()
}

/// `GET /internal/placement/{digest}` — where this cluster thinks a digest belongs.
async fn internal_placement(
    State(serving): State<Arc<Serving>>,
    UrlPath(digest): UrlPath<String>,
) -> Response {
    let nodes = match media_nodes::members(&serving.pool, cluster::MEMBER_MAX_AGE).await {
        Ok(nodes) => nodes,
        Err(error) => {
            tracing::error!(%error, "the media membership could not be read");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let members: Vec<Member> = nodes
        .into_iter()
        .map(|node| Member {
            name: node.name,
            endpoint: node.endpoint,
        })
        .collect();
    let placed = placement(&digest, &members, cluster::REPLICAS);
    let owner = placed
        .first()
        .map_or_else(String::new, |member| member.name.clone());
    let local = owner == serving.node;
    axum::Json(PlacementView {
        owner,
        replicas: placed.iter().map(|member| member.name.clone()).collect(),
        local,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use tower::ServiceExt;

    use super::{
        default_avatar, Serving, DEFAULT_AVATAR_SIZE, PEER_BUDGET, PLACEHOLDER_BACKGROUND,
        PLACEHOLDER_FIGURE,
    };
    use crate::cluster::{self, Member};

    fn temp_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("nodus-media-{}", ulid::Ulid::new()))
    }

    fn serving_in(root: &std::path::Path, node: &str, cluster_token: Option<&str>) -> Arc<Serving> {
        let store =
            nodus_server_store::Store::connect_lazy("postgres://nodus:nodus@127.0.0.1:1/nodus", 1);
        Arc::new(Serving::new(
            store.pool().clone(),
            root.to_path_buf(),
            root.join("variants"),
            node.to_owned(),
            cluster_token.map(str::to_owned),
        ))
    }

    fn digest_of(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        crate::hash::hex(&sha2::Sha256::digest(bytes))
    }

    /// A serving state with no database: these tests assert routing and token handling, and
    /// the one route that reads membership is only asserted where it must refuse a request.
    fn serving(cluster_token: Option<&str>) -> Arc<Serving> {
        serving_in(&temp_root(), "test-node", cluster_token)
    }

    /// Just enough HTTP to be a real network neighbour: one request per connection, with
    /// the behaviour the test needs. No container and no second service.
    #[derive(Clone)]
    enum Behaviour {
        Serve(Vec<u8>),
        Gone,
        Silent,
    }

    struct FakePeer {
        endpoint: String,
        hits: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl FakePeer {
        async fn spawn(behaviour: Behaviour) -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind a fake peer");
            let address = listener.local_addr().expect("fake peer address");
            let hits = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&hits);
            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    counter.fetch_add(1, Ordering::SeqCst);
                    let behaviour = behaviour.clone();
                    tokio::spawn(async move {
                        let mut buffer = [0u8; 2048];
                        let _ = stream.read(&mut buffer).await;
                        match behaviour {
                            Behaviour::Silent => {
                                // Accept, read, then never answer: only the caller's
                                // deadline can end this request.
                                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                            }
                            Behaviour::Serve(bytes) => {
                                let head = format!(
                                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                                    bytes.len()
                                );
                                let _ = stream.write_all(head.as_bytes()).await;
                                let _ = stream.write_all(&bytes).await;
                                let _ = stream.shutdown().await;
                            }
                            Behaviour::Gone => {
                                let _ = stream
                                    .write_all(
                                        b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                                    )
                                    .await;
                                let _ = stream.shutdown().await;
                            }
                        }
                    });
                }
            });
            Self {
                endpoint: format!("http://{address}"),
                hits,
            }
        }

        fn requests(&self) -> usize {
            self.hits.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn member(&self, name: &str) -> Member {
            Member {
                name: name.to_owned(),
                endpoint: self.endpoint.clone(),
            }
        }
    }

    async fn status_of(token: Option<&str>, request: HttpRequest<Body>) -> StatusCode {
        serving(token)
            .router()
            .oneshot(request)
            .await
            .expect("router response")
            .status()
    }

    #[tokio::test]
    async fn a_wrong_cluster_token_is_unauthorised() {
        let request = HttpRequest::builder()
            .uri("/internal/placement/00")
            .header("x-nodus-cluster", "not-the-token")
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            status_of(Some("the-token"), request).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn a_missing_cluster_token_is_unauthorised() {
        let request = HttpRequest::builder()
            .uri("/internal/media/00")
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            status_of(Some("the-token"), request).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn the_internal_routes_are_absent_without_a_token() {
        for uri in ["/internal/placement/00", "/internal/media/00"] {
            let request = HttpRequest::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request");
            assert_eq!(
                status_of(None, request).await,
                StatusCode::NOT_FOUND,
                "{uri} must look like an unknown path"
            );
        }
    }

    /// The default picture is only useful if a client can decode it, so the test decodes it.
    #[tokio::test]
    async fn the_default_avatar_is_a_square_png_with_a_figure() {
        let response = default_avatar().await;
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("body");
        let decoded = image::load_from_memory(&bytes).expect("decodable png");
        assert_eq!(decoded.width(), DEFAULT_AVATAR_SIZE);
        assert_eq!(decoded.height(), DEFAULT_AVATAR_SIZE);

        // A flat square would be indistinguishable from a failed load, so check the figure
        // is actually drawn: the middle of the head is the figure colour, the corner is not.
        let picture = decoded.to_rgba8();
        let head = picture.get_pixel(DEFAULT_AVATAR_SIZE / 2, 156);
        let corner = picture.get_pixel(2, 2);
        assert_eq!([head[0], head[1], head[2]], PLACEHOLDER_FIGURE[..3]);
        assert_eq!(
            [corner[0], corner[1], corner[2]],
            PLACEHOLDER_BACKGROUND[..3]
        );
    }

    #[tokio::test]
    async fn the_avatar_route_answers_a_png() {
        let response = default_avatar().await;
        assert_eq!(response.status(), 200);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok());
        assert_eq!(content_type, Some("image/png"));
    }

    /// A peer that never answers must not turn a miss into a slow miss.
    #[tokio::test]
    async fn a_miss_with_a_silent_peer_is_bounded_by_the_budget() {
        let peer = FakePeer::spawn(Behaviour::Silent).await;
        let serving = serving_in(&temp_root(), "test-node", Some("token"));
        let digest = digest_of(b"absent");
        let began = std::time::Instant::now();
        assert!(serving
            .copy_from_peers(&digest, &[peer.member("beta")])
            .await
            .is_none());
        let waited = began.elapsed();
        assert!(
            waited >= cluster::PEER_DEADLINE,
            "the peer was not waited for at all: {waited:?}"
        );
        assert!(
            waited < PEER_BUDGET + std::time::Duration::from_secs(1),
            "a silent peer exceeded the budget: {waited:?}"
        );
        assert_eq!(peer.requests(), 1);
        assert_eq!(
            serving.inflight_len().await,
            0,
            "a failed copy leaked an entry"
        );
    }

    /// A 404 from the replica is a miss, and leaves nothing half-written behind.
    #[tokio::test]
    async fn a_peer_without_the_digest_leaves_no_trace() {
        let peer = FakePeer::spawn(Behaviour::Gone).await;
        let root = temp_root();
        let serving = serving_in(&root, "test-node", Some("token"));
        let digest = digest_of(b"nowhere");
        assert!(serving
            .copy_from_peers(&digest, &[peer.member("beta")])
            .await
            .is_none());
        assert!(!tokio::fs::try_exists(root.join(&digest))
            .await
            .expect("exists"));
        assert_eq!(serving.inflight_len().await, 0);
    }

    /// Read repair keeps the bytes, and the next miss reads them instead of the network.
    #[tokio::test]
    async fn a_peer_copy_is_kept_and_asked_only_once() {
        let body = b"replicated bytes".to_vec();
        let digest = digest_of(&body);
        let peer = FakePeer::spawn(Behaviour::Serve(body.clone())).await;
        let root = temp_root();
        let serving = serving_in(&root, "test-node", Some("token"));
        let peers = [peer.member("beta")];
        assert_eq!(
            serving.copy_from_peers(&digest, &peers).await.as_deref(),
            Some(body.as_slice())
        );
        assert_eq!(
            tokio::fs::read(root.join(&digest)).await.expect("kept"),
            body
        );
        assert_eq!(
            serving.copy_from_peers(&digest, &peers).await.as_deref(),
            Some(body.as_slice())
        );
        assert_eq!(
            peer.requests(),
            1,
            "the second miss must read the local copy"
        );
        assert_eq!(serving.inflight_len().await, 0);
    }

    /// A burst of misses for one digest asks the peer once, not once per request.
    #[tokio::test]
    async fn concurrent_misses_copy_once() {
        let body = b"one copy".to_vec();
        let digest = digest_of(&body);
        let peer = FakePeer::spawn(Behaviour::Serve(body.clone())).await;
        let root = temp_root();
        let serving = serving_in(&root, "test-node", Some("token"));
        let peers = [peer.member("beta")];
        let (left, right) = tokio::join!(
            serving.copy_from_peers(&digest, &peers),
            serving.copy_from_peers(&digest, &peers)
        );
        assert_eq!(left.as_deref(), Some(body.as_slice()));
        assert_eq!(right.as_deref(), Some(body.as_slice()));
        assert_eq!(peer.requests(), 1, "the copy was made more than once");
        assert_eq!(serving.inflight_len().await, 0);
    }

    /// A delete reaches a live peer, and an unreachable one does not stop the answer.
    #[tokio::test]
    async fn a_delete_reaches_every_member_and_tolerates_a_dead_one() {
        let live = FakePeer::spawn(Behaviour::Serve(Vec::new())).await;
        let dead = FakePeer::spawn(Behaviour::Silent).await;
        let root = temp_root();
        let digest = digest_of(b"quarantined");
        let serving = serving_in(&root, "test-node", Some("token"));
        tokio::fs::create_dir_all(&root).await.expect("media root");
        tokio::fs::write(root.join(&digest), b"quarantined")
            .await
            .expect("seed a copy");
        let members = vec![
            Member {
                name: "test-node".to_owned(),
                endpoint: "http://127.0.0.1:1".to_owned(),
            },
            live.member("beta"),
            dead.member("gamma"),
        ];
        let began = std::time::Instant::now();
        serving.delete_everywhere(&digest, &members).await;
        assert!(
            began.elapsed() < cluster::PEER_DEADLINE * 3,
            "a dead member held up the delete"
        );
        assert!(!tokio::fs::try_exists(root.join(&digest))
            .await
            .expect("exists"));
        assert_eq!(live.requests(), 1, "the live replica kept its copy");
        assert_eq!(dead.requests(), 1, "the dead member was never asked");
    }

    /// A sink a test can read back, so a warning is asserted on its text and its count
    /// rather than on the fact that nothing panicked.
    #[derive(Clone)]
    struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Sink {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log sink").extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The bytes of one digest, written here so the task has something to re-read.
    async fn seed_local(root: &std::path::Path, digest: &str, bytes: &[u8]) {
        tokio::fs::create_dir_all(root).await.expect("media root");
        tokio::fs::write(root.join(digest), bytes)
            .await
            .expect("seed a local copy");
    }

    /// One request through the internal router, with the status, headers and body kept so a
    /// test can assert on all three rather than on the status alone.
    async fn answer(
        serving: &Arc<Serving>,
        request: HttpRequest<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        use axum::http::header::HeaderMap;
        let response = serving
            .router()
            .oneshot(request)
            .await
            .expect("router response");
        let status = response.status();
        let headers: HeaderMap = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body")
            .to_vec();
        (status, headers, body)
    }

    /// A single `bytes=` range gives exactly that slice and the header a ranged client uses
    /// to place it; an impossible range is a 416 that still carries the length; a header
    /// nothing can parse is ignored, because RFC 9110 says a whole body beats an error.
    #[tokio::test]
    async fn an_internal_read_answers_one_range_exactly() {
        let body = b"0123456789abcdef".to_vec();
        let digest = digest_of(&body);
        let root = temp_root();
        seed_local(&root, &digest, &body).await;
        let serving = serving_in(&root, "test-node", Some("token"));
        let uri = format!("/internal/media/{digest}");

        let ranged = HttpRequest::builder()
            .uri(&uri)
            .header("x-nodus-cluster", "token")
            .header("range", "bytes=4-7")
            .body(Body::empty())
            .expect("request");
        let (status, headers, bytes) = answer(&serving, ranged).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(bytes, b"4567", "the range was not served as that slice");
        assert_eq!(
            headers.get("content-range").and_then(|v| v.to_str().ok()),
            Some("bytes 4-7/16")
        );
        assert_eq!(
            headers.get("content-length").and_then(|v| v.to_str().ok()),
            Some("4"),
            "the partial body did not declare its own length"
        );

        let beyond = HttpRequest::builder()
            .uri(&uri)
            .header("x-nodus-cluster", "token")
            .header("range", "bytes=99-")
            .body(Body::empty())
            .expect("request");
        let (status, headers, _) = answer(&serving, beyond).await;
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            headers.get("content-range").and_then(|v| v.to_str().ok()),
            Some("bytes */16"),
            "a 416 has to say how long the object is"
        );

        let rambling = HttpRequest::builder()
            .uri(&uri)
            .header("x-nodus-cluster", "token")
            .header("range", "bytes=lots")
            .body(Body::empty())
            .expect("request");
        let (status, _, bytes) = answer(&serving, rambling).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            bytes, body,
            "an unreadable range must not truncate the answer"
        );
    }

    /// The public answer for a body already in hand, which is what both `/media/{id}` and
    /// `/media/{id}/{layer}` return once they have the bytes. The catalogue needs a database
    /// this harness does not have, so the range rules are asserted on the response the route
    /// builds rather than through a router that would answer 404 first.
    async fn public_answer(
        body: &[u8],
        range: Option<&str>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let range = range.map(|value| {
            axum::http::HeaderValue::from_str(value).expect("a test range is a valid header")
        });
        let response = super::with_cache(
            body.to_vec(),
            "image/png",
            "public, max-age=31536000, immutable",
            range.as_ref(),
        );
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body")
            .to_vec();
        (status, headers, bytes)
    }

    /// A public read honours one `bytes=` range exactly as the internal route does: a slice
    /// with its `Content-Range`, a 416 that still carries the length, and the whole body for
    /// a header that is not one range — never an error a client cannot act on.
    #[tokio::test]
    async fn the_public_media_answer_honours_one_range() {
        let body = b"0123456789abcdef";

        let (status, headers, bytes) = public_answer(body, Some("bytes=0-3")).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(bytes, b"0123", "the range was not served as that slice");
        assert_eq!(
            headers.get("content-range").and_then(|v| v.to_str().ok()),
            Some("bytes 0-3/16")
        );
        assert_eq!(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
            Some("image/png"),
            "a partial answer kept its content type"
        );
        assert_eq!(
            headers.get("accept-ranges").and_then(|v| v.to_str().ok()),
            Some("bytes")
        );

        let (status, headers, bytes) = public_answer(body, Some("bytes=999999-")).await;
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            headers.get("content-range").and_then(|v| v.to_str().ok()),
            Some("bytes */16"),
            "a 416 has to say how long the object is"
        );
        assert!(bytes.is_empty(), "a 416 carries no body");

        let (status, headers, bytes) = public_answer(body, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, body, "an unranged read is the whole original");
        assert_eq!(
            headers.get("content-length").and_then(|v| v.to_str().ok()),
            Some("16")
        );
        assert!(
            headers.get("content-range").is_none(),
            "a 200 has no range to describe"
        );

        let (status, _, bytes) = public_answer(body, Some("bytes=lots")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            bytes, body,
            "an unreadable range must not truncate the answer"
        );
    }

    /// Bytes a peer served are marked, and a read that already carries the mark is refused
    /// where it lands: passing it on again is exactly how two nodes would bounce a digest
    /// neither of them holds, so the second hop must stop rather than forward.
    #[tokio::test]
    async fn a_peer_served_read_is_marked_and_a_marked_one_is_not_forwarded() {
        let body = b"only on beta".to_vec();
        let digest = digest_of(&body);
        let peer = crate::testpeer::Peer::spawn("beta").await;
        peer.seed(&digest, body.clone());

        let root = temp_root();
        let serving = serving_in(&root, "test-node", Some("token"));
        *serving.peers.lock().await = Some(vec![peer.member()]);
        let uri = format!("/internal/media/{digest}");

        let first = HttpRequest::builder()
            .uri(&uri)
            .header("x-nodus-cluster", "token")
            .body(Body::empty())
            .expect("request");
        let (status, headers, bytes) = answer(&serving, first).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, body, "the peer's bytes did not reach the caller");
        assert_eq!(
            headers
                .get("x-internal-forwarded")
                .and_then(|v| v.to_str().ok()),
            Some("1"),
            "a peer-served answer must say a peer served it"
        );
        assert_eq!(peer.gets(), 1);
        assert!(
            peer.seen().iter().all(|request| request.forwarded),
            "the outbound read must arrive marked, or the peer would forward it on again"
        );

        // A node that does not hold the digest, asked with the mark already set, answers
        // from itself or not at all — never with another hop to the peer that has it.
        let second = serving_in(&temp_root(), "test-node", Some("token"));
        *second.peers.lock().await = Some(vec![peer.member()]);
        let marked = HttpRequest::builder()
            .uri(&uri)
            .header("x-nodus-cluster", "token")
            .header("x-internal-forwarded", "1")
            .body(Body::empty())
            .expect("request");
        let (status, _, bytes) = answer(&second, marked).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            String::from_utf8_lossy(&bytes),
            "forwarded too far",
            "a refused forward must say what it refused"
        );
        assert_eq!(peer.gets(), 1, "the marked request was forwarded onward");
    }

    /// The upload's answer does not include the replication: the second member is asked,
    /// once, with the digest and the token — after the caller already had its 201.
    #[tokio::test]
    async fn a_stored_upload_is_replicated_to_the_second_member_once() {
        let body = b"replicate me".to_vec();
        let digest = digest_of(&body);
        let root = temp_root();
        seed_local(&root, &digest, &body).await;
        let serving = serving_in(&root, "test-node", Some("token"));
        let peer = crate::testpeer::Peer::spawn("beta").await;
        serving
            .replicate_to(&digest, &[peer.member()], "token")
            .await;
        let seen = peer.seen();
        assert_eq!(seen.len(), 1, "one PUT per digest: {seen:?}");
        assert_eq!(seen[0].method, "PUT");
        assert_eq!(seen[0].path, format!("/internal/media/{digest}"));
        assert_eq!(seen[0].token, "token");
        assert_eq!(peer.file(&digest).as_deref(), Some(body.as_slice()));
    }

    /// A digest that was deleted between the local write and the replication is not
    /// pushed anywhere: the task reads the file, it does not keep the uploaded body.
    #[tokio::test]
    async fn a_digest_that_is_no_longer_local_is_not_replicated() {
        let body = b"already gone".to_vec();
        let digest = digest_of(&body);
        let serving = serving_in(&temp_root(), "test-node", Some("token"));
        let peer = crate::testpeer::Peer::spawn("beta").await;
        serving
            .replicate_to(&digest, &[peer.member()], "token")
            .await;
        assert_eq!(peer.requests(), 0, "a missing local file was pushed");
    }

    /// A live upload answers 201 and returns before a silent replica is even waited for.
    #[tokio::test]
    async fn an_upload_to_a_dead_replica_is_still_created_and_answered_at_once() {
        let body = b"answered anyway".to_vec();
        let digest = digest_of(&body);
        let root = temp_root();
        let serving = serving_in(&root, "test-node", Some("token"));
        let request = HttpRequest::builder()
            .method("PUT")
            .uri(format!("/internal/media/{digest}"))
            .header("x-nodus-cluster", "token")
            .body(Body::from(body.clone()))
            .expect("request");
        let began = std::time::Instant::now();
        let response = serving
            .router()
            .oneshot(request)
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(
            began.elapsed() < std::time::Duration::from_millis(500),
            "the upload waited for the cluster"
        );

        // The detached task is what tries the replica; it must not hold the caller.
        let dead = FakePeer::spawn(Behaviour::Silent).await;
        let began = std::time::Instant::now();
        serving.spawn_replication_to(&digest, vec![dead.member("beta")]);
        assert!(
            began.elapsed() < std::time::Duration::from_millis(100),
            "spawning the replication waited for the peer"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(dead.requests(), 1, "the replica was never tried");
    }

    /// Three attempts, then exactly one warning. Nothing retries after the schedule is
    /// spent, because a later pass of the repair walk is what covers a peer that stayed
    /// down.
    #[tokio::test]
    async fn a_dead_replica_is_warned_about_once_after_three_attempts() {
        let body = b"nobody home".to_vec();
        let digest = digest_of(&body);
        let root = temp_root();
        seed_local(&root, &digest, &body).await;
        let serving = serving_in(&root, "test-node", Some("token"));
        let dead = FakePeer::spawn(Behaviour::Gone).await;

        let buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Sink(Arc::clone(&buffer));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let began = std::time::Instant::now();
        serving
            .replicate_to(&digest, &[dead.member("beta")], "token")
            .await;
        let waited = began.elapsed();
        drop(guard);

        assert_eq!(dead.requests(), cluster::REPLICATION_ATTEMPTS);
        assert!(
            waited < cluster::REPLICATION_BUDGET,
            "replication overran its budget: {waited:?}"
        );
        let logs = String::from_utf8(buffer.lock().expect("log buffer").clone()).expect("utf8");
        assert_eq!(
            logs.matches("could not replicate media to a peer").count(),
            1,
            "expected exactly one warning, got: {logs}"
        );
        assert!(logs.contains("WARN"), "the line was not a warning: {logs}");
    }
}

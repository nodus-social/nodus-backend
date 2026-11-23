//! What a request for a profile layer answers when the layer was never rendered.
//!
//! A picture chosen before the profile layers existed has no `avatar`/`header` variant,
//! and a replica's variant directory can be empty even when the catalogue row exists. The
//! media route has to keep such a profile working without ever answering a `*_static`
//! field with an animation, and it has to make the real layer exist for the next request.

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use nodus_server_core::Id;
use nodus_server_store::media::{self, VariantRow};
use nodus_server_store::Store;

use support::{create_account, run_db_test};

/// A photo large enough that both profile edges downscale it.
const SOURCE: (u32, u32) = (1600, 1200);

struct Fixture {
    root: PathBuf,
    variants: PathBuf,
    gif: Vec<u8>,
    preview: Vec<u8>,
}

impl Fixture {
    async fn new() -> Option<Self> {
        let gif = animated_gif().await?;
        let root = std::env::temp_dir().join(format!("nodus-profile-layers-{}", Id::new()));
        let variants = root.join("variants");
        tokio::fs::create_dir_all(&variants).await.ok()?;
        Some(Self {
            root,
            variants,
            gif,
            preview: b"the preview of the same picture".to_vec(),
        })
    }

    /// Stores the animation and a preview, exactly the shape of a row that predates the
    /// profile layers: only `preview` was ever generated.
    async fn store_picture(&self, store: &Store, account: &str) -> String {
        let id = Id::new().to_string();
        let digest = digest_of(&self.gif);
        tokio::fs::write(self.root.join(&digest), &self.gif)
            .await
            .expect("write original");
        sqlx::query(
            "INSERT INTO media_attachment \
             (id, account_id, digest, content_type, size, width, height) \
             VALUES ($1, $2, $3, 'image/gif', $4, $5, $6)",
        )
        .bind(&id)
        .bind(account)
        .bind(&digest)
        .bind(i64::try_from(self.gif.len()).expect("fits"))
        .bind(i32::try_from(SOURCE.0).expect("fits"))
        .bind(i32::try_from(SOURCE.1).expect("fits"))
        .execute(store.pool())
        .await
        .expect("insert attachment");
        let preview = digest_of(&self.preview);
        tokio::fs::write(self.variants.join(&preview), &self.preview)
            .await
            .expect("write preview");
        media::upsert_variant(
            store.pool(),
            &VariantRow {
                media_id: id.clone(),
                layer: "preview".to_owned(),
                max_edge: 1280,
                object_key: format!("media/{digest}/preview/{preview}"),
                content_type: "image/webp".to_owned(),
                digest: preview,
                size: i64::try_from(self.preview.len()).expect("fits"),
                width: None,
                height: None,
                expires_at: None,
                created_at: chrono::Utc::now(),
            },
        )
        .await
        .expect("insert preview");
        id
    }

    fn router(&self, store: &Store) -> axum::Router {
        let serving = nodus_server_media::serve::Serving::new(
            store.pool().clone(),
            self.root.clone(),
            self.variants.clone(),
            "test-node".to_owned(),
            None,
        );
        Arc::new(serving).router()
    }
}

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    let request = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    (status, content_type, bytes)
}

/// Waits for a render that a request started behind its answer.
async fn wait_for_layer(store: &Store, id: &str, layer: &str) -> Option<VariantRow> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Ok(Some(row)) = media::variant(store.pool(), id, layer).await {
            return Some(row);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

fn digest_of(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn read_variant(root: &Path, variant: &VariantRow) -> Vec<u8> {
    tokio::fs::read(root.join(&variant.digest))
        .await
        .expect("variant bytes")
}

#[tokio::test]
async fn an_avatar_with_only_a_preview_answers_it_and_renders_the_real_layer() {
    let Some(fixture) = Fixture::new().await else {
        return;
    };
    run_db_test(|store, _app| async move {
        let account = create_account(store.pool(), "layers").await;
        let id = fixture.store_picture(&store, &account).await;
        let media = fixture.router(&store);

        let (status, _, body) = get(&media, &format!("/media/{id}/avatar")).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a profile is never broken by a missing layer"
        );
        assert_eq!(body, fixture.preview, "the preview is already the picture");

        let avatar = wait_for_layer(&store, &id, "avatar")
            .await
            .expect("the request renders the layer behind its answer");
        let (status, content_type, body) = get(&media, &format!("/media/{id}/avatar")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some("image/webp"));
        assert_eq!(body, read_variant(&fixture.variants, &avatar).await);
        assert_ne!(
            body, fixture.preview,
            "the next request finds the real layer"
        );
    })
    .await;
}

#[tokio::test]
async fn a_still_layer_is_rendered_rather_than_answered_with_the_animation() {
    let Some(fixture) = Fixture::new().await else {
        return;
    };
    run_db_test(|store, _app| async move {
        let account = create_account(store.pool(), "still").await;
        let id = fixture.store_picture(&store, &account).await;
        let media = fixture.router(&store);

        let (status, content_type, body) = get(&media, &format!("/media/{id}/avatar_static")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some("image/webp"));
        assert_ne!(
            body, fixture.gif,
            "the still field must not answer the original animation"
        );
        assert_eq!(
            count_frames(&body),
            1,
            "an animated answer would defeat the whole field"
        );

        // The header has no variants at all, which is the older shape: both header fields
        // must still resolve, and the still one must still be one frame.
        let (status, _, _) = get(&media, &format!("/media/{id}/header")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, content_type, body) = get(&media, &format!("/media/{id}/header_static")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some("image/webp"));
        assert_eq!(count_frames(&body), 1);
    })
    .await;
}

#[tokio::test]
async fn the_rendered_layers_are_the_profile_sizes() {
    let Some(fixture) = Fixture::new().await else {
        return;
    };
    run_db_test(|store, _app| async move {
        let account = create_account(store.pool(), "edges").await;
        let id = fixture.store_picture(&store, &account).await;
        let media = fixture.router(&store);

        // The animated field starts the render behind its answer; the still one renders
        // before answering, so both layers exist once the header request returns.
        let (status, _, _) = get(&media, &format!("/media/{id}/avatar")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = get(&media, &format!("/media/{id}/header_static")).await;
        assert_eq!(status, StatusCode::OK);

        let avatar = wait_for_layer(&store, &id, "avatar")
            .await
            .expect("avatar layer");
        let header = wait_for_layer(&store, &id, "header")
            .await
            .expect("header layer");
        assert_eq!(
            probe_edge(&read_variant(&fixture.variants, &avatar).await).await,
            400,
            "an avatar is drawn at 400 px"
        );
        assert_eq!(
            probe_edge(&read_variant(&fixture.variants, &header).await).await,
            1500,
            "a header is drawn at 1500 px"
        );
    })
    .await;
}

/// Frames a decoder reports for a WebP: `1` for a still, as ffprobe counts an `ANMF`
/// animation as a stream of frames.
fn count_frames(bytes: &[u8]) -> usize {
    if bytes.windows(4).any(|window| window == b"ANMF") {
        return bytes.windows(4).filter(|window| *window == b"ANMF").count();
    }
    1
}

/// The longest edge of the picture ffprobe reads from `bytes`.
async fn probe_edge(bytes: &[u8]) -> u32 {
    let path = std::env::temp_dir().join(format!("nodus-probe-{}", Id::new()));
    tokio::fs::write(&path, bytes)
        .await
        .expect("write probe input");
    let output = tokio::process::Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-select_streams",
            "v:0",
            "-show_entries",
            "stream=width,height",
            "-of",
            "csv=p=0",
        ])
        .arg(&path)
        .output()
        .await
        .expect("ffprobe");
    let _ = tokio::fs::remove_file(&path).await;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut edges = text
        .trim()
        .split(',')
        .filter_map(|field| field.trim().parse::<u32>().ok());
    edges.next().unwrap_or(0).max(edges.next().unwrap_or(0))
}

/// A 10 fps, 2 s animation at the fixture size, from the machine's own ffmpeg.
async fn animated_gif() -> Option<Vec<u8>> {
    let path = std::env::temp_dir().join(format!("nodus-profile-src-{}.gif", Id::new()));
    let status = tokio::process::Command::new("ffmpeg")
        .args(["-v", "error", "-y", "-f", "lavfi", "-i"])
        .arg(format!("testsrc=size={}x{}:rate=10", SOURCE.0, SOURCE.1))
        .args(["-t", "2", "-loop", "0"])
        .arg(&path)
        .status()
        .await
        .ok()?;
    if !status.success() {
        return None;
    }
    let bytes = tokio::fs::read(&path).await.ok()?;
    let _ = tokio::fs::remove_file(&path).await;
    Some(bytes)
}

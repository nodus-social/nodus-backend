//! Rendering the layers a profile picture needs, and deciding when a request must.
//!
//! A picture chosen before the profile layers existed has no `avatar`/`header` variants,
//! and a media replica holds its own variant directory, so a node can answer for a row
//! whose layer bytes it has never received. The request that misses a layer renders it
//! from the original: a still layer before the answer, so a `*_static` field can never
//! return the animation, and an animated layer behind the answer.

use std::path::Path;

use sha2::{Digest as _, Sha256};
use sqlx::PgPool;

use nodus_server_store::media::{self, MediaRow, VariantRow};

use crate::hash::hex;
use crate::{process, Kind, Layer, VariantSpec};

/// The two layers one profile slot needs: the one that may animate, and its still twin.
#[must_use]
pub const fn slot_layers(layer: Layer) -> Option<(Layer, Layer)> {
    match layer {
        Layer::Avatar | Layer::AvatarStatic => Some((Layer::Avatar, Layer::AvatarStatic)),
        Layer::Header | Layer::HeaderStatic => Some((Layer::Header, Layer::HeaderStatic)),
        Layer::Preview | Layer::Compressed | Layer::Lossless => None,
    }
}

/// Writes both layers of `layer`'s slot from `source`.
///
/// `source` has to be a local file: the callers fetch it from a peer first, because a
/// replica that owns the row does not necessarily own the original.
pub async fn write_layers(
    pool: &PgPool,
    variants: &Path,
    row: &MediaRow,
    kind: Kind,
    source: &Path,
    layer: Layer,
) -> Result<Vec<Layer>, String> {
    let Some((animated, still)) = slot_layers(layer) else {
        return Err("this layer is not a profile layer".to_owned());
    };
    let width = u32::try_from(row.width.unwrap_or(1)).unwrap_or(1).max(1);
    let height = u32::try_from(row.height.unwrap_or(1)).unwrap_or(1).max(1);
    let plan = crate::plan_profile(kind, width, height).map_err(|error| error.to_string())?;
    let mut written = Vec::new();
    for spec in plan
        .iter()
        .filter(|spec| spec.layer == animated || spec.layer == still)
    {
        render_layer(pool, variants, row, kind, source, spec).await?;
        written.push(spec.layer);
    }
    Ok(written)
}

/// Renders one profile layer for a media id whose original is at `source`.
///
/// Both layers of the slot are written so the next request — whichever twin it asks
/// for — finds a real variant rather than starting another render.
pub async fn render(
    pool: &PgPool,
    variants: &Path,
    media_id: &str,
    source: &Path,
    layer: Layer,
) -> Result<Vec<Layer>, String> {
    let row = media::by_id(pool, media_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the media row is gone".to_owned())?;
    let kind = Kind::from_content_type(&row.content_type);
    write_layers(pool, variants, &row, kind, source, layer).await
}

/// Encodes and stores one planned layer.
async fn render_layer(
    pool: &PgPool,
    variants: &Path,
    row: &MediaRow,
    kind: Kind,
    source: &Path,
    spec: &VariantSpec,
) -> Result<(), String> {
    let rendered = process::render_one(source, kind, spec)
        .await
        .map_err(|error| error.to_string())?;
    if let Some(reason) = rendered.still_reason {
        tracing::info!(
            reason = reason.as_str(),
            media = %row.id,
            layer = spec.layer.as_str(),
            "a profile picture was rendered still"
        );
    }
    let digest = hex(&Sha256::digest(&rendered.bytes));
    tokio::fs::write(variants.join(&digest), &rendered.bytes)
        .await
        .map_err(|error| error.to_string())?;
    // A profile layer is kept while the picture exists, so no expiry is written.
    media::upsert_variant(
        pool,
        &VariantRow {
            media_id: row.id.clone(),
            layer: spec.layer.as_str().to_owned(),
            max_edge: i64::from(spec.max_edge),
            object_key: crate::object_key(&row.digest, &digest, spec.layer),
            content_type: rendered.content_type.to_owned(),
            digest,
            size: i64::try_from(rendered.bytes.len()).unwrap_or(i64::MAX),
            width: None,
            height: None,
            expires_at: None,
            created_at: sqlx::types::chrono::Utc::now(),
        },
    )
    .await
    .map_err(|error| error.to_string())
}

/// Whether this node has the bytes for a variant row.
pub async fn has_bytes(variants: &Path, variant: &VariantRow) -> bool {
    tokio::fs::metadata(variants.join(&variant.digest))
        .await
        .is_ok()
}

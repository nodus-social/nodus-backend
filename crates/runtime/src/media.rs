//! Deleting what nobody references any more.
//!
//! The rule that decides what is junk lives in the store; this decides which files on
//! disk lost their last reference, so a digest shared by two posts survives as long as
//! either of them does.

use std::path::{Path, PathBuf};

use nodus_server_store::{media, Store};

#[must_use]
pub fn media_dir() -> PathBuf {
    std::env::var_os("NODUS_MEDIA_DIR").map_or_else(|| PathBuf::from("./media"), PathBuf::from)
}

#[must_use]
pub fn variants_dir() -> PathBuf {
    std::env::var_os("NODUS_MEDIA_VARIANTS_DIR")
        .map_or_else(|| media_dir().join("variants"), PathBuf::from)
}

async fn remove_unreferenced_variants(pool: &sqlx::PgPool, variants_root: &Path, digests: Vec<String>) {
    for digest in digests {
        if !media::variant_digest_referenced(pool, &digest)
            .await
            .unwrap_or(true)
        {
            let _ = tokio::fs::remove_file(variants_root.join(&digest)).await;
        }
    }
}

async fn remove_unreferenced_originals(pool: &sqlx::PgPool, media_root: &Path, digests: Vec<String>) {
    for digest in digests {
        if !media::original_digest_referenced(pool, &digest)
            .await
            .unwrap_or(true)
        {
            let _ = tokio::fs::remove_file(media_root.join(&digest)).await;
        }
    }
}

/// One pass over everything that expires.
pub async fn prune_media(store: &Store) {
    prune_media_in(store, &media_dir(), &variants_dir()).await;
}

/// One pass with explicit roots, so a test can own the directories it inspects.
pub async fn prune_media_in(store: &Store, media_root: &Path, variants_root: &Path) {
    let pool = store.pool();
    match media::delete_expired_variants(pool).await {
        Ok(digests) => remove_unreferenced_variants(pool, variants_root, digests).await,
        Err(error) => tracing::warn!(%error, "could not prune media variants"),
    }
    match media::expired_originals(pool).await {
        Ok(digests) => remove_unreferenced_originals(pool, media_root, digests).await,
        Err(error) => tracing::warn!(%error, "could not prune media originals"),
    }
    match media::delete_expired_unattached(pool).await {
        Ok(pruned) => {
            remove_unreferenced_variants(pool, variants_root, pruned.variant_digests).await;
            remove_unreferenced_originals(pool, media_root, pruned.original_digests).await;
        }
        Err(error) => tracing::warn!(%error, "could not prune unattached media"),
    }

    let auth = nodus_auth::store::PgAuthStore::new(pool.clone());
    if let Err(error) = auth.delete_expired_sessions().await {
        tracing::warn!(%error, "could not prune expired auth sessions");
    }
    if let Err(error) = auth.delete_expired_codes().await {
        tracing::warn!(%error, "could not prune expired oauth codes");
    }
    if let Err(error) = nodus_server_store::miauth::delete_expired(pool).await {
        tracing::warn!(%error, "could not prune expired miauth sessions");
    }
}

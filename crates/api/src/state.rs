//! Shared handler state: the store, the instance's public identity, and the key this
//! instance signs its own requests with.
//!
//! `Arc<Inner>` rather than several fields so cloning into each router is one pointer
//! increment; the config is read-only for the process's lifetime.

use std::sync::Arc;

use nodus_activitypub_client::{ActivityPub, HttpSigner};
use nodus_server_store::Store;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};

pub use nodus_server_core::instance::InstanceConfig;

#[derive(Debug)]
struct Inner {
    store: Store,
    instance: InstanceConfig,
    federation: Option<Arc<FederationKey>>,
}

/// Cloned into every handler; `Store` is a pool handle and `InstanceConfig` is small.
#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

/// The identity this instance signs its own reads with, as `{instance}/actor#main-key`.
///
/// Optional on purpose: a fresh instance has no key yet, and a server that refused to boot
/// over a missing key would turn degraded federation into an outage.
#[derive(Debug, Clone)]
pub struct FederationKey {
    signer: HttpSigner,
    public_pem: String,
}

impl FederationKey {
    /// Reads `NODUS_FEDERATION_KEY_PATH`, falling back to `NODUS_FEDERATION_KEY`.
    pub fn from_env(instance: &InstanceConfig) -> Option<Self> {
        let path = std::env::var("NODUS_FEDERATION_KEY_PATH")
            .ok()
            .filter(|path| !path.trim().is_empty());
        let pem = match path {
            Some(path) => match std::fs::read_to_string(&path) {
                Ok(pem) => pem,
                Err(error) => {
                    tracing::warn!(
                        %path,
                        %error,
                        "instance signing key is unreadable; outbound fetches stay unsigned"
                    );
                    return None;
                }
            },
            None => match std::env::var("NODUS_FEDERATION_KEY") {
                Ok(pem) if !pem.trim().is_empty() => pem,
                _ => {
                    tracing::info!(
                        "no instance signing key configured; outbound fetches stay unsigned"
                    );
                    return None;
                }
            },
        };
        let key = Self::from_pem(instance, &pem);
        if key.is_none() {
            tracing::warn!(
                "the configured instance signing key is not a PKCS#8 RSA key; \
                 outbound fetches stay unsigned"
            );
        }
        key
    }

    /// Builds the key whose id is `{instance}/actor#main-key`.
    #[must_use]
    pub fn from_pem(instance: &InstanceConfig, pem: &str) -> Option<Self> {
        let key_id = format!("{}#main-key", instance.url("/actor"));
        let signer = HttpSigner::from_pkcs8_pem(key_id, pem).ok()?;
        let public_pem = rsa::RsaPublicKey::from(&rsa::RsaPrivateKey::from_pkcs8_pem(pem).ok()?)
            .to_public_key_pem(LineEnding::LF)
            .ok()?;
        Some(Self { signer, public_pem })
    }

    #[must_use]
    pub fn signer(&self) -> &HttpSigner {
        &self.signer
    }

    #[must_use]
    pub fn public_pem(&self) -> &str {
        &self.public_pem
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        self.signer.key_id()
    }
}

impl AppState {
    #[must_use]
    pub fn new(store: Store, instance: InstanceConfig) -> Self {
        Self::with_federation(store, instance, None)
    }

    #[must_use]
    pub fn with_federation(
        store: Store,
        instance: InstanceConfig,
        federation: Option<FederationKey>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                instance,
                federation: federation.map(Arc::new),
            }),
        }
    }

    #[must_use]
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    #[must_use]
    pub fn instance(&self) -> &InstanceConfig {
        &self.inner.instance
    }

    #[must_use]
    pub fn federation(&self) -> Option<&FederationKey> {
        self.inner.federation.as_deref()
    }

    /// The reader for documents owned by no local account: signed when a key is set.
    #[must_use]
    pub fn fediverse_client(&self) -> ActivityPub {
        let client = ActivityPub::new();
        match self.federation() {
            Some(key) => client.with_signer(key.signer.clone()),
            None => client,
        }
    }
}

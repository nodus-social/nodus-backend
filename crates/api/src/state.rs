//! Shared handler state: the store, plus the instance's public identity.
//!
//! `Arc<Inner>` rather than several fields so cloning into each router is one pointer
//! increment; the config is read-only for the process's lifetime.

use std::sync::Arc;

use nodus_server_store::Store;

/// What this deployment calls itself.
#[derive(Debug, Clone)]
pub struct InstanceConfig {
    /// The domain users see in `@user@domain`, without scheme.
    pub domain: String,
    /// Absolute base URL for generated links, no trailing slash.
    pub base_url: String,
    pub title: String,
    pub description: String,
    pub contact_email: Option<String>,
    /// Version we advertise as the Mastodon API generation (docs/07-decisions.md D11).
    pub api_version: String,
    /// Our own build, reported separately so it never confuses a client.
    pub version: String,
}

impl InstanceConfig {
    /// The `acct` form of a local username.
    #[must_use]
    pub fn acct(&self, username: &str) -> String {
        format!("{username}@{}", self.domain)
    }

    /// Absolute URL for a path.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }
}

#[derive(Debug)]
struct Inner {
    store: Store,
    instance: InstanceConfig,
}

/// Cloned into every handler; `Store` is a pool handle and `InstanceConfig` is small.
#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

impl AppState {
    #[must_use]
    pub fn new(store: Store, instance: InstanceConfig) -> Self {
        Self { inner: Arc::new(Inner { store, instance }) }
    }

    #[must_use]
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    #[must_use]
    pub fn instance(&self) -> &InstanceConfig {
        &self.inner.instance
    }
}

//! Shared handler state: the store, plus the instance's public identity.
//!
//! `Arc<Inner>` rather than several fields so cloning into each router is one pointer
//! increment; the config is read-only for the process's lifetime.

use std::sync::Arc;

use nodus_server_store::Store;

pub use nodus_server_core::instance::InstanceConfig;

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
        Self {
            inner: Arc::new(Inner { store, instance }),
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
}

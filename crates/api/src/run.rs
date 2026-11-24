//! The process around the API surface: logging, storage, the loops that publish queued
//! work, and the listener.
//!
//! It lives here rather than in `services/api/src/main.rs` so the `nodus` binary can start
//! the same process without a second copy of it. `services/api` is a two-line wrapper and
//! `nodus api` calls the same function, which is what keeps the deployed unit and the new
//! entrypoint from drifting.

use std::future::Future;
use std::sync::Arc;

use anyhow::anyhow;
use axum::Router;
use nodus_auth::store::PgAuthStore;
use nodus_server_runtime::{self as runtime, Config};
use nodus_server_store::invalidate::{InvalidationSink, ValkeyInvalidator, DEFAULT_CHANNEL};
use nodus_server_store::Store;

use crate::{root_router, AppState, FederationKey};

/// What `nodus api` starts and where it listens, without binding.
///
/// The address is read from the environment this run path reads, so `--dry-run` prints the
/// API's own answer rather than a copy of it kept in the entrypoint.
#[must_use]
pub fn plan() -> (&'static str, &'static str, String) {
    let bind = std::env::var("NODUS_BIND").unwrap_or_else(|_| runtime::DEFAULT_BIND.to_owned());
    ("api", "nodus_server_api::run", bind)
}

/// Run the API as its own process, with its own logging, telemetry and stop signal.
///
/// # Errors
///
/// Fails when the configuration is wrong, the database cannot be prepared, or the
/// listener cannot bind.
pub async fn run() -> anyhow::Result<()> {
    let agent = runtime::init("api");
    let config = runtime::read().map_err(|error| anyhow!("{error}"))?;
    let telemetry = config
        .telemetry
        .clone()
        .map(|address| runtime::serve_telemetry(address, agent));

    let result = serve(config, runtime::shutdown()).await;
    runtime::stop_telemetry(telemetry).await;
    result
}

/// Serve the API on `config.bind` until `shutdown` resolves.
///
/// `aio` composes this with the media role in one process, so everything the process owns
/// — logging, telemetry, the stop signal — stays with [`run`] and only the serving half
/// is here.
///
/// # Errors
///
/// Fails when the database cannot be prepared or the listener cannot bind.
pub async fn serve<F>(config: Config, shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    // Mail is optional by construction: no SMTP means no sender, no worker and no
    // confirmation tokens, exactly as `NODUS_DRIVE_SHARE_SECRET` gates share links.
    // Enforcement cannot work without that sender, so a half-configured instance stops
    // here instead of accepting a switch that would refuse every new account forever.
    let mail = nodus_mail::sender_from_env();
    // A migrations-only run never serves requests, so it must not be blocked by a
    // switch that only matters to the serving path.
    if !config.migrate_only {
        if let Some(message) =
            missing_mail_sender(config.require_email_confirmation, mail.is_some())
        {
            return Err(anyhow!("{message}"));
        }
    }
    let store = runtime::prepare(&config)
        .await
        .map_err(|error| anyhow!("{error}"))?;
    let sink = invalidation_sink();
    if let Some(mail) = mail.clone() {
        tokio::spawn(nodus_auth::outbox::run(store.pool().clone(), mail));
    }
    // Push without a key is a degraded feature, not a broken API: log what an operator
    // must set and let the subscription verbs answer `501`. One line per process.
    if let Some(vapid) = config.vapid.clone() {
        tokio::spawn(crate::webpush::run(store.pool().clone(), vapid));
    } else {
        tracing::info!(
            "Web Push is off: set NODUS_VAPID_PUBLIC_KEY and NODUS_VAPID_PRIVATE_KEY to \
             accept subscriptions"
        );
    }
    // One variable turns the home timelines' fan-out on: with no `NODUS_VALKEY_URL` this is
    // `None`, and every home read is the SQL query it has always been.
    let home = crate::home::HomeShards::from_env();
    if config.migrate_only {
        tracing::info!("migrations applied");
        return Ok(());
    }

    // Queued posts publish and outbound activities leave from the process that also
    // serves requests: one pool, one set of signing keys, and no second deployable to
    // keep in step with this one.
    let federation = FederationKey::from_env(&config.instance);
    let state = AppState::with_federation_and_sink(
        store.clone(),
        config.instance.clone(),
        federation.clone(),
        sink.clone(),
    )
    .with_authorized_fetch(config.authorized_fetch)
    .with_require_email_confirmation(config.require_email_confirmation)
    .with_drive_share(crate::drive::share_links_configured())
    .with_account_delete_grace_days(config.account_delete_grace_days)
    .with_home(home.clone())
    .with_vapid(config.vapid.clone().map(Arc::new));
    if let Some(home) = home.as_ref() {
        // Removals another replica published are applied here; a single-process deployment
        // hears its own echo and finds nothing left to remove.
        crate::home::spawn_subscriber(home);
    }
    tokio::spawn(crate::schedules::run(state.clone()));
    // The subscription sweep lives here rather than in the pruning worker: it is an
    // outbound fetch, and the outbound guard, the client and the import path all live in
    // this process. One more loop on a clock, not a third service.
    tokio::spawn(crate::admin::blocklist::run(state.clone()));
    tokio::spawn(crate::outbox::run(state));

    tracing::info!(
        address = %config.bind,
        domain = %config.instance.domain,
        "api listening"
    );
    // The deploy's stop signal reaches the streams through a watch channel, so a
    // restarted unit closes EventSource connections instead of leaving them hanging on a
    // socket the new process does not own. The log line counts what was open at the
    // moment the signal arrived.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    nodus_server_store::live::install_shutdown(stop_rx);
    let shutdown = async move {
        shutdown.await;
        nodus_server_store::live::begin_shutdown();
        let _ = stop_tx.send(true);
    };
    nodus_server_transport::serve_http(
        &config.bind,
        router(&store, &config, federation, sink, home, mail.as_ref()),
        shutdown,
    )
    .await?;
    Ok(())
}

/// The startup contract for email-confirmation enforcement.
///
/// Enforcement without a sender cannot work: every new account would wait for a link
/// that is never sent. Such a configuration is refused before the database is opened.
fn missing_mail_sender(
    require_email_confirmation: bool,
    sender_configured: bool,
) -> Option<&'static str> {
    if require_email_confirmation && !sender_configured {
        Some(
            "NODUS_REQUIRE_EMAIL_CONFIRMATION is on but no mail sender is configured: \
             set NODUS_SMTP_HOST (and the rest of NODUS_SMTP_*) or turn the switch off",
        )
    } else {
        None
    }
}

/// The sink committed writes publish to, from the environment.
///
/// One variable decides it: `NODUS_VALKEY_URL` set means other replicas are told what
/// changed; unset means there is no cache to tell and every write behaves exactly as it
/// did before. The channel name is logged either way, because an operator debugging a
/// stale cache needs to know which channel to subscribe to. The unset case is logged by
/// [`crate::home::HomeShards::from_env`], which is what names the read path this deployment
/// takes.
fn invalidation_sink() -> Option<Arc<dyn InvalidationSink>> {
    let url = match std::env::var("NODUS_VALKEY_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => return None,
    };
    let channel = std::env::var("NODUS_VALKEY_CHANNEL")
        .ok()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_CHANNEL.to_owned());
    tracing::info!(channel = %channel, "invalidations publish to valkey");
    Some(Arc::new(ValkeyInvalidator::spawn(&url, &channel)))
}

/// Everything this service answers, in the order the router sees it.
fn router(
    store: &Store,
    config: &Config,
    federation: Option<FederationKey>,
    sink: Option<Arc<dyn InvalidationSink>>,
    home: Option<Arc<crate::home::HomeShards>>,
    mail: Option<&Arc<dyn nodus_mail::Transport>>,
) -> Router {
    let api = root_router(
        AppState::with_federation_and_sink(
            store.clone(),
            config.instance.clone(),
            federation,
            sink,
        )
        .with_authorized_fetch(config.authorized_fetch)
        .with_require_email_confirmation(config.require_email_confirmation)
        .with_drive_share(crate::drive::share_links_configured())
        .with_account_delete_grace_days(config.account_delete_grace_days)
        .with_home(home)
        .with_vapid(config.vapid.clone().map(Arc::new)),
    );
    let mut auth_state = nodus_auth::AppState::new(
        PgAuthStore::new(store.pool().clone()),
        nodus_auth::Config {
            domain: config.instance.domain.clone(),
            issuer: config.instance.base_url.clone(),
            secure_cookies: config.secure_cookies,
            registrations_open: config.registrations_open,
        },
    );
    if mail.is_some() {
        auth_state = auth_state.with_email_confirmation(nodus_auth::EmailConfirmation {
            base_url: config.instance.base_url.clone(),
        });
    }
    let auth = nodus_auth::router(auth_state);
    api.merge(auth)
}

#[cfg(test)]
mod tests {
    use super::missing_mail_sender;

    #[test]
    fn enforcement_without_a_sender_refuses_to_start() {
        let message = missing_mail_sender(true, false).expect("must refuse");
        assert!(message.contains("NODUS_SMTP_HOST"), "{message}");
        assert!(
            message.contains("NODUS_REQUIRE_EMAIL_CONFIRMATION"),
            "{message}"
        );
    }

    #[test]
    fn enforcement_with_a_sender_starts() {
        assert_eq!(missing_mail_sender(true, true), None);
    }

    #[test]
    fn the_default_switch_does_not_need_a_sender() {
        assert_eq!(missing_mail_sender(false, false), None);
    }
}

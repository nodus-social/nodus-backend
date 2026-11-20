//! The process around the recommendation engine's heavy half.
//!
//! Every outbound Mastodon request a browser does not make happens here, along with the
//! similarity and affinity recomputes, model fitting and retention. It shares the engine's
//! schema with the feed service and never calls it: the queue is the only thing between
//! them, so either can be restarted alone.
//!
//! It lives here rather than in `services/calc/src/main.rs` so `nodus calc` starts exactly
//! this process. The engine itself is `nodus_calculator` in the recommender's workspace;
//! this crate is only the part a deployed unit needs — configuration, the engine pool, the
//! worker, the maintenance clock and the stop signal. `services/calc` is a two-line
//! wrapper and `nodus calc` calls the same function.

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use nodus_calculator::handlers::{RefreshConfig, SyncConfig};
use nodus_calculator::maintenance::Maintenance;
use nodus_calculator::{Config, Registry, Worker};
use nodus_server_proto::control::control_server::Control;
use nodus_server_proto::control::{TriggerReply, TriggerRequest};
use nodus_server_runtime as runtime;
use nodus_store::crypto::TokenSealer;
use nodus_store::{engine_pool, ENGINE_SCHEMA};
use tonic::{Request, Response, Status};

/// Fifteen minutes is the arithmetic of the passes this enqueues: retention runs daily
/// and follow-through recounts are cheap, so anything faster is queue churn and anything
/// slower makes a fresh deployment wait hours for its first counters.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15 * 60);

struct WorkerControl {
    wake: Arc<tokio::sync::Notify>,
}

#[tonic::async_trait]
impl Control for WorkerControl {
    async fn trigger(
        &self,
        request: Request<TriggerRequest>,
    ) -> Result<Response<TriggerReply>, Status> {
        let work = request.into_inner().work;
        let accepted = work.is_empty() || work == "calc";
        if accepted {
            self.wake.notify_one();
        }
        Ok(Response::new(TriggerReply {
            accepted,
            detail: if accepted {
                "a maintenance tick is queued".to_owned()
            } else {
                format!("this service does not do {work:?}")
            },
        }))
    }
}

/// Run the calculator as its own process, with its own logging, telemetry and stop signal.
///
/// # Errors
///
/// Fails when the configuration is wrong, the database cannot be reached, the token key is
/// missing, or the control listener cannot bind.
pub async fn run() -> anyhow::Result<()> {
    serve().await.map_err(|error| anyhow::anyhow!("{error}"))
}

/// What `nodus calc` starts and where it listens, without binding.
///
/// The address is read from the environment this run path reads, so `--dry-run` prints the
/// worker's own answer rather than a copy of it kept in the entrypoint.
#[must_use]
pub fn plan() -> (&'static str, &'static str, String) {
    let listen = match (
        std::env::var("NODUS_TELEMETRY_SOCKET"),
        std::env::var("NODUS_TELEMETRY_BIND"),
    ) {
        (Ok(socket), _) => format!("the control socket {socket}"),
        (_, Ok(address)) => format!("the control address {address}"),
        _ => "nothing (no NODUS_TELEMETRY_SOCKET or NODUS_TELEMETRY_BIND)".to_owned(),
    };
    ("calc", "nodus_server_calc::run", listen)
}

async fn serve() -> Result<(), Box<dyn Error>> {
    let agent = runtime::init("calc");
    let serving = runtime::read()?;

    // The engine reads its own variable names; a deployment that only names the database
    // once must not silently point this service at a different one.
    if std::env::var_os("DATABASE_URL").is_none() {
        std::env::set_var("DATABASE_URL", &serving.database_url);
    }
    let config = Config::from_env()?;
    config.validate()?;

    let pool = engine_pool(&serving.database_url, config.pool_size, ENGINE_SCHEMA).await?;
    if serving.migrate_only {
        tracing::info!("migrations applied");
        return Ok(());
    }

    // The calculator opens tokens the feed service sealed. A deployment that forgot the
    // key cannot sync anyone, and saying so now beats a queue full of failures.
    let Ok(encoded) = std::env::var("TOKEN_ENC_KEY") else {
        return Err("TOKEN_ENC_KEY is not set; the calculator cannot sync any user".into());
    };
    let sealer = Arc::new(TokenSealer::from_base64(&encoded)?);

    let refresh = RefreshConfig::new(Arc::clone(&sealer), config.max_rps_per_host)
        .with_budget_fraction(config.budget_fraction)
        .with_post_retention_days(u32::from(config.post_retention_days));
    let sync = SyncConfig::new(sealer, config.max_rps_per_host)
        .with_budget_fraction(config.budget_fraction);

    // One budget for the process, shared across every crawl handler and through Redis when
    // it is configured: the per-host rate belongs to the instance being crawled, not to a
    // handler or a replica.
    let rate = sync.budget_rate();
    let budget: Arc<dyn nodus_cache::Budget> = if let Some(url) = config.redis_url.as_deref() {
        Arc::new(nodus_cache::RedisBudget::connect(url, rate).await?)
    } else {
        tracing::warn!("no shared request budget configured; per-host budgets are per process");
        Arc::new(nodus_cache::InMemoryBudget::with_rate(
            sync.effective_rps(),
            5,
        ))
    };
    let sync = sync.with_budget(Arc::clone(&budget));
    let refresh = refresh.with_budget(budget);

    let retention = nodus_store::retention::RetentionPolicy {
        post_days: u32::from(config.post_retention_days),
        event_days: u32::from(config.event_retention_days),
    };
    tracing::info!(worker = %config.worker_id, kinds = ?config.kinds, "calc worker running");

    let worker = Worker::new(
        pool.clone(),
        Registry::standard(pool.clone(), sync, refresh, retention),
        config,
    );
    let wake = Arc::new(tokio::sync::Notify::new());
    let telemetry = serving.telemetry.clone().map(|address| {
        let control = WorkerControl {
            wake: Arc::clone(&wake),
        };
        runtime::serve_worker(address, Arc::clone(&agent), control)
    });

    let maintenance = tokio::spawn(maintain(Maintenance::new(pool), wake));
    let result = worker.run(runtime::shutdown()).await;
    maintenance.abort();
    runtime::stop_telemetry(telemetry).await;
    result?;
    Ok(())
}

/// The tick that enqueues what only a clock would ask for.
async fn maintain(maintenance: Maintenance, wake: Arc<tokio::sync::Notify>) {
    let mut ticker = tokio::time::interval(MAINTENANCE_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            () = wake.notified() => {}
        }
        if let Err(error) = maintenance.tick().await {
            tracing::warn!(%error, "maintenance tick failed");
        }
    }
}

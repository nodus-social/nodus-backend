//! One binary, several roles.
//!
//! The deployed units keep their names and their behaviour: `nodus-api`, `nodus-media`,
//! `nodus-feed`, `nodus-scan`, `nodus-prune` and `nodus-calc` are still what systemd
//! starts. This binary is the additive entrypoint a host can use instead, and it starts the
//! *same* run paths those units start rather than a copy of them: `nodus api` and
//! `nodus-api` both execute `nodus_server_api::run`, and every other role has the same
//! arrangement with its own crate.
//!
//! Seven roles, no eighth:
//!
//! | Role | What starts |
//! | --- | --- |
//! | `api` | the API process, on `NODUS_BIND` |
//! | `media-worker` | the media process, on `NODUS_BIND` |
//! | `feed` | the feed process, on `NODUS_BIND` |
//! | `scan` | the scanner sweep, with a control listener when telemetry is configured |
//! | `prune` | the pruning worker, with a control listener when telemetry is configured |
//! | `calc` | the recommendation worker, with a control listener when telemetry is configured |
//! | `aio` | api and media in one process: api on `NODUS_BIND`, media on `NODUS_MEDIA_BIND` |
//!
//! `aio` is api plus media only. The three workers are deliberately not in it: they are
//! long-running loops rather than listeners, and folding them in would give one process the
//! failure domain of four services.
//!
//! Launching a second copy of the same role against the same database is the operator's
//! problem, not the parser's: every role here is the same process the unit starts.

use std::future::Future;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::anyhow;
use nodus_server_runtime as runtime;
use nodus_server_transport::Address;
use tokio::sync::{mpsc, watch};

/// The port `nodus-media.service` binds. `aio` uses it when `NODUS_MEDIA_BIND` says
/// nothing, so the combined process answers where the split deployment answers.
const DEFAULT_MEDIA_BIND: &str = "0.0.0.0:3003";

/// How long a role gets to finish its graceful stop before the process gives up on it.
/// The stop path is a cancelled `axum::serve`, so anything longer means it is stuck.
const STOP_GRACE: Duration = Duration::from_secs(10);

/// Set this, or pass `--dry-run`, to print what a role would start and where it would
/// listen, then exit 0 without binding anything. It exists so a test can prove the dispatch
/// without starting five more servers.
const DRY_RUN_ENV: &str = "NODUS_ROLE_DRY_RUN";

const HELP: &str = "\
nodus — one binary, several roles

Usage:
  nodus <role> [--dry-run]

Roles:
  api           the Mastodon API, ActivityPub documents and auth pages
                listens on NODUS_BIND (default 0.0.0.0:3000)
  media-worker  serves uploaded media and its variants
                listens on NODUS_BIND (default 0.0.0.0:3000)
  feed          the recommendation, browse and sync surface the client reads
                listens on NODUS_BIND (default 0.0.0.0:3000)
  scan          the scanner sweep: asks the configured scanners, applies what they say
                answers for a pass now on NODUS_TELEMETRY_SOCKET / NODUS_TELEMETRY_BIND
  prune         the pruning worker: media, sessions, codes and stale rows on a clock
                answers for a pass now on NODUS_TELEMETRY_SOCKET / NODUS_TELEMETRY_BIND
  calc          the recommendation worker: crawling, recomputing and retention
                answers for a maintenance tick on NODUS_TELEMETRY_SOCKET / NODUS_TELEMETRY_BIND
  aio           api and media-worker in one process (nothing else: the three workers are
                long-running loops, not listeners, so they stay separate roles)
                api on NODUS_BIND, media on NODUS_MEDIA_BIND (default 0.0.0.0:3003)

With no role, or with --help, this text is printed and nothing starts.

--dry-run (or NODUS_ROLE_DRY_RUN=1) prints the role, the run path it calls and the address
it would listen on, then exits 0 without binding.

The deployed units are unchanged: nodus-api, nodus-media, nodus-feed, nodus-scan,
nodus-prune and nodus-calc still start their own binaries. See docs/entrypoints.md.";

/// One role's answer to "what would you start, and where would you listen?".
///
/// Returned by each crate's `plan`, so `--dry-run` prints the role's own reading of its
/// environment rather than a copy of it kept here.
type Plan = (&'static str, &'static str, String);

#[tokio::main]
async fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let dry_run = std::env::var_os(DRY_RUN_ENV).is_some()
        || arguments.iter().any(|argument| argument == "--dry-run");
    let roles: Vec<&str> = arguments
        .iter()
        .map(String::as_str)
        .filter(|argument| !argument.starts_with('-'))
        .collect();
    let wanted_help = arguments
        .iter()
        .any(|argument| argument == "-h" || argument == "--help");
    let role = roles.first().copied();

    if wanted_help || role.is_none() {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }

    match role.unwrap_or_default() {
        "api" => {
            start(
                nodus_server_api::run::plan,
                nodus_server_api::run(),
                dry_run,
            )
            .await
        }
        "media-worker" => {
            start(
                nodus_server_media::run::plan,
                nodus_server_media::run(),
                dry_run,
            )
            .await
        }
        "feed" => start(nodus_server_feed::plan, nodus_server_feed::run(), dry_run).await,
        "scan" => {
            start(
                nodus_server_scan::run::plan,
                nodus_server_scan::run(),
                dry_run,
            )
            .await
        }
        "prune" => {
            start(
                nodus_server_prune::run::plan,
                nodus_server_prune::run(),
                dry_run,
            )
            .await
        }
        "calc" => {
            start(
                nodus_server_calc::run::plan,
                nodus_server_calc::run(),
                dry_run,
            )
            .await
        }
        "aio" => {
            if dry_run {
                let api = nodus_server_api::run::plan();
                let media =
                    nodus_server_media::run::plan_on("NODUS_MEDIA_BIND", DEFAULT_MEDIA_BIND);
                return announce_aio(api, media);
            }
            finish(aio().await)
        }
        other => {
            eprintln!(
                "nodus: unknown role `{other}`; expected one of: api, media-worker, feed, \
                 scan, prune, calc, aio\n\
                 Run `nodus --help` for what each role does."
            );
            ExitCode::from(2)
        }
    }
}

/// Start one role's run path, or describe it when `--dry-run` asked for that.
///
/// The future is created either way but only polled on the real path: an `async fn` does
/// nothing until it is first polled, so `--dry-run` opens no socket and reads no database.
async fn start<F>(plan: fn() -> Plan, role_run: F, dry_run: bool) -> ExitCode
where
    F: Future<Output = anyhow::Result<()>>,
{
    if dry_run {
        return announce(plan());
    }
    finish(role_run.await)
}

/// Print what a role would start, in one line a test can match exactly.
fn announce((role, path, listen): Plan) -> ExitCode {
    println!("nodus {role} dry run: would start {path} on {listen}");
    ExitCode::SUCCESS
}

fn announce_aio(api: Plan, media: Plan) -> ExitCode {
    println!(
        "nodus aio dry run: would start {} on {}, and {} on {}",
        api.1, api.2, media.1, media.2
    );
    ExitCode::SUCCESS
}

fn finish(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nodus: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Both roles in one process, each on its own listener, sharing one stop signal.
///
/// This is the part that is not just two calls in a row: a role that stops — with an
/// error, or by returning before anyone asked it to — takes the other one down, so the
/// operator never finds half a deployment running and believes the other half is up.
///
/// `NODUS_AIO_ANNOUNCE_SECS` makes the process print the two addresses it was given and
/// ask both roles to stop after that many seconds. It exists for the listener test, which
/// needs a process that binds, serves and exits on its own; it changes nothing else.
async fn aio() -> anyhow::Result<()> {
    let agent = runtime::init("aio");
    let api_address = address("NODUS_BIND", runtime::DEFAULT_BIND)?;
    let media_address = address("NODUS_MEDIA_BIND", DEFAULT_MEDIA_BIND)?;
    let api = runtime::read_with_bind(api_address.clone()).map_err(|error| anyhow!("{error}"))?;
    let media =
        runtime::read_with_bind(media_address.clone()).map_err(|error| anyhow!("{error}"))?;

    let telemetry = api
        .telemetry
        .clone()
        .map(|address| runtime::serve_telemetry(address, agent));

    let announce = match std::env::var("NODUS_AIO_ANNOUNCE_SECS") {
        Ok(value) => Some(
            value
                .parse::<u64>()
                .map_err(|error| anyhow!("NODUS_AIO_ANNOUNCE_SECS is not a number: {error}"))?,
        ),
        Err(_) => None,
    };

    let (stop, stop_rx) = watch::channel(false);
    let (done_tx, mut done_rx) = mpsc::channel::<(&'static str, anyhow::Result<()>)>(2);

    tracing::info!(
        api = %api_address,
        media = %media_address,
        "aio: api and media in one process"
    );
    if let Some(seconds) = announce {
        // Printed rather than logged so a test reads two plain lines, not a log format.
        println!("nodus aio: api on {api_address}");
        println!("nodus aio: media on {media_address}");
        let stop = stop.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(seconds)).await;
            let _ = stop.send(true);
        });
    }

    let api_task = tokio::spawn(forward(
        "api",
        done_tx.clone(),
        nodus_server_api::run::serve(api, stopped(stop_rx.clone())),
    ));
    let media_task = tokio::spawn(forward(
        "media",
        done_tx,
        nodus_server_media::run::serve(media, stopped(stop_rx.clone())),
    ));

    // Either the operator asked to stop, the announce timer expired, or a role finished
    // on its own. Only the last case is a failure, and it names the role that went first.
    let first = tokio::select! {
        _ = runtime::shutdown() => None,
        () = stopped(stop_rx.clone()) => None,
        done = done_rx.recv() => done,
    };

    let mut failure = match &first {
        Some((role, Ok(()))) => Some(anyhow!(
            "the {role} role stopped serving; stopping the other role so the process \
             cannot look healthy with half its listeners gone"
        )),
        Some((role, Err(error))) => Some(anyhow!("the {role} role failed: {error:#}")),
        None => None,
    };

    let _ = stop.send(true);
    let mut api_task = Some(api_task);
    let mut media_task = Some(media_task);
    if let Some((finished, _)) = &first {
        if *finished == "api" {
            api_task = None;
        } else {
            media_task = None;
        }
    }
    for (role, task) in [("api", api_task), ("media", media_task)] {
        let Some(task) = task else { continue };
        match tokio::time::timeout(STOP_GRACE, task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                failure.get_or_insert_with(|| anyhow!("the {role} role did not stop: {error}"));
            }
            Err(_) => {
                failure.get_or_insert_with(|| {
                    anyhow!("the {role} role did not stop within {STOP_GRACE:?}")
                });
            }
        }
    }

    runtime::stop_telemetry(telemetry).await;
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Await a role and hand its result to the select loop above.
async fn forward<F>(
    role: &'static str,
    done: mpsc::Sender<(&'static str, anyhow::Result<()>)>,
    role_run: F,
) where
    F: Future<Output = anyhow::Result<()>>,
{
    let result = role_run.await;
    let _ = done.send((role, result)).await;
}

/// Resolve when the shared stop signal is raised, including when it was raised before
/// this future was first polled.
async fn stopped(mut stop: watch::Receiver<bool>) {
    loop {
        if *stop.borrow_and_update() {
            return;
        }
        if stop.changed().await.is_err() {
            return;
        }
    }
}

/// The address a role listens on: the named variable, or the role's default.
fn address(variable: &str, default: &str) -> anyhow::Result<Address> {
    let value = std::env::var(variable).unwrap_or_else(|_| default.to_owned());
    nodus_server_transport::parse(&value).map_err(|error| anyhow!("{variable}: {error}"))
}

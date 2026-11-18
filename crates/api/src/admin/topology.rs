//! What the other processes of this instance are doing, asked over their telemetry service.
//!
//! Nothing here is stored: the answer is assembled from live calls, and the only memory is
//! the last time a node answered, so a failed probe can still say when that node last looked
//! well. A probe is bounded at [`PROBE_BUDGET`], and the nodes are asked in parallel, so a
//! dead node costs the same wall-clock time as a fast one.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::response::sse::{Event as SseEvent, KeepAlive};
use axum::response::Sse;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use nodus_server_proto::control::control_client::ControlClient;
use nodus_server_proto::control::TriggerRequest;
use nodus_server_proto::telemetry::telemetry_client::TelemetryClient;
use nodus_server_proto::telemetry::{Empty, LogEntry, LogStreamRequest};
use serde::{Deserialize, Serialize};
use tonic::transport::{Channel, Endpoint};

use super::AppState;
use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};

/// How long a single node may take to answer.
const PROBE_BUDGET: Duration = Duration::from_millis(250);
/// How many entries a log drawer can ask for in one pull.
const LOG_LIMIT: usize = 500;

/// One process this instance expects to find.
#[derive(Debug, Clone)]
enum Target {
    Socket { name: String, path: PathBuf },
    Http { name: String, url: String },
}

impl Target {
    fn name(&self) -> &str {
        match self {
            Self::Socket { name, .. } | Self::Http { name, .. } => name,
        }
    }

    fn transport(&self) -> &'static str {
        match self {
            Self::Socket { .. } => "unix",
            Self::Http { .. } => "http",
        }
    }

    fn endpoint(&self) -> String {
        if full_visibility() {
            return match self {
                Self::Socket { path, .. } => path.display().to_string(),
                Self::Http { url, .. } => url.clone(),
            };
        }
        // A socket path and an internal address are infrastructure, not health: an
        // administrator who needs them says so once in the environment.
        match self {
            Self::Socket { .. } => "unix socket".to_owned(),
            Self::Http { .. } => "tcp".to_owned(),
        }
    }
}

/// Whether endpoint paths and addresses are answered as configured.
///
/// Off by default: the topology view answers whether a node is well, which does not
/// need the filesystem layout. `NODUS_TELEMETRY_FULL=true` turns the detail on.
fn full_visibility() -> bool {
    static FULL: OnceLock<bool> = OnceLock::new();
    *FULL.get_or_init(|| {
        std::env::var("NODUS_TELEMETRY_FULL")
            .is_ok_and(|value| matches!(value.trim(), "1" | "true" | "yes" | "on"))
    })
}

/// Reads `NODUS_TELEMETRY` once: `name=unix:/run/nodus/api.sock,name=http://10.0.1.4:50051`.
///
/// A process that serves its own telemetry and names nothing else still has itself to show,
/// which is the default of a single-process deployment.
fn targets() -> &'static [Target] {
    static TARGETS: OnceLock<Vec<Target>> = OnceLock::new();
    TARGETS.get_or_init(|| {
        let listed = std::env::var("NODUS_TELEMETRY").unwrap_or_default();
        let mut parsed: Vec<Target> = listed
            .split(',')
            .filter_map(|entry| {
                let (name, address) = entry.split_once('=')?;
                let name = name.trim();
                let address = address.trim();
                if name.is_empty() || address.is_empty() {
                    return None;
                }
                match address.strip_prefix("unix:") {
                    Some(path) => Some(Target::Socket {
                        name: name.to_owned(),
                        path: socket_path(path),
                    }),
                    None => Some(Target::Http {
                        name: name.to_owned(),
                        url: address.to_owned(),
                    }),
                }
            })
            .collect();
        // The API answers the question and is a node of its own, so it belongs in the
        // answer even when the worker list is configured: a console that hides the process
        // it is talking to cannot show that process failing.
        if let Ok(path) = std::env::var("NODUS_TELEMETRY_SOCKET") {
            let name = std::env::var("NODUS_NODE_NAME").unwrap_or_else(|_| "api".to_owned());
            if !parsed.iter().any(|target| target.name() == name) {
                parsed.insert(
                    0,
                    Target::Socket {
                        name,
                        path: socket_path(&path),
                    },
                );
            }
        }
        parsed
    })
}

/// A socket path as either side of a deployment writes it: `/run/nodus/api.sock` or
/// `unix:///run/nodus/api.sock`.
fn socket_path(value: &str) -> PathBuf {
    let value = value.trim();
    let value = value
        .strip_prefix("unix://")
        .or_else(|| value.strip_prefix("unix:"))
        .unwrap_or(value);
    PathBuf::from(value)
}

/// The whole chain, so a view that says a service is dead also says why.
fn describe(error: &tonic::transport::Error) -> String {
    let mut message = error.to_string();
    let mut cause = std::error::Error::source(error);
    while let Some(inner) = cause {
        message.push_str(": ");
        message.push_str(&inner.to_string());
        cause = inner.source();
    }
    message
}

#[derive(Debug, Default)]
struct Seen {
    last_seen_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
}

fn seen() -> &'static Mutex<HashMap<String, Seen>> {
    static SEEN: OnceLock<Mutex<HashMap<String, Seen>>> = OnceLock::new();
    SEEN.get_or_init(|| Mutex::new(HashMap::new()))
}

fn record(name: &str, answer: &Result<String, String>) {
    let Ok(mut seen) = seen().lock() else {
        return;
    };
    let entry = seen.entry(name.to_owned()).or_default();
    match answer {
        Ok(version) => {
            entry.last_seen_at = Some(Utc::now());
            entry.last_error = None;
            let _ = version;
        }
        Err(error) => entry.last_error = Some(error.clone()),
    }
}

fn remembered(name: &str) -> Seen {
    seen().lock().map_or_else(
        |_| Seen::default(),
        |seen| {
            seen.get(name).map_or(Seen::default(), |seen| Seen {
                last_seen_at: seen.last_seen_at,
                last_error: seen.last_error.clone(),
            })
        },
    )
}

/// The channel to one node, whether it is a socket or an address.
async fn channel(target: &Target) -> Result<Channel, String> {
    match target {
        Target::Socket { path, .. } => {
            let socket = path.clone();
            let channel = Endpoint::try_from("http://[::]:50051")
                .map_err(|error| error.to_string())?
                .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                    let socket = socket.clone();
                    async move {
                        let stream = tokio::net::UnixStream::connect(socket).await?;
                        Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                    }
                }))
                .await
                .map_err(|error| describe(&error))?;
            Ok(channel)
        }
        Target::Http { url, .. } => Endpoint::from_shared(url.clone())
            .map_err(|error| error.to_string())?
            .connect()
            .await
            .map_err(|error| describe(&error)),
    }
}

async fn client(target: &Target) -> Result<TelemetryClient<Channel>, String> {
    Ok(TelemetryClient::new(channel(target).await?))
}

/// What a node said when asked to do something now.
#[derive(Debug, Serialize)]
pub struct TriggerDto {
    pub accepted: bool,
    pub detail: String,
}

#[derive(Debug, Deserialize)]
pub struct TriggerBody {
    /// The work to do. Empty asks the node for whatever it does by default.
    #[serde(default)]
    pub work: String,
}

/// Ask one node to run its work now instead of on its tick.
///
/// The queue is the durable path; this is the path an administrator takes when they do
/// not want to wait for a clock, and it goes over the same channel the report does.
async fn trigger(
    State(_state): State<AppState>,
    auth: Auth,
    Path(name): Path<String>,
    Json(body): Json<TriggerBody>,
) -> ApiResult<Json<TriggerDto>> {
    auth.require_administrator("admin:write")?;
    let target = targets()
        .iter()
        .find(|target| target.name() == name)
        .ok_or_else(|| ApiError::not_found("no such node"))?;
    let answer = ControlClient::new(channel(target).await.map_err(refused)?)
        .trigger(TriggerRequest { work: body.work })
        .await
        .map_err(|status| refused(status.to_string()))?
        .into_inner();
    Ok(Json(TriggerDto {
        accepted: answer.accepted,
        detail: answer.detail,
    }))
}

fn refused(reason: String) -> ApiError {
    ApiError::new(axum::http::StatusCode::BAD_GATEWAY, reason)
}

#[derive(Debug, Serialize)]
pub struct NodeDto {
    pub name: String,
    pub transport: &'static str,
    pub endpoint: String,
    pub status: &'static str,
    pub version: Option<String>,
    pub uptime_seconds: u64,
    pub cpu_usage_percent: f64,
    pub rss_bytes: u64,
    pub queue_depth: Option<u64>,
    pub latency_ms: u64,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    /// Whether this node runs a different build than the process answering.
    pub version_mismatch: bool,
}

#[derive(Debug, Serialize)]
pub struct TopologyDto {
    pub version: String,
    pub nodes: Vec<NodeDto>,
}

#[derive(Debug, Deserialize)]
pub struct LogQuery {
    limit: Option<usize>,
    min_level: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LogDto {
    pub timestamp: String,
    pub level: &'static str,
    pub target: String,
    pub message: String,
}

fn level_name(level: i32) -> &'static str {
    match level {
        0 => "trace",
        1 => "debug",
        2 => "info",
        3 => "warn",
        _ => "error",
    }
}

fn level_value(name: &str) -> i32 {
    match name.trim().to_ascii_lowercase().as_str() {
        "trace" => 0,
        "debug" => 1,
        "warn" => 3,
        "error" => 4,
        _ => 2,
    }
}

async fn probe(target: &Target) -> NodeDto {
    let started = Instant::now();
    let answer = match tokio::time::timeout(PROBE_BUDGET, async {
        let mut client = client(target).await?;
        let telemetry = client
            .get_node_telemetry(Empty {})
            .await
            .map_err(|status| status.message().to_owned())?
            .into_inner();
        Ok::<_, String>(telemetry)
    })
    .await
    {
        Ok(Ok(telemetry)) => Ok(telemetry),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(format!("no answer within {} ms", PROBE_BUDGET.as_millis())),
    };

    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let recorded = match &answer {
        Ok(telemetry) => Ok(telemetry.binary_version.clone()),
        Err(error) => Err(error.clone()),
    };
    record(target.name(), &recorded);
    match answer {
        Ok(telemetry) => NodeDto {
            name: target.name().to_owned(),
            transport: target.transport(),
            endpoint: target.endpoint(),
            status: if telemetry.status() == nodus_server_proto::telemetry::Health::Degraded {
                "degraded"
            } else {
                "healthy"
            },
            version_mismatch: telemetry.binary_version != env!("CARGO_PKG_VERSION"),
            version: Some(telemetry.binary_version),
            uptime_seconds: telemetry.uptime_seconds,
            cpu_usage_percent: telemetry.cpu_usage_percent,
            rss_bytes: telemetry.rss_memory_bytes,
            queue_depth: telemetry.queue_depth,
            latency_ms,
            last_seen_at: Some(Utc::now()),
            last_error: None,
        },
        Err(error) => {
            let remembered = remembered(target.name());
            NodeDto {
                name: target.name().to_owned(),
                transport: target.transport(),
                endpoint: target.endpoint(),
                status: "dead",
                version: None,
                uptime_seconds: 0,
                cpu_usage_percent: 0.0,
                rss_bytes: 0,
                queue_depth: None,
                latency_ms,
                last_seen_at: remembered.last_seen_at,
                last_error: Some(error),
                version_mismatch: false,
            }
        }
    }
}

async fn topology(State(_state): State<AppState>, auth: Auth) -> ApiResult<Json<TopologyDto>> {
    auth.require_admin("admin:read")?;
    let nodes = futures_util::future::join_all(targets().iter().map(probe)).await;
    Ok(Json(TopologyDto {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        nodes,
    }))
}

async fn logs(
    State(_state): State<AppState>,
    auth: Auth,
    Path(name): Path<String>,
    Query(query): Query<LogQuery>,
) -> ApiResult<Json<Vec<LogDto>>> {
    auth.require_admin("admin:read")?;
    let Some(target) = targets().iter().find(|target| target.name() == name) else {
        return Err(ApiError::not_found("no such node"));
    };
    let limit = query.limit.unwrap_or(200).min(LOG_LIMIT);
    let min_level = level_value(query.min_level.as_deref().unwrap_or("info"));

    let collected = tokio::time::timeout(PROBE_BUDGET, async {
        let mut client = client(target)
            .await
            .map_err(|error| ApiError::new(axum::http::StatusCode::BAD_GATEWAY, error))?;
        let mut stream = client
            .stream_logs(LogStreamRequest {
                buffered: u32::try_from(limit).unwrap_or(u32::try_from(LOG_LIMIT).unwrap_or(500)),
                min_level,
            })
            .await
            .map_err(|status| {
                ApiError::new(
                    axum::http::StatusCode::BAD_GATEWAY,
                    status.message().to_owned(),
                )
            })?
            .into_inner();
        let mut entries: Vec<LogEntry> = Vec::with_capacity(limit);
        while entries.len() < limit {
            match stream.next().await {
                Some(Ok(entry)) => entries.push(entry),
                Some(Err(status)) => {
                    if entries.is_empty() {
                        return Err(ApiError::new(
                            axum::http::StatusCode::BAD_GATEWAY,
                            status.message().to_owned(),
                        ));
                    }
                    break;
                }
                None => break,
            }
        }
        Ok::<_, ApiError>(entries)
    })
    .await
    .map_err(|_| {
        ApiError::new(
            axum::http::StatusCode::GATEWAY_TIMEOUT,
            format!("{} did not answer in time", target.name()),
        )
    })??;

    Ok(Json(collected.into_iter().map(log_dto).collect()))
}

/// The tail of one node's log, as it happens.
///
/// The drawer opens this once and closes it by disconnecting; dropping the response
/// drops the gRPC stream with it, so a closed drawer holds no socket on either side.
async fn stream_logs(
    State(_state): State<AppState>,
    auth: Auth,
    Path(name): Path<String>,
    Query(query): Query<LogQuery>,
) -> ApiResult<Sse<impl futures_util::Stream<Item = Result<SseEvent, Infallible>>>> {
    auth.require_admin("admin:read")?;
    let Some(target) = targets().iter().find(|target| target.name() == name) else {
        return Err(ApiError::not_found("no such node"));
    };
    let limit = query.limit.unwrap_or(200).min(LOG_LIMIT);
    let min_level = level_value(query.min_level.as_deref().unwrap_or("info"));

    let mut client = client(target)
        .await
        .map_err(|error| ApiError::new(axum::http::StatusCode::BAD_GATEWAY, error))?;
    let stream = client
        .stream_logs(LogStreamRequest {
            buffered: u32::try_from(limit).unwrap_or(u32::try_from(LOG_LIMIT).unwrap_or(500)),
            min_level,
        })
        .await
        .map_err(|status| {
            ApiError::new(
                axum::http::StatusCode::BAD_GATEWAY,
                status.message().to_owned(),
            )
        })?
        .into_inner();

    let events = stream.map(|entry| {
        Ok(match entry {
            Ok(entry) => match SseEvent::default().json_data(log_dto(entry)) {
                Ok(event) => event,
                Err(error) => SseEvent::default()
                    .event("error")
                    .data(format!("a log entry could not be read: {error}")),
            },
            Err(status) => SseEvent::default().event("error").data(status.message()),
        })
    });
    Ok(Sse::new(events).keep_alive(KeepAlive::default()))
}

fn log_dto(entry: LogEntry) -> LogDto {
    LogDto {
        timestamp: entry.timestamp,
        level: level_name(entry.level),
        target: entry.target,
        message: entry.message,
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/topology", axum::routing::get(topology))
        .route(
            "/api/v1/admin/topology/{name}/logs",
            axum::routing::get(logs),
        )
        .route(
            "/api/v1/admin/topology/{name}/logs/stream",
            axum::routing::get(stream_logs),
        )
        .route(
            "/api/v1/admin/topology/{name}/trigger",
            axum::routing::post(trigger),
        )
}

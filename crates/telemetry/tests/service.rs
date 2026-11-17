//! A node answering over its socket, which is the only thing the console depends on.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use nodus_server_proto::telemetry::telemetry_client::TelemetryClient;
use nodus_server_proto::telemetry::{Empty, LogStreamRequest};
use nodus_server_telemetry::{entry, Agent, Node};
use tonic::transport::{Endpoint, Uri};

async fn connect(socket: std::path::PathBuf) -> TelemetryClient<tonic::transport::Channel> {
    let channel = Endpoint::try_from("http://[::]:50051")
        .expect("a placeholder endpoint")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let socket = socket.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(socket).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .expect("the socket answers");
    TelemetryClient::new(channel)
}

#[tokio::test]
async fn a_node_answers_about_itself_over_its_socket() {
    let directory = std::env::temp_dir().join(format!("nodus-telemetry-{}", std::process::id()));
    let socket = directory.join("api.sock");
    let agent = Agent::new(Node {
        name: "api".to_owned(),
        version: "9.9.9".to_owned(),
    });
    let serving = Arc::clone(&agent);
    let target = socket.clone();
    let server = tokio::spawn(async move {
        let address = nodus_server_transport::Address::Path(target);
        nodus_server_telemetry::serve(serving, &address, std::future::pending()).await
    });

    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut client = connect(socket).await;
    let telemetry = client
        .get_node_telemetry(Empty {})
        .await
        .expect("the node answers")
        .into_inner();
    assert_eq!(telemetry.service_name, "api");
    assert_eq!(telemetry.binary_version, "9.9.9");
    assert_eq!(telemetry.queue_depth, None);
    assert!(telemetry.rss_memory_bytes > 0, "a process uses some memory");

    server.abort();
    let _ = std::fs::remove_dir_all(directory);
}

#[tokio::test]
async fn the_ring_is_what_a_log_drawer_reads() {
    let directory =
        std::env::temp_dir().join(format!("nodus-telemetry-logs-{}", std::process::id()));
    let socket = directory.join("api.sock");
    let agent = Agent::new(Node {
        name: "api".to_owned(),
        version: "9.9.9".to_owned(),
    });
    agent.ring().push(entry(
        tracing::Level::INFO,
        "nodus_server",
        "started".to_owned(),
    ));
    agent.ring().push(entry(
        tracing::Level::ERROR,
        "nodus_server",
        "the database refused".to_owned(),
    ));

    let serving = Arc::clone(&agent);
    let target = socket.clone();
    let server = tokio::spawn(async move {
        let address = nodus_server_transport::Address::Path(target);
        nodus_server_telemetry::serve(serving, &address, std::future::pending()).await
    });
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut client = connect(socket).await;
    let mut streaming = client
        .stream_logs(LogStreamRequest {
            buffered: 10,
            min_level: 0,
        })
        .await
        .expect("the stream opens")
        .into_inner();
    let mut entries = Vec::new();
    while entries.len() < 2 {
        match streaming.next().await {
            Some(Ok(entry)) => entries.push(entry),
            other => panic!("the buffered entries should arrive: {other:?}"),
        }
    }
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].message, "started");
    assert_eq!(entries[1].message, "the database refused");

    server.abort();
    let _ = std::fs::remove_dir_all(directory);
}

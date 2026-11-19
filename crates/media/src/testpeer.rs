//! A fake media node for this crate's tests.
//!
//! Just enough of the internal protocol to be a real network neighbour: it stores what a
//! `PUT` sends, answers `GET`/`HEAD` from that store, and records every request so a test
//! can assert what was asked for and how often. No container, no second service.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cluster::Member;

/// One request the peer saw, reduced to what a test asserts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub token: String,
    pub body: Vec<u8>,
}

#[derive(Default)]
struct State {
    files: HashMap<String, Vec<u8>>,
    seen: Vec<Request>,
}

/// A peer that behaves like a media node.
pub struct Peer {
    pub name: String,
    pub endpoint: String,
    state: Arc<Mutex<State>>,
}

impl Peer {
    pub async fn spawn(name: &str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a fake peer");
        let address = listener.local_addr().expect("fake peer address");
        let state = Arc::new(Mutex::new(State::default()));
        let shared = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    let Some((head, body)) = read_request(&mut stream).await else {
                        return;
                    };
                    let (method, path, token) = parse_head(&head);
                    let digest = path.rsplit('/').next().unwrap_or_default().to_owned();
                    let (status, payload) = {
                        let mut state = shared.lock().expect("peer state");
                        state.seen.push(Request {
                            method: method.clone(),
                            path: path.clone(),
                            token,
                            body: body.clone(),
                        });
                        match method.as_str() {
                            "PUT" => {
                                state.files.insert(digest, body);
                                ("201 Created", Vec::new())
                            }
                            "DELETE" => {
                                state.files.remove(&digest);
                                ("204 No Content", Vec::new())
                            }
                            "GET" => match state.files.get(&digest) {
                                Some(bytes) => ("200 OK", bytes.clone()),
                                None => ("404 Not Found", Vec::new()),
                            },
                            "HEAD" if state.files.contains_key(&digest) => ("200 OK", Vec::new()),
                            _ => ("404 Not Found", Vec::new()),
                        }
                    };
                    let reply = format!(
                        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        payload.len()
                    );
                    let _ = stream.write_all(reply.as_bytes()).await;
                    if !payload.is_empty() {
                        let _ = stream.write_all(&payload).await;
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            name: name.to_owned(),
            endpoint: format!("http://{address}"),
            state,
        }
    }

    /// The membership entry for this peer.
    pub fn member(&self) -> Member {
        Member {
            name: self.name.clone(),
            endpoint: self.endpoint.clone(),
        }
    }

    /// Puts bytes on the peer as if a replication had already reached it.
    pub fn seed(&self, digest: &str, bytes: Vec<u8>) {
        self.state
            .lock()
            .expect("peer state")
            .files
            .insert(digest.to_owned(), bytes);
    }

    /// What the peer holds under a digest, if anything.
    pub fn file(&self, digest: &str) -> Option<Vec<u8>> {
        self.state
            .lock()
            .expect("peer state")
            .files
            .get(digest)
            .cloned()
    }

    /// Every request the peer saw, in arrival order.
    pub fn seen(&self) -> Vec<Request> {
        self.state.lock().expect("peer state").seen.clone()
    }

    pub fn requests(&self) -> usize {
        self.state.lock().expect("peer state").seen.len()
    }

    pub fn gets(&self) -> usize {
        self.seen()
            .iter()
            .filter(|request| request.method == "GET")
            .count()
    }

    pub fn puts(&self) -> usize {
        self.seen()
            .iter()
            .filter(|request| request.method == "PUT")
            .count()
    }
}

fn parse_head(head: &str) -> (String, String, String) {
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let token = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("x-nodus-cluster")
                .then(|| value.trim().to_owned())
        })
        .unwrap_or_default();
    (method, path, token)
}

/// Reads one request: the head up to the blank line, then `content-length` bytes.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
        let mut length = 0usize;
        for line in head.lines() {
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
        }
        let mut body = buffer[end + 4..].to_vec();
        while body.len() < length {
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read]);
        }
        return Some((head, body));
    }
}

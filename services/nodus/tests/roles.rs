//! The three roles, as an operator meets them: the help text, the refusal of a role that
//! does not exist, and `aio` actually opening two listeners instead of claiming to.
//!
//! The `aio` test needs a database because both roles run migrations before they bind, so
//! it is gated on `DATABASE_URL` and skips with a message otherwise. It proves the
//! listeners with a TCP connect: the process prints the two addresses it was given and
//! stops itself after `NODUS_AIO_ANNOUNCE_SECS` seconds, so the test can dial both ports
//! and then expect a clean exit without signalling the process itself.

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// The binary under test.
const ROLES: [&str; 3] = ["api", "media-worker", "aio"];

fn run(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_nodus"))
        .args(args)
        .output()
        .expect("the nodus binary runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn assert_names_every_role(where_: &str, text: &str) {
    for role in ROLES {
        assert!(
            text.contains(role),
            "{where_} should name the `{role}` role, got:\n{text}"
        );
    }
}

#[test]
fn help_names_the_three_roles() {
    let (ok, stdout, stderr) = run(&["--help"]);
    assert!(ok, "--help should exit 0, stderr:\n{stderr}");
    assert_names_every_role("--help", &stdout);
}

#[test]
fn no_role_prints_the_help() {
    let (ok, stdout, stderr) = run(&[]);
    assert!(ok, "no arguments should exit 0, stderr:\n{stderr}");
    assert_names_every_role("no arguments", &stdout);
}

#[test]
fn unknown_role_fails_and_names_the_accepted_ones() {
    let (ok, stdout, stderr) = run(&["docker"]);
    assert!(
        !ok,
        "an unknown role should exit non-zero, stdout:\n{stdout}"
    );
    assert_names_every_role("the unknown-role message", &stderr);
    assert!(
        stderr.contains("docker"),
        "the message should name what was rejected, got:\n{stderr}"
    );
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free local port")
        .port()
}

/// Read lines from a child pipe on a thread, so the child never blocks on a full pipe.
fn lines_of<R: std::io::Read + Send + 'static>(reader: R, tx: std::sync::mpsc::Sender<String>) {
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
}

fn collect(rx: &Receiver<String>, lines: &mut Vec<String>, wait: Duration) {
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => lines.push(line),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn wait_for_exit(child: &mut Child, within: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        match child
            .try_wait()
            .expect("the child is still ours to wait on")
        {
            Some(status) => return Some(status),
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

#[test]
fn aio_opens_both_listeners_and_stops_cleanly() {
    let database_url = std::env::var("DATABASE_URL")
        .or_else(|_| std::env::var("NODUS_DATABASE_URL"))
        .unwrap_or_else(|_| {
            eprintln!(
                "skipping the aio listener test: DATABASE_URL is not set, and both roles \
                 migrate before they bind. Point it at a scratch database to run this test."
            );
            String::new()
        });
    if database_url.is_empty() {
        return;
    }

    let api_port = free_port();
    let media_port = free_port();
    let media_dir = std::env::temp_dir().join(format!("nodus-aio-test-{}", std::process::id()));
    std::fs::create_dir_all(&media_dir).expect("a scratch media directory");
    // The announce window has to outlast two migrations against a cold database.
    let announce_secs = "10";

    let mut child = Command::new(env!("CARGO_BIN_EXE_nodus"))
        .arg("aio")
        .env("NODUS_BIND", format!("127.0.0.1:{api_port}"))
        .env("NODUS_MEDIA_BIND", format!("127.0.0.1:{media_port}"))
        .env("NODUS_AIO_ANNOUNCE_SECS", announce_secs)
        .env("NODUS_DOMAIN", "localhost")
        .env("NODUS_MEDIA_DIR", &media_dir)
        .env("NODUS_MEDIA_REPAIR", "off")
        .env("NODUS_DATABASE_URL", &database_url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("aio starts");

    let (tx, rx) = channel();
    lines_of(child.stdout.take().expect("stdout is piped"), tx.clone());
    lines_of(child.stderr.take().expect("stderr is piped"), tx);

    let mut lines = Vec::new();
    let mut api_up = false;
    let mut media_up = false;
    let window = Duration::from_secs(announce_secs.parse::<u64>().expect("a number") + 5);
    let deadline = Instant::now() + window;
    while Instant::now() < deadline && !(api_up && media_up) {
        collect(&rx, &mut lines, Duration::from_millis(150));
        api_up = api_up || TcpStream::connect(("127.0.0.1", api_port)).is_ok();
        media_up = media_up || TcpStream::connect(("127.0.0.1", media_port)).is_ok();
    }

    let status = wait_for_exit(&mut child, Duration::from_secs(30));
    collect(&rx, &mut lines, Duration::from_millis(400));
    let output = lines.join("\n");
    std::fs::remove_dir_all(&media_dir).ok();

    assert!(
        output.contains(&format!("nodus aio: api on 127.0.0.1:{api_port}")),
        "aio should print where the api listens, got:\n{output}"
    );
    assert!(
        output.contains(&format!("nodus aio: media on 127.0.0.1:{media_port}")),
        "aio should print where media listens, got:\n{output}"
    );
    assert!(
        api_up,
        "the api listener on 127.0.0.1:{api_port} should accept a connection, got:\n{output}"
    );
    assert!(
        media_up,
        "the media listener on 127.0.0.1:{media_port} should accept a connection, got:\n{output}"
    );
    let status = status.unwrap_or_else(|| panic!("aio should stop on its own, got:\n{output}"));
    assert!(
        status.success(),
        "aio should exit 0 after the announce window, got {status}, output:\n{output}"
    );
}

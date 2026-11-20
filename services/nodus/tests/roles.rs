//! The seven roles, as an operator meets them: the help text, the refusal of a role that
//! does not exist, and one dry-run per role proving it reaches its own run path.
//!
//! The dry-run tests are the dispatch proof: `nodus <role> --dry-run` prints the run path
//! that role calls and the address that role would bind, both read from the role's own
//! module, then exits 0. Nothing is bound — the tests take the ports they tell a role to
//! use, so a role that ignored the flag would fail instead of passing quietly.
//!
//! The `aio` listener test needs a database because both roles run migrations before they
//! bind, so it is gated on `DATABASE_URL` and skips with a message otherwise. It proves the
//! listeners with a TCP connect: the process prints the two addresses it was given and
//! stops itself after `NODUS_AIO_ANNOUNCE_SECS` seconds, so the test can dial both ports
//! and then expect a clean exit without signalling the process itself.

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// The binary under test.
const ROLES: [&str; 7] = [
    "api",
    "media-worker",
    "feed",
    "scan",
    "prune",
    "calc",
    "aio",
];

/// Everything a dry run must not inherit, so a developer's shell cannot decide the answer.
const AMBIENT: [&str; 4] = [
    "NODUS_BIND",
    "NODUS_MEDIA_BIND",
    "NODUS_TELEMETRY_SOCKET",
    "NODUS_TELEMETRY_BIND",
];

fn run(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_nodus"))
        .args(args)
        .env_remove("NODUS_ROLE_DRY_RUN")
        .output()
        .expect("the nodus binary runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Run one role in dry-run mode with a known environment, and return what it printed.
fn dry_run(role: &str, environment: &[(&str, &str)], flag: bool) -> (bool, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nodus"));
    command.arg(role);
    command.env_remove("NODUS_ROLE_DRY_RUN");
    for variable in AMBIENT {
        command.env_remove(variable);
    }
    if flag {
        command.arg("--dry-run");
    } else {
        // The environment form, exercised on every role: the flag is only the nicer spelling.
        command.env("NODUS_ROLE_DRY_RUN", "1");
    }
    for (variable, value) in environment {
        command.env(variable, value);
    }
    let output = command.output().expect("the nodus binary runs");
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
fn help_names_the_seven_roles() {
    let (ok, stdout, stderr) = run(&["--help"]);
    assert!(ok, "--help should exit 0, stderr:\n{stderr}");
    assert_names_every_role("--help", &stdout);
    assert!(
        stdout.contains("aio           api and media-worker in one process"),
        "the help should say what aio is, got:\n{stdout}"
    );
    assert!(
        stdout.contains("not listeners"),
        "the help should say why the three workers are not in aio, got:\n{stdout}"
    );
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

/// The listener that holds a port while a role is told to use it. A dry run that really
/// bound would fail; one that never ran the read would print the wrong answer.
fn held_port() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free local port");
    let port = listener.local_addr().expect("a local address").port();
    (listener, port)
}

/// One listener role: it prints its own run path and the `NODUS_BIND` it was given.
fn assert_listener_role(role: &str, path: &str, flag: bool) {
    let (_held, port) = held_port();
    let bind = format!("127.0.0.1:{port}");
    let (ok, stdout, stderr) = dry_run(role, &[("NODUS_BIND", &bind)], flag);
    assert!(
        ok,
        "`nodus {role} --dry-run` should exit 0, stderr:\n{stderr}"
    );
    assert_eq!(
        stdout.trim(),
        format!("nodus {role} dry run: would start {path} on {bind}"),
        "the dry run should name the role's own run path and address"
    );
}

/// One worker role: it prints its own run path and the control address it would answer on.
fn assert_worker_role(role: &str, path: &str, flag: bool) {
    let (ok, stdout, stderr) = dry_run(role, &[("NODUS_TELEMETRY_SOCKET", "/tmp/held.sock")], flag);
    assert!(
        ok,
        "`nodus {role} --dry-run` should exit 0, stderr:\n{stderr}"
    );
    assert_eq!(
        stdout.trim(),
        format!("nodus {role} dry run: would start {path} on the control socket /tmp/held.sock"),
        "the dry run should name the role's own run path and control socket"
    );
}

#[test]
fn api_dry_run_reaches_the_api_run_path() {
    assert_listener_role("api", "nodus_server_api::run", true);
}

#[test]
fn media_worker_dry_run_reaches_the_media_run_path() {
    assert_listener_role("media-worker", "nodus_server_media::run", false);
}

#[test]
fn feed_dry_run_reaches_the_feed_run_path() {
    assert_listener_role("feed", "nodus_server_feed::run", true);
}

#[test]
fn scan_dry_run_reaches_the_scan_run_path() {
    assert_worker_role("scan", "nodus_server_scan::run", true);
}

#[test]
fn prune_dry_run_reaches_the_prune_run_path() {
    assert_worker_role("prune", "nodus_server_prune::run", false);
}

#[test]
fn calc_dry_run_reaches_the_calc_run_path() {
    assert_worker_role("calc", "nodus_server_calc::run", true);
}

#[test]
fn aio_dry_run_reaches_both_listener_run_paths() {
    let (_api_held, api_port) = held_port();
    let (_media_held, media_port) = held_port();
    let api = format!("127.0.0.1:{api_port}");
    let media = format!("127.0.0.1:{media_port}");
    let (ok, stdout, stderr) = dry_run(
        "aio",
        &[("NODUS_BIND", &api), ("NODUS_MEDIA_BIND", &media)],
        false,
    );
    assert!(ok, "`nodus aio --dry-run` should exit 0, stderr:\n{stderr}");
    assert_eq!(
        stdout.trim(),
        format!(
            "nodus aio dry run: would start nodus_server_api::run on {api}, and \
             nodus_server_media::run on {media}"
        ),
        "aio's dry run should name both run paths and both addresses"
    );
}

#[test]
fn a_worker_without_a_control_address_says_so() {
    let (ok, stdout, stderr) = dry_run("scan", &[], true);
    assert!(
        ok,
        "`nodus scan --dry-run` should exit 0, stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("on nothing (no NODUS_TELEMETRY_SOCKET or NODUS_TELEMETRY_BIND)"),
        "a worker with no control address should say so, got:\n{stdout}"
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

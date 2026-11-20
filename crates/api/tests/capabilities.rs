//! Every capability the handshake advertises is a route this instance answers, and every
//! admin surface is one a console can ask about.
//!
//! `/api/v1/meta` is the gate: a console draws a panel because a name is in `features` and
//! hides one because it is absent. That makes two failures silent — a name with nothing
//! behind it (a door onto a 404; the audit that started this file found `{"features":[]}`
//! unlocking every panel) and a route with no name (a surface no console can reach). This
//! file is the table that ties the two together, and it fails by naming whatever drifted.
//!
//! It holds four things in step:
//!
//! 1. every advertised name maps to a path that answers — 401 or 405 for the doors behind a
//!    grant, 200 JSON for the public documents, never a 404 and never an HTML shell;
//! 2. the advertised list and the table are the same set, in both directions, so a name
//!    without a route and a route without a name are both test failures;
//! 3. every module under `src/admin/` names at least one feature, read from the `mod`
//!    declarations themselves — a module added with nothing to advertise fails here;
//! 4. every `/api/...` literal registered by those modules still answers, so a route that is
//!    renamed or deleted out from under a feature is caught even when the table is stale.
//!
//! One caveat, stated rather than hidden: `feed_accounts`, `events` and `sync_token` belong
//! to the `nodus-feed` process, which is deployed beside this one and answers on the same
//! origin. This test asserts they are advertised and *not* shadowed by this router; the live
//! smoke test after a deploy is what proves the sibling answers them.

use std::collections::BTreeSet;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use nodus_server_api::{router, AppState, InstanceConfig};
use nodus_server_store::Store;

/// Which process on this origin answers for a feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owner {
    /// This API: the path must be in `router()` and must answer.
    Api,
    /// The recommender's `nodus-feed` process, which shares the domain.
    Feeds,
}

/// One advertised capability and the surface it stands for.
struct Capability {
    name: &'static str,
    /// The first path a client calls for this surface: the one a console would probe.
    path: &'static str,
    owner: Owner,
}

/// The capability table. This is the document; `FEATURES` in `src/meta.rs` is what clients
/// see. They are asserted to agree, so a name reaches a client only with a route beside it.
const CAPABILITIES: &[Capability] = &[
    // The recommender's three, served by `nodus-feed` on this origin.
    Capability {
        name: "feed_accounts",
        path: "/api/v1/feed/accounts",
        owner: Owner::Feeds,
    },
    Capability {
        name: "events",
        path: "/api/v1/events",
        owner: Owner::Feeds,
    },
    Capability {
        name: "sync_token",
        path: "/api/v1/sync/token",
        owner: Owner::Feeds,
    },
    // `admin`: the door itself. `/api/v1/admin/meta` is what a console calls before it
    // renders anything, so it is the surface, not merely a health check.
    Capability {
        name: "admin",
        path: "/api/v1/admin/meta",
        owner: Owner::Api,
    },
    // `moderation`: the report queue, the account actions behind it and the audit trail.
    Capability {
        name: "moderation",
        path: "/api/v1/admin/reports",
        owner: Owner::Api,
    },
    Capability {
        name: "scanners",
        path: "/api/v1/admin/scanners",
        owner: Owner::Api,
    },
    Capability {
        name: "topology",
        path: "/api/v1/admin/topology",
        owner: Owner::Api,
    },
    // `protocol`: the Nodus capability document the console's Protocol panel reads.
    Capability {
        name: "protocol",
        path: "/api/v1/nodus/capabilities",
        owner: Owner::Api,
    },
    Capability {
        name: "remote_blocks",
        path: "/api/v1/admin/federation/remote-blocks",
        owner: Owner::Api,
    },
    Capability {
        name: "polls",
        // The ballot, not the tally: a poll read would reach for a row first, and this test
        // has no database. A GET to a POST-only route answers 405 instantly.
        path: "/api/v1/polls/01j00000000000000000000000/votes",
        owner: Owner::Api,
    },
    Capability {
        name: "batch",
        path: "/api/v1/nodus/batch",
        owner: Owner::Api,
    },
    // The moderation surfaces that were served but unannounced.
    Capability {
        name: "appeals",
        path: "/api/v1/appeals",
        owner: Owner::Api,
    },
    Capability {
        name: "instance_rules",
        path: "/api/v1/admin/rules",
        owner: Owner::Api,
    },
    Capability {
        name: "moderation_rules",
        path: "/api/v1/admin/moderation-rules",
        owner: Owner::Api,
    },
    Capability {
        name: "media_quarantine",
        path: "/api/v1/admin/media/quarantined",
        owner: Owner::Api,
    },
    Capability {
        name: "block_lists",
        path: "/api/v1/admin/domain-blocks/export",
        owner: Owner::Api,
    },
    Capability {
        name: "moderation_stats",
        path: "/api/v1/admin/stats",
        owner: Owner::Api,
    },
    Capability {
        name: "remote_accounts",
        path: "/api/v1/admin/federation/remote-accounts",
        owner: Owner::Api,
    },
    Capability {
        name: "warnings",
        path: "/api/v1/admin/warning_presets",
        owner: Owner::Api,
    },
    Capability {
        name: "escalation",
        path: "/api/v1/admin/escalation",
        owner: Owner::Api,
    },
    // Not `federation_deliveries`: the retry handlers in `admin/federation.rs` already tag
    // their audit rows `federation_delivery`, and a capability the audit filter spells
    // differently from the log is a panel that lists nothing.
    Capability {
        name: "federation_delivery",
        path: "/api/v1/admin/federation/deliveries",
        owner: Owner::Api,
    },
    Capability {
        name: "domain_pauses",
        path: "/api/v1/admin/federation/domain-pauses",
        owner: Owner::Api,
    },
    Capability {
        name: "settings_transfer",
        path: "/api/v1/admin/settings/export",
        owner: Owner::Api,
    },
    // What we told a peer about its own user. The list of forwarded reports is the screen;
    // the per-report forward route hangs off the report itself.
    Capability {
        name: "report_forwarding",
        path: "/api/v1/admin/federation/forwarded",
        owner: Owner::Api,
    },
    // The deletion surface is a GET probe's 405 on the recovery route: the request itself
    // is a DELETE, which this probe does not speak, but the path must be registered.
    Capability {
        name: "account_deletion",
        path: "/api/v1/accounts/{id}/undelete",
        owner: Owner::Api,
    },
    // The drive. `drive` is the folder tree and the content route; `drive_share` and
    // `drive_attach` are probed on their POST-only worker routes, which answer 405 to this
    // GET (see `polls`), because the readable halves are a minted link that is a genuine 404
    // for any token we did not mint and a media upload the drive only feeds.
    Capability {
        name: "drive",
        path: "/api/v1/drive",
        owner: Owner::Api,
    },
    Capability {
        name: "drive_share",
        path: "/api/v1/drive/files/{id}/share",
        owner: Owner::Api,
    },
    Capability {
        name: "drive_attach",
        path: "/api/v1/drive/files/{id}/attach",
        owner: Owner::Api,
    },
];

/// Which features each administration module stands behind.
///
/// Every module declared in `src/admin/mod.rs` needs a row: a module that serves a surface
/// no capability names is a screen the console cannot draw. `src/admin/mod.rs` itself is not
/// listed — the routes it owns (`/admin/meta`, `/admin/overview`, `/admin/measures`,
/// `/admin/audit`, `/admin/alerts`, `/admin/warning_presets`) are covered by `admin`,
/// `moderation_stats` and `warnings`.
const MODULE_FEATURES: &[(&str, &[&str])] = &[
    ("accounts", &["admin"]),
    ("appeals", &["appeals"]),
    ("escalation", &["escalation"]),
    ("blocklist", &["block_lists"]),
    (
        "federation",
        &[
            "remote_blocks",
            "remote_accounts",
            "federation_delivery",
            "domain_pauses",
        ],
    ),
    ("forwarded", &["report_forwarding"]),
    ("media", &["media_quarantine"]),
    ("moderation_rules", &["moderation_rules"]),
    ("reports", &["moderation"]),
    ("rules", &["instance_rules"]),
    ("scanners", &["scanners"]),
    ("settings_transfer", &["settings_transfer"]),
    ("stats", &["moderation_stats"]),
    ("topology", &["topology"]),
];

/// The administration sources, so the table above can be checked against the code instead of
/// against a promise. `include_str!` makes a rename a compile error rather than a stale test.
const ADMIN_SOURCES: &[(&str, &str)] = &[
    ("admin/mod.rs", include_str!("../src/admin/mod.rs")),
    (
        "admin/accounts.rs",
        include_str!("../src/admin/accounts.rs"),
    ),
    ("admin/appeals.rs", include_str!("../src/admin/appeals.rs")),
    (
        "admin/escalation.rs",
        include_str!("../src/admin/escalation.rs"),
    ),
    (
        "admin/blocklist.rs",
        include_str!("../src/admin/blocklist.rs"),
    ),
    (
        "admin/settings_transfer.rs",
        include_str!("../src/admin/settings_transfer.rs"),
    ),
    (
        "admin/federation.rs",
        include_str!("../src/admin/federation.rs"),
    ),
    (
        "admin/forwarded.rs",
        include_str!("../src/admin/forwarded.rs"),
    ),
    ("admin/media.rs", include_str!("../src/admin/media.rs")),
    (
        "admin/moderation_rules.rs",
        include_str!("../src/admin/moderation_rules.rs"),
    ),
    ("admin/reports.rs", include_str!("../src/admin/reports.rs")),
    ("admin/rules.rs", include_str!("../src/admin/rules.rs")),
    (
        "admin/scanners.rs",
        include_str!("../src/admin/scanners.rs"),
    ),
    ("admin/stats.rs", include_str!("../src/admin/stats.rs")),
    (
        "admin/topology.rs",
        include_str!("../src/admin/topology.rs"),
    ),
];

/// Which capability stands behind each route `src/drive.rs` registers.
///
/// The drive is the surface that taught this file its lesson: nine routes served, no name
/// published, and a console that gates on `/api/v1/meta` hid every one of them. The table is
/// asserted against the `.route(...)` calls themselves, so a route added to the drive without
/// a row here fails rather than shipping unannounced.
const DRIVE_ROUTES: &[(&str, &str)] = &[
    ("/api/v1/drive", "drive"),
    ("/api/v1/drive/folders", "drive"),
    ("/api/v1/drive/folders/{id}", "drive"),
    ("/api/v1/drive/files", "drive"),
    ("/api/v1/drive/files/{id}", "drive"),
    ("/api/v1/drive/files/{id}/content", "drive"),
    ("/api/v1/drive/files/{id}/share", "drive_share"),
    // Unauthenticated on purpose — the token is the credential — so it is a route of this
    // API that `route_literals` above would still find, and a row that names it.
    ("/media/share/{token}", "drive_share"),
    ("/api/v1/drive/files/{id}/attach", "drive_attach"),
    // The other half of attach: `POST /api/v1/media {stored_object_id}`. Registered in
    // `src/media.rs`, which this table does not read, so it is listed here deliberately.
    ("/api/v1/media", "drive_attach"),
];

/// The drive's source, read for its route calls.
const DRIVE_SOURCE: &str = include_str!("../src/drive.rs");

fn state() -> AppState {
    // A lazy pool: this test asserts routing and status codes, never a row. A handler that
    // reaches the database stops at the connect attempt, which is still a rejection by the
    // grant in front of it, and still not a 404.
    let store = Store::connect_lazy("postgres://nodus:nodus@127.0.0.1:1/nodus", 1);
    AppState::new(
        store,
        InstanceConfig {
            domain: "social.test".to_owned(),
            base_url: "https://social.test".to_owned(),
            title: "Nodus test".to_owned(),
            description: "A test instance".to_owned(),
            contact_email: None,
            api_version: "4.3.0".to_owned(),
            version: "0.1.0".to_owned(),
            registrations_open: false,
        },
    )
}

/// How long a probe waits for a handler that has no database to reach.
///
/// Some routes reach for a row before any grant is consulted — `/api/v1/scan/nodes/{id}/config` is
/// public
/// and reads one — and the lazy pool above spends sqlx's 30 s acquire timeout failing. That
/// is still a route: the router's fallback answers a 404 at once. So the probe is bounded and
/// a handler still running at the bound counts as present, never as missing.
const PROBE_BUDGET: Duration = Duration::from_secs(2);

/// Status and content type of an unauthenticated `GET`, or `None` if a handler was still
/// running at [`PROBE_BUDGET`].
async fn probe(path: &str) -> Option<(StatusCode, Option<String>)> {
    tokio::time::timeout(PROBE_BUDGET, status_and_type(path))
        .await
        .ok()
}

/// Whether a route answers at all, as opposed to the router's 404 fallback.
async fn answers(template: &str) -> bool {
    let path = concrete(template);
    match probe(&path).await {
        Some((status, _)) => status != StatusCode::NOT_FOUND && status != StatusCode::GONE,
        None => true,
    }
}

/// Whether a path reached a handler rather than the router's fallback.
///
/// [`answers`] cannot be used for the drive: a share token this instance never minted is a
/// deliberate 404 from the handler, so "answers 404" is a healthy route there. The fallback
/// and that refusal are one status apart only by their bodies — the fallback says
/// `no route for GET /...`, a handler says what it looked for — so the body is what is read.
async fn handled(path: &str) -> bool {
    match tokio::time::timeout(PROBE_BUDGET, body_text(path)).await {
        // Still running at the budget: a route, and no fallback answers slowly.
        Err(_) => true,
        Ok((status, body)) => status != StatusCode::GONE && !body.contains("no route for"),
    }
}

/// Status and body of an unauthenticated `GET`.
async fn body_text(path: &str) -> (StatusCode, String) {
    let response = router(state())
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// Status and content type of an unauthenticated `GET`.
async fn status_and_type(path: &str) -> (StatusCode, Option<String>) {
    let response = router(state())
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    (status, content_type)
}

/// The body of a public JSON document.
async fn document(path: &str) -> Value {
    let response = router(state())
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK, "{path} did not answer");
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{path} was not JSON: {error}"))
}

fn advertised(document: &Value) -> Vec<String> {
    document["features"]
        .as_array()
        .unwrap_or_else(|| panic!("no features array in {document}"))
        .iter()
        .map(|name| {
            name.as_str()
                .unwrap_or_else(|| panic!("feature name is not a string: {name}"))
                .to_owned()
        })
        .collect()
}

/// Every `"/api/..."` string literal in a source file.
///
/// The route table is data, not a type, so the only way to read it is to read it. A literal
/// in a comment is single quotes or backticks in this codebase, which is why plain `"` is
/// enough to tell a route from prose about one.
fn route_literals(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = source;
    while let Some(at) = rest.find("\"/api/") {
        rest = &rest[at + 1..];
        let Some(end) = rest.find('"') else { break };
        found.push(rest[..end].to_owned());
        rest = &rest[end..];
    }
    found
}

/// The route templates a file registers with `.route(...)`, read from those calls.
///
/// [`route_literals`] cannot be reused for the drive: `src/drive.rs` also builds URLs for the
/// media service (`/media/{id}/compressed`) that are not routes of this API, and one of the
/// drive's own routes *is* `/media/share/{token}` — so the literal has to be read from the
/// line that registers it. The call and its literal are on separate lines in two places,
/// which is why the literal is taken from the first quoted path after the call opens.
fn registered_routes(source: &str) -> Vec<String> {
    let mut routes = Vec::new();
    let mut expecting = false;
    for line in source.lines() {
        if line.contains(".route(") {
            expecting = true;
        }
        if !expecting {
            continue;
        }
        let Some(at) = line.find("\"/") else { continue };
        let rest = &line[at + 1..];
        let Some(end) = rest.find('"') else { continue };
        routes.push(rest[..end].to_owned());
        expecting = false;
    }
    routes
}

/// The `mod` names a file declares, so the module list cannot be remembered wrongly.
fn declared_modules(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("//") || !line.ends_with(';') {
                return None;
            }
            let name = line.split_once("mod ")?.1.strip_suffix(';')?.trim();
            let valid = !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
            valid.then(|| name.to_owned())
        })
        .collect()
}

/// A route template with its path parameters filled, so it can be requested.
fn concrete(template: &str) -> String {
    let mut path = String::with_capacity(template.len() + 8);
    let mut chars = template.chars();
    while let Some(c) = chars.next() {
        if c == '{' {
            for c in chars.by_ref() {
                if c == '}' {
                    break;
                }
            }
            path.push_str("01j00000000000000000000000");
        } else {
            path.push(c);
        }
    }
    path
}

#[tokio::test]
async fn every_advertised_feature_answers_for_itself() {
    let failures = {
        let mut failures = Vec::new();
        for capability in CAPABILITIES {
            let Some((status, content_type)) = probe(capability.path).await else {
                // Still running at the budget: a route, and no server shell answers slowly.
                continue;
            };
            let answered = status != StatusCode::NOT_FOUND && status != StatusCode::GONE;
            let html = content_type
                .as_deref()
                .is_some_and(|value| value.contains("text/html"));
            match capability.owner {
                // A door behind a grant answers 401; a route that only takes another method
                // answers 405. Both mean the route is there. A 200 is fine only when it is
                // the document itself, never an HTML page from a frontend fallback.
                Owner::Api if !answered => failures.push(format!(
                    "`{}` is advertised but {} answers {status}",
                    capability.name, capability.path
                )),
                Owner::Api if status == StatusCode::OK && html => failures.push(format!(
                    "`{}` is advertised but {} answers an HTML page",
                    capability.name, capability.path
                )),
                Owner::Api => {}
                // The recommender's routes are not mounted here, and must not be: a copy
                // would be a second implementation behind one name.
                Owner::Feeds if status == StatusCode::NOT_FOUND => {}
                Owner::Feeds => failures.push(format!(
                    "`{}` belongs to nodus-feed but this router answers {} with {status}",
                    capability.name, capability.path
                )),
            }
        }
        failures
    };
    assert!(
        failures.is_empty(),
        "the feature list promises surfaces the server does not answer:\n  {}",
        failures.join("\n  ")
    );
}

#[tokio::test]
async fn the_published_list_and_the_capability_table_are_the_same_set() {
    let published: BTreeSet<String> = advertised(&document("/api/v1/meta").await)
        .into_iter()
        .collect();
    let tabled: BTreeSet<String> = CAPABILITIES
        .iter()
        .map(|capability| capability.name.to_owned())
        .collect();

    let unbacked: Vec<&String> = published.difference(&tabled).collect();
    assert!(
        unbacked.is_empty(),
        "advertised in /api/v1/meta with no path in {file}:\n  {unbacked:#?}",
        file = file!()
    );
    let unannounced: Vec<&String> = tabled.difference(&published).collect();
    assert!(
        unannounced.is_empty(),
        "the capability table names features /api/v1/meta does not publish:\n  {unannounced:#?}"
    );

    for capability in CAPABILITIES {
        let name = capability.name;
        assert!(
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "`{name}` is not snake_case"
        );
    }
}

#[tokio::test]
async fn the_handshake_and_the_protocol_screen_publish_one_vocabulary() {
    let handshake = advertised(&document("/api/v1/meta").await);
    let capabilities = document("/api/v1/nodus/capabilities").await;
    assert_eq!(
        capabilities["contract"], "nodus-1",
        "the protocol document must still say which dialect it is"
    );
    assert_eq!(
        advertised(&capabilities),
        handshake,
        "/api/v1/nodus/capabilities publishes a different list from /api/v1/meta; \
         two vocabularies with one meaning is what makes a console's gate untrustworthy"
    );
}

#[tokio::test]
async fn every_admin_module_names_at_least_one_feature() {
    let declared = declared_modules(ADMIN_SOURCES[0].1);
    assert!(
        declared.len() > 5,
        "the module list was not parsed: {declared:?}"
    );

    let tabled: BTreeSet<&str> = MODULE_FEATURES.iter().map(|(name, _)| *name).collect();
    let missing: Vec<&String> = declared
        .iter()
        .filter(|name| !tabled.contains(name.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "admin module(s) with no capability in MODULE_FEATURES — a console cannot ask for \
         them, so nothing is drawn:\n  {missing:#?}"
    );

    let published: BTreeSet<String> = CAPABILITIES
        .iter()
        .map(|capability| capability.name.to_owned())
        .collect();
    for (module, features) in MODULE_FEATURES {
        assert!(
            declared.iter().any(|declared| declared == module),
            "MODULE_FEATURES names `{module}`, which src/admin/mod.rs no longer declares"
        );
        assert!(
            !features.is_empty(),
            "admin module `{module}` stands behind no capability"
        );
        for feature in *features {
            assert!(
                published.contains(*feature),
                "admin module `{module}` claims `{feature}`, which is not advertised"
            );
        }
    }
}

#[tokio::test]
async fn every_drive_route_is_announced() {
    let registered = registered_routes(DRIVE_SOURCE);
    assert!(
        registered.len() >= 9,
        "the drive's route calls were not parsed: {registered:?}"
    );

    let tabled: BTreeSet<&str> = DRIVE_ROUTES.iter().map(|(path, _)| *path).collect();
    let unlisted: Vec<&String> = registered
        .iter()
        .filter(|path| !tabled.contains(path.as_str()))
        .collect();
    assert!(
        unlisted.is_empty(),
        "drive route(s) no capability names — the console hides a door it is never told about, \
         which is how the drive shipped unreachable:\n  {unlisted:#?}"
    );

    let published: BTreeSet<String> = CAPABILITIES
        .iter()
        .map(|capability| capability.name.to_owned())
        .collect();
    for (path, feature) in DRIVE_ROUTES {
        assert!(
            published.contains(*feature),
            "drive route `{path}` claims `{feature}`, which is not advertised"
        );
    }
}

#[tokio::test]
async fn every_drive_route_still_answers() {
    let failures = {
        let mut failures = Vec::new();
        for (template, _) in DRIVE_ROUTES {
            let path = concrete(template);
            if !handled(&path).await {
                failures.push(format!(
                    "the drive registers {template}, which no handler answers"
                ));
            }
        }
        failures
    };
    assert!(
        failures.is_empty(),
        "a drive route is registered but not served:\n  {}",
        failures.join("\n  ")
    );
}

#[tokio::test]
async fn every_registered_admin_route_still_answers() {
    let failures = {
        let mut failures = Vec::new();
        for (file, source) in ADMIN_SOURCES {
            for template in route_literals(source) {
                if !answers(&template).await {
                    failures.push(format!("{file} registers {template}, which answers 404"));
                }
            }
        }
        failures
    };
    assert!(
        failures.is_empty(),
        "an admin route is registered but not served:\n  {}",
        failures.join("\n  ")
    );
}

//! `GET /api/v1/meta`: the handshake every client calls once at boot.
//!
//! The answer is the instance's whole truth. A console gates its doors and panels on the
//! `features` array, so a name that is served here but missing from the response is a
//! surface nobody can reach, and a name that is published but not served is a door that
//! opens onto a 404. One document, one list, one process: a client must not have to ask a
//! second host what this one can do.

use axum::Json;
use axum::http::header;
use axum::response::{IntoResponse, Response};

use nodus_shared::{CONTRACT_VERSION, MIN_CONTRACT_VERSION, Meta};

/// Capabilities this instance serves.
///
/// Names are part of the contract: rename one and old clients lose the feature, because an
/// absent name means unsupported. Additions are safe; removals and renames are not.
///
/// The first three are the recommender's (`feed_accounts`, `events`, `sync_token`), whose
/// service shares this instance; the rest are this API's own doors and panels. `batch`
/// belongs to the nodus extension, which is also served from here.
pub const FEATURES: [&str; 11] = [
    "feed_accounts",
    "events",
    "sync_token",
    "admin",
    "moderation",
    "scanners",
    "topology",
    "protocol",
    "remote_blocks",
    "polls",
    "batch",
];

/// The capability names as owned strings, for documents that serialize their own envelope.
pub fn features() -> Vec<String> {
    FEATURES.iter().map(|name| (*name).to_owned()).collect()
}

/// Report the contract version and every capability this instance serves.
pub async fn meta() -> Response {
    let body = Meta {
        api: "1".to_owned(),
        contract: CONTRACT_VERSION.to_owned(),
        min_contract: MIN_CONTRACT_VERSION.to_owned(),
        features: features(),
    };
    // Safe to cache for a minute: the payload changes only on deploy, and a stale copy can
    // at worst delay a new feature flag by that minute.
    ([(header::CACHE_CONTROL, "public, max-age=60")], Json(body)).into_response()
}

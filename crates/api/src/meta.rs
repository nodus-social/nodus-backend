//! `GET /api/v1/meta`: the handshake every client calls once at boot.
//!
//! The answer is the instance's whole truth. A console gates its doors and panels on the
//! `features` array, so a name that is served here but missing from the response is a
//! surface nobody can reach, and a name that is published but not served is a door that
//! opens onto a 404. One document, one list, one process: a client must not have to ask a
//! second host what this one can do.

use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;

use nodus_shared::{Meta, CONTRACT_VERSION, MIN_CONTRACT_VERSION};

/// Capabilities this instance serves.
///
/// Names are part of the contract: rename one and old clients lose the feature, because an
/// absent name means unsupported. Additions are safe; removals and renames are not.
///
/// A name must describe a surface a client can actually call, and a surface with no name is
/// a panel no console can gate on — which is how `moderation` came to mean "there are
/// reports" while appeals, the instance rules, the spam autopilot, quarantined media and the
/// block-list transfer were all served and all unannounced.
///
/// The first three are the recommender's (`feed_accounts`, `events`, `sync_token`), served by
/// this instance's `nodus-feed` process on the same origin. The rest are answered by this
/// API. `tests/capabilities.rs` holds the feature-to-path table and fails when a name here
/// stops answering or a route appears that no name covers.
pub const FEATURES: [&str; 24] = [
    // Recommender (`nodus-feed`), same origin: `/api/v1/feed/accounts`, `/api/v1/events`,
    // `/api/v1/sync/token`.
    "feed_accounts",
    "events",
    "sync_token",
    // This API's own doors, in the order they were published.
    "admin",
    "moderation",
    "scanners",
    "topology",
    "protocol",
    "remote_blocks",
    "polls",
    "batch",
    // The moderation surfaces the console could not previously see. Each one is a route
    // group in `crate::admin` or `crate::appeals`; the comment names its first path.
    "appeals",          // GET|POST /api/v1/appeals, GET /api/v1/admin/appeals
    "instance_rules",   // GET|POST /api/v1/admin/rules
    "moderation_rules", // GET|POST /api/v1/admin/moderation-rules
    "media_quarantine", // GET /api/v1/admin/media/quarantined
    "block_lists",      // GET /api/v1/admin/domain-blocks/export
    "moderation_stats", // GET /api/v1/admin/stats
    "remote_accounts",  // GET /api/v1/admin/federation/remote-accounts
    "warnings",         // GET /api/v1/admin/warning_presets
    // The two surfaces the last two commits shipped without a name. `federation_delivery`
    // rather than `federation_deliveries` or `deliveries` because it is already the feature
    // string those handlers write to the audit log (`admin/federation.rs`): one spelling for
    // one thing, so the console's audit filter and its capability gate agree.
    "escalation",          // GET|PUT /api/v1/admin/escalation
    "federation_delivery", // GET /api/v1/admin/federation/deliveries
    // The reversible middle between a suspension and nothing: a domain pause expires and
    // is never announced to the peer.
    "domain_pauses", // GET|POST /api/v1/admin/federation/domain-pauses
    // The whole console tuned once and carried to the next instance: rules, presets, the
    // ladder and both domain lists in one versioned document, and a two-phase import.
    "settings_transfer", // GET /api/v1/admin/settings/export
    // The outbound half of the report queue: a report about a remote account leaves this
    // instance as a signed Flag, so the peer's moderators can act on it too.
    "report_forwarding", // POST|GET /api/v1/admin/reports/{id}/forward
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

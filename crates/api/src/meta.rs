//! `GET /api/v1/meta`: the handshake every client calls once at boot.
//!
//! The answer is the instance's whole truth. A console gates its doors and panels on the
//! `features` array, so a name that is served here but missing from the response is a
//! surface nobody can reach, and a name that is published but not served is a door that
//! opens onto a 404. One document, one list, one process: a client must not have to ask a
//! second host what this one can do.

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;

use nodus_shared::{Meta, CONTRACT_VERSION, MIN_CONTRACT_VERSION};

use crate::state::AppState;

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
pub const FEATURES: [&str; 42] = [
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
    // Leaving: a deletion request hides the account and its writing at once, queues a
    // signed Delete for every peer that knows the actor, and erases the profile after the
    // grace period unless the account comes back first.
    "account_deletion", // DELETE /api/v1/accounts/{id}; POST /api/v1/accounts/{id}/undelete
    // The drive: a folder tree, the files in it and the bytes behind them. It was served
    // from the first commit and named from none, so a console that draws only what the
    // handshake advertises hid its door, its page and its composer button — three surfaces
    // built, deployed and unreachable. Split by how a client reaches it: the tree and its
    // content behind the actor's own grant, a minted link that needs no session at all, and
    // the hand-off that turns stored bytes into an attachment.
    "drive",        // GET /api/v1/drive, /drive/folders, /drive/files and the {id} forms
    "drive_share",  // POST /api/v1/drive/files/{id}/share; GET /media/share/{token}
    "drive_attach", // POST /api/v1/drive/files/{id}/attach; POST /api/v1/media {stored_object_id}
    // The client-facing Mastodon surfaces this API has always served and never named. A
    // console that hides a panel because its name is absent hides a working route: these
    // are the collections, the composer's scheduled queue, the notification inbox and the
    // discovery pages the frontend draws. None of them varies by instance, so every one is
    // published unconditionally.
    "favourites",         // GET /api/v1/favourites
    "bookmarks",          // GET /api/v1/bookmarks
    "conversations",      // GET /api/v1/conversations, POST /{id}/read, POST /{id}/mute
    "lists",              // GET|POST /api/v1/lists, /lists/{id}, /lists/{id}/accounts
    "filters",            // GET|POST /api/v2/filters and /api/v1/filters, both with /{id}/keywords
    "scheduled_statuses", // GET /api/v1/scheduled_statuses; DELETE /{id}
    "notifications",      // GET /api/v1/notifications, /clear, /{id}, POST /{id}/dismiss
    "announcements",      // GET /api/v1/announcements; POST /{id}/dismiss
    "search",             // GET /api/v1/search and /api/v2/search
    "directory",          // GET /api/v1/directory
    "markers",            // GET|POST /api/v1/markers
    "preferences",        // GET /api/v1/preferences
    "streaming",          // GET /api/v1/streaming (the SSE tail of the events table)
    "tags",               // GET /api/v1/tags/{name}, /{name}/follow, /{name}/unfollow
];

/// The capability names this deployment can actually honour, as owned strings.
///
/// [`FEATURES`] is the vocabulary, not the answer: a name whose routes need a setting that
/// is absent is a door that opens onto a refusal, so it is withheld rather than advertised.
/// `drive_share` is the first such name — `POST /api/v1/drive/files/{id}/share` signs with
/// `NODUS_DRIVE_SHARE_SECRET` and refuses without one (`crate::drive::share_file`), so an
/// instance that has no secret must not tell a console to draw the button.
///
/// The switch is passed in rather than read here: the binary reads the environment once
/// (`run.rs`) and tests construct the state they mean, so this function stays pure and the
/// same call is made by `/api/v1/meta` and `/api/v1/nodus/capabilities`.
pub fn features(share_links: bool) -> Vec<String> {
    FEATURES
        .iter()
        .filter(|name| **name != "drive_share" || share_links)
        .map(|name| (*name).to_owned())
        .collect()
}

/// Report the contract version and every capability this instance serves.
pub async fn meta(State(state): State<AppState>) -> Response {
    let body = Meta {
        api: "1".to_owned(),
        contract: CONTRACT_VERSION.to_owned(),
        min_contract: MIN_CONTRACT_VERSION.to_owned(),
        features: features(state.drive_share()),
    };
    // Safe to cache for a minute: the payload changes only on deploy, and a stale copy can
    // at worst delay a new feature flag by that minute.
    ([(header::CACHE_CONTROL, "public, max-age=60")], Json(body)).into_response()
}

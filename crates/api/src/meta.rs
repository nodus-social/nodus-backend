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
///
/// `admin` and `moderation` stay: they mean "this instance has an administration (or
/// moderation) area at all". The pages inside those areas are named separately at the end
/// of the list, because a peer that serves a smaller console must hide the pages it does not
/// have without losing the area's door — and a peer that serves them all must draw every
/// one. New names are appended rather than sorted: clients compare the array, so a reorder
/// is churn with no meaning.
pub const FEATURES: [&str; 74] = [
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
    // The settings tab the inbox never had: what to do with each notification kind, stored
    // per account and honoured where the notification is created.
    "notification_settings", // GET|PUT /api/v2/notifications/policy
    "streaming",             // GET /api/v1/streaming (the SSE tail of the events table)
    "tags",                  // GET /api/v1/tags/{name}, /{name}/follow, /{name}/unfollow
    // The administration pages the console draws. `admin` above says the area exists; these
    // say which page inside it is served, so a peer with a smaller console can omit a page
    // without omitting the area. The test table beside `tests/capabilities.rs` names the
    // handler family behind each and whether the route path alone distinguishes it.
    "admin_overview",      // GET /api/v1/admin/overview, /stats, /measures, /alerts
    "admin_announcements", // GET|POST /api/v1/admin/announcements
    "admin_audit",         // GET /api/v1/admin/audit, /audit.csv
    "admin_domains",       // /api/v1/admin/domain_allows, /domain_blocks
    "admin_email",         // /api/v1/admin/email_domain_blocks
    "admin_escalation",    // GET|PUT /api/v1/admin/escalation
    "admin_federation",    // /api/v1/admin/federation/{deliveries,domain-pauses,forwarded}
    "admin_protocol",      // GET /api/v1/nodus/capabilities
    "admin_replies",       // /api/v1/admin/warning_presets
    "admin_rules",         // /api/v1/admin/rules
    "admin_scanners",      // /api/v1/admin/scanners, /scanner_assets, /scans
    "admin_settings",      // /api/v1/admin/settings/{export,import}
    "admin_topology",      // /api/v1/admin/topology, /topology/{name}/logs
    // The moderation sections. `moderation_rules` above already names the rules section;
    // adding the string a second time would publish one page twice, so it is reused.
    "moderation_accounts",   // /api/v1/admin/accounts, /{id}/notes, /{id}/role
    "moderation_appeals",    // /api/v1/admin/appeals, /{id}/decide
    "moderation_federation", // /api/v1/admin/federation/remote-accounts, /domain_blocks
    "moderation_flags",      // /api/v1/admin/flags, /{id}/resolve
    "moderation_media",      // /api/v1/admin/media/quarantined
    "moderation_registrations", // /api/v1/admin/accounts/{id}/approve, /reject
    "moderation_reports",    // /api/v1/admin/reports, /bulk, /{id}/forward
    // The actor's own relationship lists and the verbs that change them. Every account can
    // mute and block, so both names are published unconditionally: a console deciding
    // whether to draw the Muted tab asks before it knows who is signed in.
    "mutes",  // GET /api/v1/mutes; POST /api/v1/accounts/{id}/mute, /unmute
    "blocks", // GET /api/v1/blocks; POST /api/v1/accounts/{id}/block, /unblock
    // The actor's own domain list: one account hiding a host from its timelines and
    // notifications. Distinct from the instance's `remote_blocks` and admin domain blocks.
    // Published unconditionally like `mutes` and `blocks`: every account has the list, and a
    // console decides whether to draw it before it knows who signed in.
    "domain_blocks", // GET|POST|DELETE /api/v1/domain_blocks and /api/v2/domain_blocks
    // The tags a profile shows to other readers, distinct from `tags` (following a tag on
    // one's own account): the public list is also served at
    // `/api/v1/accounts/{id}/featured_tags`, and the owner's verbs manage it.
    "featured_tags", // GET|POST /api/v1/featured_tags, /suggestions; DELETE /{id}
    // The backend-assembled page payloads: a profile with its statuses, a status with its
    // thread. The shell gates its one-call profile and thread screens on this name.
    "pages", // GET /api/v1/pages/profile/{id}, /api/v1/pages/status/{id}
    // Everything this instance holds about one account, in one document a person can keep.
    // The shell's Export tab downloads it; the projection is itself the contract (see
    // `crate::accounts::export`: no credential leaves in an export).
    "exports", // GET /api/v1/accounts/{id}/export
    // The banners an account publishes for its profile. The owner's whole style — nav
    // layout, rail modules, categories — stays private client metadata; only these three
    // regions cross the boundary, so a viewer can draw the banners without learning the
    // arrangement. The read lives at `/api/v1/accounts/{id}/style_public`, under the core
    // accounts group, so this name is for the owner's write.
    "style_public", // PUT /api/v1/style/public
    // Two abilities of the SHELL, not of this API. Upstream Mastodon has no JSON API for
    // either — both live in its HTML settings — and this instance follows: a session is
    // reviewed and signed out with the credential the login minted, and a second factor
    // (TOTP enrolment, verification and recovery codes) is proved by the shell's own
    // login. They are published because the handshake is how a console decides whether to
    // draw those settings sections at all; leaving them out hid both on every instance,
    // including this one. `tests/capabilities.rs` declares them in `SHELL_CAPABILITIES`
    // with the sentence each one stands on, so neither can go unpublished unnoticed.
    "sessions",
    "two_factor",
    // Web Push: the browser's own subscription store, `POST|GET|PUT|DELETE
    // /api/v1/push/subscription`. Slice 1 publishes the surface a client registers on;
    // delivery and encryption are not built yet, so the name says "this instance can hold
    // a subscription", which is exactly what the route does today.
    "push",
    // The media library: a listing of every picture this account uploaded, with usage for
    // each, and a remove route for what is unused. Shipped without a name in `86618da` — a
    // screen nobody could reach — so the web child's tab stayed hidden.
    "media_library", // GET /api/v1/media/library; DELETE /api/v1/media/library/{id}
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

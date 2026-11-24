//! The three schema facts `docs/18-sharding.md` says keep a shard-local account id possible,
//! checked against the migrations themselves rather than against a remembered list.
//!
//! The design note decides where each table would live if this data had to sit on more than
//! one Postgres database. A decision written in prose has no teeth: a table nobody classified,
//! a key the database mints instead of the application, or a foreign key to another account's
//! row becomes expensive only at the moment someone tries to route the query. So this file
//! parses `crates/store/migrations/*.sql` and holds three invariants in both directions — a
//! code fact with no declaration fails, and a declaration with no code fact fails too.
//!
//! 1. No table may mint its own key. A shard-local `account.id` is an application-minted ULID
//!    precisely so that any shard can create a row without coordinating a sequence; a new
//!    `serial`, identity or `nextval` default is how that property would be lost silently.
//! 2. Every shipped table has a bucket (`SHARD-AFFINE`, `GLOBAL-REPLICATED`,
//!    `CROSS-SHARD-BY-DESIGN`) and a one-line reason. An unclassified table is a routing
//!    decision deferred to the day the routing code is written, by whoever is in a hurry.
//! 3. Every foreign key that crosses buckets is named with the rule that keeps it honest.
//!    Dropping the soft ones and keeping the replicated ones is a schema change nobody should
//!    make by accident, and an unnamed new one would be the first cross-shard join.
//!
//! The buckets are §2 of the design note, the rules are §3.1-§3.2, and the key allowlist is
//! §5.14. This file does not re-argue any of it; where it disagrees with the note it says so
//! in a comment on the row.

use std::collections::BTreeSet;
use std::path::Path;

/// Where a table would live if the instance had more than one database. The definitions are
/// `docs/18-sharding.md` §2, verbatim in spirit:
///
/// - affine: the row belongs to one account and travels with it;
/// - replicated: an instance fact, small, read everywhere, copied to every shard;
/// - cross-shard: the row names two accounts, so neither copy is honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucket {
    ShardAffine,
    GlobalReplicated,
    CrossShardByDesign,
}

/// One table and the decision about where it lives.
struct Table {
    name: &'static str,
    bucket: Bucket,
    /// One line, in the design note's own words where the note has a row for the table.
    /// Empty is a failure: a bucket without a reason is a shrug.
    why: &'static str,
}

/// What the migrations ship, bucketed as `docs/18-sharding.md` §2.1-§2.3 buckets it.
///
/// The note's roster is 72 tables (28 / 26 / 18). The parse finds 83: migrations `0062` to
/// `0070` landed after §2 was written and add eleven tables, each marked `QUESTION` below.
/// This is the discrepancy the test reports rather than hides — see the counts assertion in
/// `every_shipped_table_has_a_bucket`.
#[rustfmt::skip]
const TABLES: &[Table] = &[
    // §2.1 SHARD-AFFINE (28).
    Table { name: "account", bucket: Bucket::ShardAffine, why: "The anchor row itself; the shard key's home." },
    Table { name: "account_credential", bucket: Bucket::ShardAffine, why: "Login material for one account, read only at login." },
    Table { name: "account_domain_block", bucket: Bucket::ShardAffine, why: "Reader's own domain mutes; already `(account_id, host)` unique." },
    Table { name: "account_preference", bucket: Bucket::ShardAffine, why: "One row per account, read on every request." },
    Table { name: "account_style_public", bucket: Bucket::ShardAffine, why: "Owner's page layout; served only to that account's token." },
    Table { name: "auth_session", bucket: Bucket::ShardAffine, why: "Browser session for one account." },
    Table { name: "drive_folder", bucket: Bucket::ShardAffine, why: "Owner's namespace; `PRIMARY KEY (account_id, id)`." },
    Table { name: "drive_object", bucket: Bucket::ShardAffine, why: "Same; `0051` states the design intent in its header." },
    Table { name: "featured_tag", bucket: Bucket::ShardAffine, why: "Owner's pinned tags." },
    Table { name: "federation_delivery", bucket: Bucket::ShardAffine, why: "One local actor's outbound work queue. Caveat §3.4." },
    Table { name: "filter", bucket: Bucket::ShardAffine, why: "Owner's filters." },
    Table { name: "filter_keyword", bucket: Bucket::ShardAffine, why: "Child of a filter; same shard by construction." },
    Table { name: "list", bucket: Bucket::ShardAffine, why: "Owner's list." },
    Table { name: "marker", bucket: Bucket::ShardAffine, why: "Owner's read positions; `last_read_id` already has no FK." },
    Table { name: "media_attachment", bucket: Bucket::ShardAffine, why: "Author's media; `status_id` is the author's own post." },
    Table { name: "media_variant", bucket: Bucket::ShardAffine, why: "Child of `media_attachment`; same shard." },
    Table { name: "moderation_strike", bucket: Bucket::ShardAffine, why: "Keyed by affected account, read on that account's write path." },
    Table { name: "notification_policy", bucket: Bucket::ShardAffine, why: "One row per (account, kind), read when writing its notifications." },
    Table { name: "oauth_code", bucket: Bucket::ShardAffine, why: "One account's authorization code." },
    Table { name: "oauth_token", bucket: Bucket::ShardAffine, why: "One account's token; `app_id` points at a replicated table." },
    Table { name: "poll", bucket: Bucket::ShardAffine, why: "Lives with its status, i.e. with the author." },
    Table { name: "poll_tally", bucket: Bucket::ShardAffine, why: "Aggregate per poll option; same shard." },
    Table { name: "scheduled_status", bucket: Bucket::ShardAffine, why: "Owner's queued post." },
    Table { name: "status", bucket: Bucket::ShardAffine, why: "Authored by one account; three foreign refs leave it (§3.2)." },
    Table { name: "status_edit", bucket: Bucket::ShardAffine, why: "Revision of one post; affine only via `status_id`." },
    Table { name: "status_emoji", bucket: Bucket::ShardAffine, why: "Custom emoji used by one post; same shard." },
    Table { name: "status_tag", bucket: Bucket::ShardAffine, why: "Tag of one post; row ships with the author." },
    Table { name: "tag_follow", bucket: Bucket::ShardAffine, why: "Owner's tag subscriptions; indexed by tag for the follower read." },
    // QUESTION: `0062` postdates the §2 roster. Bucketed by the §2 rule from the schema:
    // one account's address confirmation, read only while confirming that account.
    Table { name: "email_confirmation", bucket: Bucket::ShardAffine, why: "One account's address confirmation token; read only at confirmation." },
    // QUESTION: `0064` postdates the roster. One account's TOTP secret, read at login.
    Table { name: "account_totp", bucket: Bucket::ShardAffine, why: "One account's TOTP secret; read only at login." },
    // QUESTION: `0064` postdates the roster. Codes for one account, keyed by it.
    Table { name: "account_recovery_code", bucket: Bucket::ShardAffine, why: "One account's recovery codes; keyed by account." },
    // QUESTION: `0064` postdates the roster. The account is known (`account_id` NOT NULL) even
    // though the row exists before the second factor is answered, unlike `miauth_session`.
    Table { name: "auth_2fa_challenge", bucket: Bucket::ShardAffine, why: "Second-factor challenge for one known account, read at login." },
    // QUESTION: `0067` postdates the roster. One account's reset token.
    Table { name: "password_reset", bucket: Bucket::ShardAffine, why: "One account's password-reset token." },
    // QUESTION: `0068` postdates the roster. Per-account failure budget, keyed by account.
    Table { name: "account_2fa_disable_attempt", bucket: Bucket::ShardAffine, why: "One account's failed-disable budget; keyed by account." },
    // QUESTION: `0069` postdates the roster. A browser subscription belongs to its account.
    Table { name: "push_subscription", bucket: Bucket::ShardAffine, why: "One account's browser push subscriptions." },
    // QUESTION: `0070` postdates the roster. The recipient's queue, same owner as the
    // notification it delivers; see the `notification_id` edge.
    Table { name: "push_outbox", bucket: Bucket::ShardAffine, why: "Recipient's push queue; same owner as its notification." },

    // §2.2 GLOBAL-REPLICATED (26).
    Table { name: "admin_alert", bucket: Bucket::GlobalReplicated, why: "Instance-wide alert stream; `account_id` is a pointer, not an owner." },
    Table { name: "announcement", bucket: Bucket::GlobalReplicated, why: "Instance announcement, staff-written, read by everyone." },
    Table { name: "audit_log", bucket: Bucket::GlobalReplicated, why: "Instance audit trail; `actor_id` nullable." },
    Table { name: "collection_state", bucket: Bucket::GlobalReplicated, why: "Root hash per event-log collection." },
    Table { name: "custom_emoji", bucket: Bucket::GlobalReplicated, why: "Instance emoji set, keyed `(shortcode, host)`." },
    Table { name: "domain_block_subscription", bucket: Bucket::GlobalReplicated, why: "Subscribed blocklists fetched over HTTP." },
    Table { name: "domain_pause", bucket: Bucket::GlobalReplicated, why: "Domain-keyed, evaluated on every read; names no local account." },
    Table { name: "email_domain_block", bucket: Bucket::GlobalReplicated, why: "Registration policy keyed by domain." },
    Table { name: "escalation_policy", bucket: Bucket::GlobalReplicated, why: "Singleton config row (`id boolean PRIMARY KEY DEFAULT true`)." },
    Table { name: "event_log", bucket: Bucket::GlobalReplicated, why: "Hash-chained log; `seq bigserial` is a global sequence (§5.14)." },
    Table { name: "external_id", bucket: Bucket::GlobalReplicated, why: "Foreign-id → local-id map; the routing directory in embryo." },
    Table { name: "instance_allow", bucket: Bucket::GlobalReplicated, why: "Domain allowlist." },
    Table { name: "instance_block", bucket: Bucket::GlobalReplicated, why: "Domain blocklist (severity, reject_media, …)." },
    Table { name: "instance_rule", bucket: Bucket::GlobalReplicated, why: "Published instance rules; `0040` explains why ids stay text." },
    Table { name: "job", bucket: Bucket::GlobalReplicated, why: "The queue every worker polls; polymorphic `subject_id`, no FK." },
    Table { name: "media_node", bucket: Bucket::GlobalReplicated, why: "Placement member list; deliberately no per-object placement table." },
    Table { name: "miauth_session", bucket: Bucket::GlobalReplicated, why: "`UNRESOLVED` by the rule — exists before the account is known; `account_id` is nullable, `0007_miauth.sql:6` (§2.4)." },
    Table { name: "moderation_rule", bucket: Bucket::GlobalReplicated, why: "Keyword/regex rules; `id uuid DEFAULT gen_random_uuid()`." },
    Table { name: "oauth_app", bucket: Bucket::GlobalReplicated, why: "Registered client applications." },
    Table { name: "remote_block", bucket: Bucket::GlobalReplicated, why: "Keyed by remote `actor_uri`." },
    Table { name: "remote_moderation", bucket: Bucket::GlobalReplicated, why: "Decision keyed by remote `actor_uri`, evaluated on every read." },
    Table { name: "scan", bucket: Bucket::GlobalReplicated, why: "Scanner queue over arbitrary subjects (`subject_id` text, no FK)." },
    Table { name: "scanner", bucket: Bucket::GlobalReplicated, why: "Scanner endpoint config." },
    Table { name: "scanner_asset", bucket: Bucket::GlobalReplicated, why: "Hashes/weights/wordlists as `bytea`." },
    Table { name: "scanner_rule", bucket: Bucket::GlobalReplicated, why: "Per-scanner label thresholds." },
    Table { name: "warning_preset", bucket: Bucket::GlobalReplicated, why: "Staff-authored preset text." },
    // QUESTION: `0062` postdates the roster. Keyed by recipient address, no account column.
    Table { name: "email_outbox", bucket: Bucket::GlobalReplicated, why: "Instance-wide outbound mail queue; keyed by address, no account column." },
    // QUESTION: `0063` postdates the roster. Instance policy keyed by CIDR, no account column.
    Table { name: "ip_block", bucket: Bucket::GlobalReplicated, why: "Instance policy keyed by CIDR; names no account." },
    // QUESTION: `0067` postdates the roster. Keyed by email, like `email_domain_block`; the
    // account may not exist, which is the point of a reset request.
    Table { name: "password_reset_attempt", bucket: Bucket::GlobalReplicated, why: "Reset rate limit keyed by email; names no account." },

    // §2.3 CROSS-SHARD-BY-DESIGN (18).
    Table { name: "account_relation", bucket: Bucket::CrossShardByDesign, why: "Two accounts; blocks must be readable from both sides." },
    Table { name: "announcement_read", bucket: Bucket::CrossShardByDesign, why: "Reader's receipt for a global announcement: affine child, replicated parent." },
    Table { name: "appeal", bucket: Bucket::CrossShardByDesign, why: "Global moderation queue; subject one account, decider another." },
    Table { name: "bookmark", bucket: Bucket::CrossShardByDesign, why: "Reader's marker on someone else's status." },
    Table { name: "conversation_mute", bucket: Bucket::CrossShardByDesign, why: "Reader's mute on a root that may be a foreign post." },
    Table { name: "conversation_read", bucket: Bucket::CrossShardByDesign, why: "Reader's read position on a root that may be foreign." },
    Table { name: "favourite", bucket: Bucket::CrossShardByDesign, why: "Two accounts: who favourited, whose post." },
    Table { name: "follow", bucket: Bucket::CrossShardByDesign, why: "Two accounts; the edge is read from both directions." },
    Table { name: "list_account", bucket: Bucket::CrossShardByDesign, why: "List owner's membership of another account." },
    Table { name: "moderator_note", bucket: Bucket::CrossShardByDesign, why: "Staff author, subject account: two accounts on a global record." },
    Table { name: "notification", bucket: Bucket::CrossShardByDesign, why: "Recipient's row about another account's action." },
    Table { name: "poll_vote", bucket: Bucket::CrossShardByDesign, why: "Voter on someone else's poll." },
    Table { name: "report", bucket: Bucket::CrossShardByDesign, why: "Reporter, target, and `status_ids text[]` with no FK by design." },
    Table { name: "report_forward", bucket: Bucket::CrossShardByDesign, why: "Delivery state of a forwarded report to another instance." },
    Table { name: "scan_flag", bucket: Bucket::CrossShardByDesign, why: "Moderator queue row naming a status, an account, a resolver." },
    Table { name: "status_mention", bucket: Bucket::CrossShardByDesign, why: "Mentioned account on someone else's post." },
    Table { name: "status_reaction", bucket: Bucket::CrossShardByDesign, why: "Reactor and author." },
    Table { name: "timeline_entry", bucket: Bucket::CrossShardByDesign, why: "Reader's timeline holding another account's status." },
];

/// What happens to a foreign key when the two buckets are not the same database.
///
/// The verdicts are `docs/18-sharding.md` §3.1 (STAYS / SOFT / MOVE) and §3.2's table, one
/// verdict per edge. Every variant that says SOFT is the same promise: keep the id column,
/// drop the constraint, and replace what the constraint guaranteed with an application
/// invariant — see §3.1 for why cascade is not a substitute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    /// Parent and child are owned by the same account, so they are on one shard by
    /// construction and the constraint can stay. §3.2: **STAYS**.
    SameShard,
    /// The parent may be on another shard; drop the constraint, keep the id. §3.2: **SOFT**.
    Soft,
    /// SOFT, and the child needs a projection of the parent (or a dual write) because the
    /// read that used to follow the FK now starts on the other row's owner. §3.2:
    /// **SOFT + projection**.
    SoftProjection,
    /// SOFT, and the direction that would have been a reverse lookup needs a mirrored copy
    /// on the other account's shard. §3.2: **SOFT + mirror**.
    SoftMirror,
    /// SOFT, and the child must store a copy of a parent column (author id, handle, domain)
    /// so rendering it does not join a foreign account row. §3.2: **SOFT / MOVE**.
    SoftMove,
    /// The parent is GLOBAL-REPLICATED, so a copy exists on every shard and the constraint
    /// is locally valid. §3.1: **STAYS**.
    Replicated,
    /// Both rows already live in the global bucket; this FK never crosses a shard.
    GlobalBoth,
    /// The child row can exist before its account does (`miauth_session.account_id` is
    /// nullable). SOFT because there is no shard to route to yet. §2.4.
    NotYetKnown,
}

impl Rule {
    fn why(self) -> &'static str {
        match self {
            Rule::SameShard => {
                "parent and child share an owner, so the FK is shard-local (§3.2 STAYS)"
            }
            Rule::Soft => {
                "drop the constraint, keep the id; the parent may live elsewhere (§3.1 SOFT)"
            }
            Rule::SoftProjection => {
                "SOFT plus a projection/dual write onto the other owner's shard (§3.2)"
            }
            Rule::SoftMirror => "SOFT plus a mirrored row readable from the other side (§3.2)",
            Rule::SoftMove => "SOFT plus a denormalised parent column on the child (§3.2 MOVE)",
            Rule::Replicated => {
                "parent is replicated to every shard, so the FK is locally valid (§3.1)"
            }
            Rule::GlobalBoth => "both rows are in the global bucket; the edge never crosses",
            Rule::NotYetKnown => {
                "account may not exist yet, so there is no shard to route to (§2.4)"
            }
        }
    }
}

/// One foreign key whose two ends sit in different buckets, and what stops it from becoming a
/// cross-shard join by accident.
struct Edge {
    child: &'static str,
    column: &'static str,
    parent: &'static str,
    rule: Rule,
}

/// Every `REFERENCES` in `crates/store/migrations/` whose child and parent are in different
/// buckets of [`TABLES`], one row per column.
///
/// Edges inside one bucket are deliberately not listed: `status.in_reply_to_id → status` is
/// SOFT in §3.2 but both ends are affine, so this test cannot see it and does not pretend to.
/// The two rows marked "not in §3.2" are edges the note's table omits (`miauth_session` is
/// argued in §2.4 instead, and `moderation_rule.created_by` is missing from §3.2 entirely);
/// their rule follows the neighbouring rows.
#[rustfmt::skip]
const EDGES: &[Edge] = &[
    Edge { child: "follow", column: "account_id", parent: "account", rule: Rule::SameShard },
    Edge { child: "follow", column: "target_account_id", parent: "account", rule: Rule::Soft },
    Edge { child: "status_mention", column: "status_id", parent: "status", rule: Rule::SameShard },
    Edge { child: "status_mention", column: "account_id", parent: "account", rule: Rule::SoftProjection },
    Edge { child: "favourite", column: "account_id", parent: "account", rule: Rule::SameShard },
    Edge { child: "favourite", column: "status_id", parent: "status", rule: Rule::Soft },
    Edge { child: "bookmark", column: "account_id", parent: "account", rule: Rule::SameShard },
    Edge { child: "bookmark", column: "status_id", parent: "status", rule: Rule::Soft },
    Edge { child: "timeline_entry", column: "account_id", parent: "account", rule: Rule::SameShard },
    Edge { child: "timeline_entry", column: "status_id", parent: "status", rule: Rule::SoftMove },
    Edge { child: "notification", column: "account_id", parent: "account", rule: Rule::SameShard },
    Edge { child: "notification", column: "from_account_id", parent: "account", rule: Rule::SoftMove },
    Edge { child: "notification", column: "status_id", parent: "status", rule: Rule::Soft },
    Edge { child: "oauth_token", column: "app_id", parent: "oauth_app", rule: Rule::Replicated },
    Edge { child: "oauth_code", column: "app_id", parent: "oauth_app", rule: Rule::Replicated },
    Edge { child: "status_reaction", column: "status_id", parent: "status", rule: Rule::Soft },
    Edge { child: "status_reaction", column: "account_id", parent: "account", rule: Rule::SameShard },
    // Not in §3.2's table; §2.4 is where this one is argued.
    Edge { child: "miauth_session", column: "account_id", parent: "account", rule: Rule::NotYetKnown },
    Edge { child: "admin_alert", column: "account_id", parent: "account", rule: Rule::Soft },
    Edge { child: "admin_alert", column: "acknowledged_by", parent: "account", rule: Rule::Soft },
    Edge { child: "report", column: "account_id", parent: "account", rule: Rule::Soft },
    Edge { child: "report", column: "target_account_id", parent: "account", rule: Rule::Soft },
    Edge { child: "audit_log", column: "actor_id", parent: "account", rule: Rule::Soft },
    Edge { child: "list_account", column: "list_id", parent: "list", rule: Rule::SameShard },
    Edge { child: "list_account", column: "account_id", parent: "account", rule: Rule::Soft },
    Edge { child: "account_relation", column: "account_id", parent: "account", rule: Rule::SameShard },
    Edge { child: "account_relation", column: "target_account_id", parent: "account", rule: Rule::SoftMirror },
    Edge { child: "announcement_read", column: "account_id", parent: "account", rule: Rule::SameShard },
    Edge { child: "announcement_read", column: "announcement_id", parent: "announcement", rule: Rule::Replicated },
    Edge { child: "conversation_read", column: "account_id", parent: "account", rule: Rule::SameShard },
    Edge { child: "conversation_read", column: "root_id", parent: "status", rule: Rule::Soft },
    Edge { child: "conversation_mute", column: "account_id", parent: "account", rule: Rule::SameShard },
    Edge { child: "conversation_mute", column: "root_id", parent: "status", rule: Rule::Soft },
    Edge { child: "report", column: "assigned_account_id", parent: "account", rule: Rule::Soft },
    Edge { child: "report", column: "action_taken_by_account_id", parent: "account", rule: Rule::Soft },
    Edge { child: "moderator_note", column: "account_id", parent: "account", rule: Rule::Soft },
    Edge { child: "moderator_note", column: "author_id", parent: "account", rule: Rule::Soft },
    Edge { child: "scan_flag", column: "scan_id", parent: "scan", rule: Rule::GlobalBoth },
    Edge { child: "scan_flag", column: "status_id", parent: "status", rule: Rule::Soft },
    Edge { child: "scan_flag", column: "account_id", parent: "account", rule: Rule::Soft },
    Edge { child: "scan_flag", column: "resolved_by", parent: "account", rule: Rule::Soft },
    Edge { child: "poll_vote", column: "poll_id", parent: "poll", rule: Rule::Soft },
    Edge { child: "poll_vote", column: "account_id", parent: "account", rule: Rule::SameShard },
    Edge { child: "appeal", column: "account_id", parent: "account", rule: Rule::Soft },
    Edge { child: "appeal", column: "decided_by", parent: "account", rule: Rule::Soft },
    // Not in §3.2's table (`0041_moderation_rules.sql:27`); follows `updated_by`/`created_by`.
    Edge { child: "moderation_rule", column: "created_by", parent: "account", rule: Rule::Soft },
    Edge { child: "moderation_strike", column: "rule_id", parent: "moderation_rule", rule: Rule::Replicated },
    Edge { child: "escalation_policy", column: "updated_by", parent: "account", rule: Rule::Soft },
    Edge { child: "domain_pause", column: "created_by", parent: "account", rule: Rule::Soft },
    Edge { child: "push_outbox", column: "notification_id", parent: "notification", rule: Rule::SameShard },
];

/// A key the database assigns instead of the application, and why the design tolerates it.
struct AssignedKey {
    file: &'static str,
    table: &'static str,
    column: &'static str,
    why: &'static str,
}

/// The only database-assigned keys in the schema, per `docs/18-sharding.md` §5.14.
///
/// The note names two, not one: `status_edit.id` is a per-shard identity (fine — ordering is
/// `created_at DESC, id DESC` within one `status_id`, which never crosses shards), and
/// `event_log.seq` is a genuinely global `bigserial` — a shard cannot mint it, which is why
/// that table is filed GLOBAL-REPLICATED. Dropping the second row would make this test fail
/// on a key the design blesses.
const ASSIGNED_KEYS: &[AssignedKey] = &[
    AssignedKey {
        file: "0006_event_log.sql",
        table: "event_log",
        column: "seq",
        why: "bigserial hash-chain position; genuinely global, so event_log stays in the global bucket (§5.14, §2.1).",
    },
    AssignedKey {
        file: "0052_status_edit.sql",
        table: "status_edit",
        column: "id",
        why: "per-shard identity, ordered only within one status_id, which never crosses shards (§2.4, §5.14).",
    },
];

/// One migration file, read from disk so that a file added tomorrow is scanned without a
/// hand-maintained `include_str!` list (the design note's §6 calls that list the guard test's
/// own weakness; here the directory is the list).
struct Migration {
    file: String,
    source: String,
}

fn migrations() -> Vec<Migration> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../store/migrations");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()))
        .map(|entry| entry.expect("migration directory entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|path| Migration {
            file: path
                .file_name()
                .expect("migration file name")
                .to_string_lossy()
                .into_owned(),
            source: std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display())),
        })
        .collect()
}

/// One line of a migration, with the table whose block contains it.
struct TableLine {
    table: String,
    line: usize,
    sql: String,
}

/// Every SQL line of a migration, annotated with its table.
///
/// A `CREATE TABLE` block runs to `);`; an `ALTER TABLE` runs to `;`. Foreign keys and
/// identity columns are only ever written inside one of those, so the enclosing table is
/// always the block opened above. `--` starts a comment to end of line in every migration
/// here, which is how prose about `REFERENCES` stays out of the parse.
fn table_lines(migration: &Migration) -> Vec<TableLine> {
    let mut lines = Vec::new();
    // (table, opened by ALTER) — ALTER closes on `;`, CREATE on `);`.
    let mut block: Option<(String, bool)> = None;
    for (index, raw) in migration.source.lines().enumerate() {
        let sql = raw.split("--").next().unwrap_or("").trim();
        if sql.is_empty() {
            continue;
        }
        if let Some(rest) = sql.strip_prefix("CREATE TABLE ") {
            let rest = rest.strip_prefix("IF NOT EXISTS ").unwrap_or(rest);
            let name = rest
                .split(|character: char| character.is_whitespace() || character == '(')
                .next()
                .unwrap_or("");
            block = Some((name.to_owned(), false));
        } else if let Some(rest) = sql.strip_prefix("ALTER TABLE ") {
            let name = rest.split_whitespace().next().unwrap_or("");
            block = Some((name.to_owned(), true));
        }
        let Some((table, altered)) = &block else {
            continue;
        };
        lines.push(TableLine {
            table: table.clone(),
            line: index + 1,
            sql: sql.to_owned(),
        });
        if (*altered && sql.ends_with(';')) || (!*altered && sql.ends_with(");")) {
            block = None;
        }
    }
    lines
}

fn shipped_tables() -> Vec<(String, String)> {
    let mut tables = Vec::new();
    for migration in migrations() {
        for entry in table_lines(&migration) {
            if entry.sql.starts_with("CREATE TABLE ") {
                tables.push((entry.table, format!("{}:{}", migration.file, entry.line)));
            }
        }
    }
    tables
}

fn bucket_of(name: &str) -> Option<Bucket> {
    TABLES
        .iter()
        .find(|table| table.name == name)
        .map(|table| table.bucket)
}

/// One `REFERENCES` found in a migration.
struct FoundEdge {
    file: String,
    line: usize,
    child: String,
    column: String,
    parent: String,
}

fn foreign_keys(migration: &Migration) -> Vec<FoundEdge> {
    let mut found = Vec::new();
    for entry in table_lines(migration) {
        let Some(at) = entry.sql.find("REFERENCES") else {
            continue;
        };
        let parent = entry.sql[at + "REFERENCES".len()..]
            .trim_start()
            .split(|character: char| character.is_whitespace() || character == '(')
            .next()
            .unwrap_or("")
            .to_owned();
        let columns = match entry.sql.find("FOREIGN KEY") {
            Some(at) => {
                let after = &entry.sql[at + "FOREIGN KEY".len()..];
                let open = after.find('(').map_or(after.len(), |open| open + 1);
                let close = after.find(')').unwrap_or(after.len());
                after[open..close]
                    .split(',')
                    .map(|column| column.trim().to_owned())
                    .collect::<Vec<_>>()
            }
            None => vec![inline_column(&entry.sql)],
        };
        for column in columns {
            found.push(FoundEdge {
                file: migration.file.clone(),
                line: entry.line,
                child: entry.table.clone(),
                column,
                parent: parent.clone(),
            });
        }
    }
    found
}

/// The column an inline `column type REFERENCES parent` declares. `ALTER TABLE` writes the
/// same thing behind `ADD COLUMN`, so the first token is one word too early there.
fn inline_column(sql: &str) -> String {
    let mut tokens = sql.split_whitespace();
    match tokens.next() {
        Some("ADD") => tokens.nth(1).unwrap_or("").to_owned(),
        Some(first) => first.to_owned(),
        None => String::new(),
    }
}

/// One database-assigned key found in a migration.
struct FoundKey {
    file: String,
    line: usize,
    table: String,
    column: String,
}

fn database_assigned_keys(migration: &Migration) -> Vec<FoundKey> {
    let mut found = Vec::new();
    for entry in table_lines(migration) {
        let words: Vec<&str> = entry.sql.split_whitespace().collect();
        let is_serial = words
            .iter()
            .any(|word| matches!(*word, "serial" | "bigserial" | "smallserial"));
        let is_identity = entry.sql.contains("AS IDENTITY");
        let is_sequence = entry.sql.contains("nextval(");
        if !(is_serial || is_identity || is_sequence) {
            continue;
        }
        found.push(FoundKey {
            file: migration.file.clone(),
            line: entry.line,
            table: entry.table.clone(),
            column: words.first().copied().unwrap_or("").to_owned(),
        });
    }
    found
}

/// No table may mint its own key.
///
/// `account.id` is an application-minted ULID so that any shard can create a row without
/// asking a sequence — that is what makes rows movable. A new `serial`, identity column or
/// `nextval` default hands key minting back to one database; the row then either cannot be
/// created on another shard or needs a global sequence round-trip on every insert. The
/// allowlist is the design note's §5.14: `status_edit.id` is per-shard and ordered only
/// within one post, `event_log.seq` is global because the log must stay global.
#[test]
fn no_table_mints_its_own_key_except_the_named_ones() {
    let sources = migrations();
    assert!(
        sources.len() >= 60,
        "read {} migrations from crates/store/migrations; the parse has gone blind",
        sources.len()
    );

    let mut found = Vec::new();
    for migration in &sources {
        found.extend(database_assigned_keys(migration));
    }

    let declared: BTreeSet<(&str, &str, &str)> = ASSIGNED_KEYS
        .iter()
        .map(|key| (key.file, key.table, key.column))
        .collect();
    let seen: BTreeSet<(&str, &str, &str)> = found
        .iter()
        .map(|key| (key.file.as_str(), key.table.as_str(), key.column.as_str()))
        .collect();

    let new: Vec<String> = found
        .iter()
        .filter(|key| {
            !declared.contains(&(key.file.as_str(), key.table.as_str(), key.column.as_str()))
        })
        .map(|key| {
            format!(
                "{}:{} {}.{} — add it to ASSIGNED_KEYS only if docs/18-sharding.md §5.14 \
                 allows a database-assigned key here",
                key.file, key.line, key.table, key.column
            )
        })
        .collect();
    assert!(
        new.is_empty(),
        "a migration lets Postgres mint a key that the design does not name:\n  {}",
        new.join("\n  ")
    );

    let vanished: Vec<String> = declared
        .difference(&seen)
        .map(|(file, table, column)| {
            format!(
                "ASSIGNED_KEYS names {file} {table}.{column}, but the migration has no \
                 identity/serial/sequence default there; remove the row"
            )
        })
        .collect();
    assert!(
        vanished.is_empty(),
        "the key allowlist is stale:\n  {}",
        vanished.join("\n  ")
    );

    for key in ASSIGNED_KEYS {
        assert!(
            key.why.len() > 40,
            "{} {}.{} is allowlisted without saying why the design tolerates it",
            key.file,
            key.table,
            key.column
        );
    }
}

/// Every table a migration ships has a bucket and a reason.
///
/// An unclassified table is a table whose rows would be placed at shard time by whoever is
/// writing the routing code, under deadline, without the analysis. Classifying it is cheap
/// now and structural later; the design note is the argument, this table is the ledger. A
/// bucket with no reason is the same failure one step quieter, so a reason is required too.
#[test]
fn every_shipped_table_has_a_bucket() {
    let shipped = shipped_tables();
    assert!(
        shipped.len() >= 60,
        "read {} CREATE TABLE statements from crates/store/migrations; the parse has gone blind",
        shipped.len()
    );

    let shipped_names: BTreeSet<&str> = shipped.iter().map(|(name, _)| name.as_str()).collect();
    let tabled: BTreeSet<&str> = TABLES.iter().map(|table| table.name).collect();

    assert_eq!(
        shipped_names.len(),
        shipped.len(),
        "a table is created twice in the migrations, so `bucket_of` would answer for both"
    );
    assert_eq!(
        tabled.len(),
        TABLES.len(),
        "TABLES names a table twice; one table has one bucket"
    );

    let unclassified: Vec<String> = shipped_names
        .difference(&tabled)
        .map(|name| {
            let at = shipped
                .iter()
                .find(|(shipped, _)| shipped == name)
                .map(|(_, at)| at.as_str())
                .unwrap_or("?");
            format!(
                "{name} (created at {at}) is shipped with no bucket — add it to TABLES with \
                 its docs/18-sharding.md §2 bucket and a one-line reason"
            )
        })
        .collect();
    assert!(
        unclassified.is_empty(),
        "a migration ships a table the design has not placed:\n  {}",
        unclassified.join("\n  ")
    );

    let vanished: Vec<String> = tabled
        .difference(&shipped_names)
        .map(|name| {
            format!(
                "TABLES classifies `{name}`, but no migration creates it — a bucket for a table \
                 that is gone is a permission slip for a name that will be reused"
            )
        })
        .collect();
    assert!(
        vanished.is_empty(),
        "the classification is stale:\n  {}",
        vanished.join("\n  ")
    );

    for table in TABLES {
        assert!(
            table.why.split_whitespace().count() >= 2,
            "`{}` is classified without a reason; an unreasoned bucket cannot be argued with",
            table.name
        );
    }

    let count = |bucket: Bucket| TABLES.iter().filter(|table| table.bucket == bucket).count();
    // docs/18-sharding.md §2 says 28 / 26 / 18 = 72. The eleven rows marked QUESTION above
    // are migrations 0062-0070 landing after that roster; this is the parse's answer, kept
    // exact so the difference has to be a deliberate edit rather than a quiet drift.
    assert_eq!(
        (
            TABLES.len(),
            count(Bucket::ShardAffine),
            count(Bucket::GlobalReplicated),
            count(Bucket::CrossShardByDesign),
        ),
        (83, 36, 29, 18),
        "the doc's roster is 72 (28 affine / 26 global / 18 cross-shard); the parse finds \
         83, and the extra eleven must be the QUESTION rows above"
    );
}

/// Every foreign key between two buckets is named, with the rule that keeps it honest.
///
/// Under shards an FK between buckets is either dropped for a soft reference (and the query
/// that trusted it rewritten) or kept because the parent is replicated. Both are real work;
/// the failure mode this catches is a new column that references another account's row and
/// is not noticed until a query starts joining across the network. The reverse direction is
/// just as important: a rule for an edge that no longer exists is a stale promise, and a
/// rewritten query must lose its exemption rather than inherit it.
#[test]
fn every_cross_bucket_foreign_key_is_named() {
    let sources = migrations();
    let mut found = Vec::new();
    for migration in &sources {
        found.extend(foreign_keys(migration));
    }
    assert!(
        found.len() >= 40,
        "read {} REFERENCES from crates/store/migrations; the parse has gone blind",
        found.len()
    );

    let crossing: Vec<&FoundEdge> = found
        .iter()
        .filter(|edge| {
            let child = bucket_of(&edge.child).unwrap_or_else(|| {
                panic!(
                    "{}:{} references from `{}`, which has no bucket; fix \
                     every_shipped_table_has_a_bucket first",
                    edge.file, edge.line, edge.child
                )
            });
            let parent = bucket_of(&edge.parent).unwrap_or_else(|| {
                panic!(
                    "{}:{} `{}.{}` references `{}`, which has no bucket; fix \
                     every_shipped_table_has_a_bucket first",
                    edge.file, edge.line, edge.child, edge.column, edge.parent
                )
            });
            child != parent
        })
        .collect();

    let declared: BTreeSet<(&str, &str, &str)> = EDGES
        .iter()
        .map(|edge| (edge.child, edge.column, edge.parent))
        .collect();
    let seen: BTreeSet<(&str, &str, &str)> = crossing
        .iter()
        .map(|edge| {
            (
                edge.child.as_str(),
                edge.column.as_str(),
                edge.parent.as_str(),
            )
        })
        .collect();

    let unlisted: Vec<String> = crossing
        .iter()
        .filter(|edge| {
            !declared.contains(&(
                edge.child.as_str(),
                edge.column.as_str(),
                edge.parent.as_str(),
            ))
        })
        .map(|edge| {
            let child = bucket_of(&edge.child).expect("checked above");
            let parent = bucket_of(&edge.parent).expect("checked above");
            format!(
                "{}:{} `{}.{}` ({child:?}) -> `{}` ({parent:?}) — add it to EDGES with the \
                 rule that keeps it honest (docs/18-sharding.md §3.1-§3.2)",
                edge.file, edge.line, edge.child, edge.column, edge.parent
            )
        })
        .collect();
    assert!(
        unlisted.is_empty(),
        "a foreign key crosses buckets and is not named:\n  {}",
        unlisted.join("\n  ")
    );

    let vanished: Vec<String> = declared
        .difference(&seen)
        .map(|(child, column, parent)| {
            format!(
                "EDGES names `{child}.{column}` -> `{parent}`, but no migration has that \
                 foreign key; remove the row, or the rule outlives the edge it protected"
            )
        })
        .collect();
    assert!(
        vanished.is_empty(),
        "the cross-bucket edge list is stale:\n  {}",
        vanished.join("\n  ")
    );

    for edge in EDGES {
        assert!(
            !edge.rule.why().is_empty(),
            "`{}.{}` -> `{}` has no rule",
            edge.child,
            edge.column,
            edge.parent
        );
    }
}

//! Rules that act on their own: a pattern, a scope and an action, evaluated while a post
//! is stored.
//!
//! The instance's code of conduct (`rules`) is what a person files a report *against*.
//! This module is the part that does not need the person: an administrator writes "posts
//! containing this phrase are flagged", and from then on ingest does the reading.
//!
//! Three things keep that from becoming a silent machine:
//!
//! * every application writes an audit row naming the rule id and name, what matched and
//!   where, and increments `hits`;
//! * `flag`, `silence` and `suspend` all leave a report in the queue whose body names the
//!   rule, so a moderator sees the decision the instance already made;
//! * `silence` and `suspend` go through [`moderation::apply_action_in`], the same call the
//!   console's buttons use, so the state they set is the state every other surface reads.
//!
//! Matching runs on the ingest path, so it is bounded in three places: how many rules one
//! post is tested against ([`RULE_CAP`]), how long a pattern may be ([`PATTERN_MAX_BYTES`])
//! and how much text is scanned ([`TEXT_MAX_BYTES`]). The regex engine is the `regex`
//! crate, whose searches are linear in the haystack, not backtracking.

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Connection, FromRow, PgConnection, PgPool};

use crate::moderation::{self, Action, NewReport};

/// How many enabled rules a single post is tested against.
///
/// A rule set is policy, not a search index: an instance cannot need hundreds of patterns
/// on the ingest path. Thirty-two keeps the worst case (32 compiles and 32 scans of a
/// 4 KiB post) comfortably below a millisecond, and the cap is applied in SQL so a
/// thousand stored rules cost nothing until they reach the front of the queue.
pub const RULE_CAP: i64 = 32;

/// The longest pattern a rule may store, in bytes. Enforced by the migration's CHECK as
/// well as here, because rows are also written by operators with a psql prompt.
pub const PATTERN_MAX_BYTES: usize = 512;

/// How much of a post is scanned. The longest local post is 500 characters, so this only
/// truncates federated text; a keyword past this point is not searched for.
pub const TEXT_MAX_BYTES: usize = 4096;

/// The longest rule name a console has to render in a report body.
pub const NAME_MAX_CHARS: usize = 120;

/// The compiled size budget for one pattern. A 512-byte pattern is nowhere near it; the
/// limit is here so a pathological-but-legal pattern fails at creation instead of on
/// every delivery.
const COMPILED_SIZE_LIMIT: usize = 1 << 20;

/// How much of the matched text is copied into the audit row and the report body.
const EXCERPT_MAX_CHARS: usize = 200;

pub const KIND_KEYWORD: &str = "keyword";
pub const KIND_REGEX: &str = "regex";
pub const KIND_DOMAIN: &str = "domain";

pub const SCOPES: [&str; 3] = ["inbound", "local", "both"];
pub const ACTIONS: [&str; 3] = ["flag", "silence", "suspend"];
pub const KINDS: [&str; 3] = [KIND_KEYWORD, KIND_REGEX, KIND_DOMAIN];

const COLUMNS: &str = "id::text AS id, name, pattern, pattern_kind, scope, action, enabled, \
     created_by, created_at, updated_at, hits";

/// One rule as stored.
#[derive(Debug, Clone, FromRow)]
pub struct RuleRow {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub pattern_kind: String,
    pub scope: String,
    pub action: String,
    pub enabled: bool,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub hits: i64,
}

/// Why a pattern was refused. The position is a byte offset into the pattern, which is
/// what an administrator needs to fix it and what a bare "invalid regex" never says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    Empty,
    TooLong { length: usize, max: usize },
    UnknownKind(String),
    Regex { position: usize, message: String },
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "a rule needs a pattern"),
            Self::TooLong { length, max } => write!(
                f,
                "the pattern is {length} bytes; the longest allowed is {max}"
            ),
            Self::UnknownKind(kind) => write!(
                f,
                "pattern_kind must be one of keyword, regex, domain, not {kind}"
            ),
            Self::Regex { position, message } => write!(
                f,
                "the pattern is not a valid regex: parse error at byte {position}: {message}"
            ),
        }
    }
}

/// A match: where it is and what it says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub start: usize,
    pub end: usize,
    pub excerpt: String,
}

/// A pattern that fired and what was done about it.
#[derive(Debug, Clone)]
pub struct Fired {
    pub rule_id: String,
    pub rule_name: String,
    pub action: String,
    pub hit: Hit,
    pub report_id: String,
}

/// Refuses a pattern no ingest pass could run: empty, too long, an unknown kind, or a
/// regex that does not compile.
pub fn validate_pattern(kind: &str, pattern: &str) -> Result<(), PatternError> {
    if pattern.trim().is_empty() {
        return Err(PatternError::Empty);
    }
    if pattern.len() > PATTERN_MAX_BYTES {
        return Err(PatternError::TooLong {
            length: pattern.len(),
            max: PATTERN_MAX_BYTES,
        });
    }
    if !KINDS.contains(&kind) {
        return Err(PatternError::UnknownKind(kind.to_owned()));
    }
    if kind == KIND_REGEX {
        compile(pattern)?;
    }
    Ok(())
}

/// Compiles a regex with the engine's budget, reporting the byte offset of a syntax error.
///
/// [`regex::Error`] keeps only the rendered message, so the span is recovered from the
/// pattern itself: re-parsing with `regex-syntax` (the same front end) yields the exact
/// offset. If that second parse somehow succeeds, offset 0 is reported rather than
/// pretending to know.
fn compile(pattern: &str) -> Result<regex::Regex, PatternError> {
    let built = regex::RegexBuilder::new(pattern)
        .size_limit(COMPILED_SIZE_LIMIT)
        .build();
    match built {
        Ok(regex) => Ok(regex),
        Err(error) => {
            let (position, message) = match regex_syntax::ast::parse::Parser::new().parse(pattern) {
                Err(parsed) => (parsed.span().start.offset, parsed.kind().to_string()),
                Ok(_) => (0, error.to_string()),
            };
            Err(PatternError::Regex { position, message })
        }
    }
}

/// Tests one rule's pattern against a sample without touching the database.
///
/// Used by both the ingest path and the console's dry run, so the answer an administrator
/// sees before enabling a rule is the answer ingest will give.
pub fn test(kind: &str, pattern: &str, sample: &str) -> Result<Option<Hit>, PatternError> {
    validate_pattern(kind, pattern)?;
    let haystack = scan_text(sample);
    let found = match kind {
        KIND_KEYWORD => {
            // An escaped literal, case-insensitive: the `regex` engine gives back real
            // byte offsets, which lowercasing the haystack would not.
            let regex = regex::RegexBuilder::new(&regex::escape(pattern))
                .case_insensitive(true)
                .size_limit(COMPILED_SIZE_LIMIT)
                .build()
                .map_err(|error| PatternError::Regex {
                    position: 0,
                    message: error.to_string(),
                })?;
            regex
                .find(haystack)
                .map(|found| (found.start(), found.end()))
        }
        KIND_REGEX => {
            let regex = compile(pattern)?;
            regex
                .find(haystack)
                .map(|found| (found.start(), found.end()))
        }
        KIND_DOMAIN => {
            // A host token, not a substring: `evil.example` must not match
            // `notevil.example.org`. Group 1 is the host itself, so the span an
            // administrator sees does not include the boundary character.
            let regex = regex::RegexBuilder::new(&format!(
                r"(?i)(?:^|[^a-z0-9.-])((?:[a-z0-9-]+\.)*{})(?:$|[^a-z0-9.-])",
                regex::escape(pattern)
            ))
            .size_limit(COMPILED_SIZE_LIMIT)
            .build()
            .map_err(|error| PatternError::Regex {
                position: 0,
                message: error.to_string(),
            })?;
            regex
                .captures(haystack)
                .and_then(|found| found.get(1).map(|host| (host.start(), host.end())))
        }
        other => return Err(PatternError::UnknownKind(other.to_owned())),
    };
    Ok(found.map(|(start, end)| Hit {
        start,
        end,
        excerpt: excerpt(&haystack[start..end]),
    }))
}

/// The part of a post a rule is allowed to read: at most [`TEXT_MAX_BYTES`], cut on a
/// character boundary so a multi-byte character is never split.
#[must_use]
pub fn scan_text(sample: &str) -> &str {
    if sample.len() <= TEXT_MAX_BYTES {
        return sample;
    }
    let mut end = TEXT_MAX_BYTES;
    while end > 0 && !sample.is_char_boundary(end) {
        end -= 1;
    }
    &sample[..end]
}

fn excerpt(matched: &str) -> String {
    let clipped: String = matched.chars().take(EXCERPT_MAX_CHARS).collect();
    if clipped.len() < matched.len() {
        format!("{clipped}…")
    } else {
        clipped
    }
}

// ---------------------------------------------------------------------------------------
// CRUD, for the console
// ---------------------------------------------------------------------------------------

pub async fn rules(pool: &PgPool) -> Result<Vec<RuleRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM moderation_rule ORDER BY created_at DESC, id LIMIT 500"
    ))
    .fetch_all(pool)
    .await
}

pub async fn rule(pool: &PgPool, id: &str) -> Result<Option<RuleRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM moderation_rule WHERE id = $1::uuid"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// A new rule as the console describes it.
#[derive(Debug, Clone)]
pub struct NewRule<'a> {
    pub name: &'a str,
    pub pattern: &'a str,
    pub pattern_kind: &'a str,
    pub scope: &'a str,
    pub action: &'a str,
    pub enabled: bool,
    pub created_by: Option<&'a str>,
}

pub async fn create(pool: &PgPool, new: &NewRule<'_>) -> Result<RuleRow, sqlx::Error> {
    sqlx::query_as(&format!(
        "INSERT INTO moderation_rule \
             (name, pattern, pattern_kind, scope, action, enabled, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {COLUMNS}"
    ))
    .bind(new.name)
    .bind(new.pattern)
    .bind(new.pattern_kind)
    .bind(new.scope)
    .bind(new.action)
    .bind(new.enabled)
    .bind(new.created_by)
    .fetch_one(pool)
    .await
}

/// Every field is a replacement, not a patch: the caller reads the row, merges the form
/// over it and sends the result, so a column can never be left holding half of two edits.
#[derive(Debug, Clone)]
pub struct RuleFields<'a> {
    pub name: &'a str,
    pub pattern: &'a str,
    pub pattern_kind: &'a str,
    pub scope: &'a str,
    pub action: &'a str,
    pub enabled: bool,
}

pub async fn update(
    pool: &PgPool,
    id: &str,
    fields: &RuleFields<'_>,
) -> Result<Option<RuleRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "UPDATE moderation_rule SET name = $2, pattern = $3, pattern_kind = $4, \
             scope = $5, action = $6, enabled = $7, updated_at = now() \
         WHERE id = $1::uuid RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(fields.name)
    .bind(fields.pattern)
    .bind(fields.pattern_kind)
    .bind(fields.scope)
    .bind(fields.action)
    .bind(fields.enabled)
    .fetch_optional(pool)
    .await
}

/// Removes the rule. Its history does not go with it: fired rules already wrote their id
/// and name into `audit_log.detail` and into the report body, which is the copy that
/// matters when someone asks why a post was hidden last month.
pub async fn delete(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query("DELETE FROM moderation_rule WHERE id = $1::uuid")
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected()
            == 1,
    )
}

// ---------------------------------------------------------------------------------------
// Matching and application
// ---------------------------------------------------------------------------------------

/// Tests `text` against the enabled rules for `scope` and applies what matches.
///
/// `scope` is `inbound` for a federated post and `local` for one of our own accounts';
/// a rule stored as `both` runs for either. Returning what fired lets the caller log or
/// test the outcome without a second query.
///
/// A rule fires at most once per post: the audit log is the record of that, so replaying
/// an activity (or an edit of the same note) does not multiply hits or queue entries.
#[allow(clippy::too_many_lines)] // one transaction and one pass: splitting it would spread the trail
pub async fn screen(
    conn: &mut PgConnection,
    scope: &str,
    status_id: &str,
    account_id: &str,
    text: &str,
) -> Result<Vec<Fired>, sqlx::Error> {
    // One transaction for the whole pass: the account action, the queue entry, the hit
    // count and the audit row describe the same event and must not disagree about it.
    let mut tx = conn.begin().await?;
    let rules: Vec<RuleRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM moderation_rule \
         WHERE enabled AND (scope = $1 OR scope = 'both') \
             AND octet_length(pattern) <= $2 \
         ORDER BY created_at ASC, id ASC LIMIT $3"
    ))
    .bind(scope)
    .bind(i64::try_from(PATTERN_MAX_BYTES).unwrap_or(i64::MAX))
    .bind(RULE_CAP)
    .fetch_all(&mut *tx)
    .await?;
    if rules.is_empty() {
        tx.commit().await?;
        return Ok(Vec::new());
    }

    // Rules that already fired on this exact post are skipped, so an edited note that is
    // delivered twice does not count its hits twice or queue itself again.
    let already: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT target_id FROM audit_log \
         WHERE action = 'moderation_rule_fired' AND target_id = ANY($1) \
             AND detail->>'status_id' = $2",
    )
    .bind(rules.iter().map(|rule| rule.id.clone()).collect::<Vec<_>>())
    .bind(status_id)
    .fetch_all(&mut *tx)
    .await?;

    // The account the rule acts on. A staff account cannot be silenced or suspended by a
    // pattern: the same refusal the console makes, for the same reason — a misfiring rule
    // must not be able to lock the operators out of the page they would fix it from.
    let target_is_staff: bool = sqlx::query_scalar("SELECT admin FROM account WHERE id = $1")
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or(false);

    let mut fired = Vec::new();
    let sample = scan_text(text);
    for rule in rules {
        if already.contains(&rule.id) {
            continue;
        }
        let hit = match test(&rule.pattern_kind, &rule.pattern, sample) {
            Ok(Some(hit)) => hit,
            Ok(None) => continue,
            Err(error) => {
                // Creation validates the pattern, so this is a row written by hand. It is
                // recorded and skipped: an ingest must not fail because a rule is broken.
                moderation::audit_in_as(
                    &mut *tx,
                    None,
                    "moderation_rule_error",
                    "moderation_rule",
                    Some(&rule.id),
                    &json!({
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "error": error.to_string(),
                        "status_id": status_id,
                    }),
                )
                .await?;
                continue;
            }
        };

        // Decided before it is applied, so the person's notification can carry the same
        // words the report does: one sentence, written once, read by both.
        let applied = match rule.action.as_str() {
            "silence" | "suspend" if !target_is_staff => rule.action.clone(),
            // Flag, and every action aimed at a staff account, only queues the post.
            _ => "flag".to_owned(),
        };
        let comment = report_comment(&rule, &applied, &hit);
        // The account change and the sentence explaining it travel together: the same
        // reason as the report, and the rule's name so the person can look it up.
        if let Some(action) = match applied.as_str() {
            "silence" => Some(Action::Silence),
            "suspend" => Some(Action::Suspend),
            _ => None,
        } {
            moderation::apply_action_noted_in(
                &mut *tx,
                account_id,
                action,
                &moderation::Notice {
                    reason: &comment,
                    rule: Some(&rule.name),
                    rule_id: Some(&rule.id),
                    actor_id: None,
                    expires_at: None,
                    strike: None,
                },
            )
            .await?;
        }

        let report = moderation::create_report_in(
            &mut *tx,
            &NewReport {
                account_id: None,
                target_account_id: account_id,
                status_ids: &[status_id.to_owned()],
                category: "other",
                comment: &comment,
                rule_ids: &[],
                activity_uri: None,
            },
        )
        .await?;

        sqlx::query("UPDATE moderation_rule SET hits = hits + 1 WHERE id = $1::uuid")
            .bind(&rule.id)
            .execute(&mut *tx)
            .await?;

        moderation::audit_in_as(
            &mut *tx,
            None,
            "moderation_rule_fired",
            "moderation_rule",
            Some(&rule.id),
            &json!({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "pattern_kind": rule.pattern_kind,
                "action": rule.action,
                "applied": applied,
                "downgraded": rule.action != applied,
                "matched": hit.excerpt,
                "span": { "start": hit.start, "end": hit.end },
                "status_id": status_id,
                "account_id": account_id,
                "report_id": report.id,
            }),
        )
        .await?;

        fired.push(Fired {
            rule_id: rule.id,
            rule_name: rule.name,
            action: applied,
            hit,
            report_id: report.id,
        });
    }
    tx.commit().await?;
    Ok(fired)
}

/// The queue entry's body. It names the rule because a moderator reading the queue has to
/// be able to find the policy the instance applied without going to the audit log first.
fn report_comment(rule: &RuleRow, applied: &str, hit: &Hit) -> String {
    let consequence = match applied {
        "silence" => "The account was silenced by the rule; this report records why.",
        "suspend" => "The account was suspended by the rule; this report records why.",
        _ => "The post is in the queue until a moderator decides.",
    };
    format!(
        "The moderation rule \"{}\" ({}: {}) matched \"{}\" at bytes {}..{} of this post. {}",
        rule.name, rule.pattern_kind, rule.pattern, hit.excerpt, hit.start, hit.end, consequence
    )
}

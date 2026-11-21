//! Carrying an instance's moderation configuration to another instance.
//!
//! Rules, warning presets, the escalation ladder, instance rules, pause and block lists and
//! the scanner label rules are all hand-built. An operator standing up a second instance, or
//! restoring one, otherwise rebuilds them from memory — so this module writes them into one
//! versioned document and reads that document back.
//!
//! The projection here is deliberate, the same way the account export is: nothing that is a
//! credential or an asset byte is published. The scanner registry itself is *not* a section:
//! a `scanner` row carries an `endpoint` and a `secret`, and an export is precisely where a
//! shared secret leaks — a file downloaded once outlives the session it was downloaded in.
//! Only the label rules (by scanner name) travel, and content sets travel by name and hash,
//! never as bytes: the digest is what lets an operator notice a set is the wrong one, while
//! the bytes would turn the document into a second copy of every set an instance holds.
//! Account strikes, reports and audit history are facts, not settings, and are absent too.
//!
//! An import never deletes and never lowers a block's severity: removing a protection from a
//! running instance is a decision an administrator makes on purpose, not one a stale document
//! makes by arriving. A row that cannot be applied is counted as skipped or reported as a
//! conflict, so the operator sees it instead of finding out later.

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgConnection;

use nodus_server_core::Id;

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// The document's name and the only version this instance understands.
const FORMAT: &str = "nodus-admin-settings";
const VERSION: u32 = 1;

/// Every section, in the order an import applies them.
///
/// The order is the dependency order: content sets are recognised first, then the rules that
/// name a scanner, then the domain lists, then the single policy rows, then moderation rules
/// last. Export writes them keyed by name; order is not part of the document's meaning.
const SECTIONS: [&str; 9] = [
    "scanner_sets",
    "scanner_rules",
    "email_domain_blocks",
    "domain_blocks",
    "domain_pauses",
    "escalation",
    "warning_presets",
    "instance_rules",
    "rules",
];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/settings/export", get(export))
        .route("/api/v1/admin/settings/import", post(import))
}

#[derive(Debug, Deserialize)]
pub(crate) struct SectionQuery {
    /// A comma-separated subset of [`SECTIONS`]; absent means all of them.
    sections: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ImportQuery {
    #[serde(default)]
    dry_run: bool,
    sections: Option<String>,
}

/// Resolves `?sections=` to the sections the request is about.
///
/// An unknown name is a 422 that lists the known ones: silently ignoring it would let an
/// operator believe they exported a section that was not included.
fn selected(query: Option<&str>) -> ApiResult<Vec<&'static str>> {
    let Some(raw) = query else {
        return Ok(SECTIONS.to_vec());
    };
    let mut chosen = Vec::new();
    for name in raw
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        let section = SECTIONS
            .iter()
            .find(|known| **known == name)
            .copied()
            .ok_or_else(|| {
                ApiError::unprocessable(format!(
                    "unknown section {name:?}; known sections are: {}",
                    SECTIONS.join(", ")
                ))
            })?;
        if !chosen.contains(&section) {
            chosen.push(section);
        }
    }
    Ok(chosen)
}

/// One conflict: a row that was understood but not applied.
#[derive(Debug, Default, serde::Serialize)]
struct Conflict {
    section: &'static str,
    name: String,
    reason: String,
}

/// What one section's import turned out to be.
#[derive(Debug, Default, serde::Serialize)]
struct Outcome {
    created: u64,
    updated: u64,
    unchanged: u64,
    skipped: u64,
    conflicts: Vec<Conflict>,
}

impl Outcome {
    fn skipped(&mut self, section: &'static str, name: &str, reason: &str) {
        self.skipped += 1;
        self.conflicts.push(Conflict {
            section,
            name: name.to_owned(),
            reason: reason.to_owned(),
        });
    }

    fn conflict(&mut self, section: &'static str, name: &str, reason: &str) {
        self.conflicts.push(Conflict {
            section,
            name: name.to_owned(),
            reason: reason.to_owned(),
        });
    }
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn flag(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// `GET /api/v1/admin/settings/export` — the settings another instance can adopt.
pub async fn export(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<SectionQuery>,
) -> ApiResult<Json<Value>> {
    auth.require_admin("admin:read")?;
    let sections = selected(query.sections.as_deref())?;
    let pool = state.store().pool();

    let mut body = serde_json::Map::new();
    for section in sections {
        let value = match section {
            "rules" => export_rules(pool).await?,
            "instance_rules" => export_instance_rules(pool).await?,
            "warning_presets" => export_warning_presets(pool).await?,
            "escalation" => export_escalation(pool).await?,
            "domain_pauses" => export_domain_pauses(pool).await?,
            "domain_blocks" => export_domain_blocks(pool).await?,
            "email_domain_blocks" => export_email_domain_blocks(pool).await?,
            "scanner_rules" => export_scanner_rules(pool).await?,
            "scanner_sets" => export_scanner_sets(pool).await?,
            _ => unreachable!("section validated by `selected`"),
        };
        body.insert(section.to_owned(), value);
    }

    Ok(Json(json!({
        "format": FORMAT,
        "version": VERSION,
        "exported_at": Utc::now(),
        "instance": state.instance().domain,
        "sections": Value::Object(body),
    })))
}

/// `POST /api/v1/admin/settings/import` — what would change, or the change itself.
///
/// The dry run is the same code path as the real import, run inside a transaction that is
/// rolled back. Reporting from a separate "preview" implementation would let preview and
/// apply disagree; rolling back the real one cannot.
pub async fn import(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<ImportQuery>,
    Json(document): Json<Value>,
) -> ApiResult<Json<Value>> {
    auth.require_admin("admin:write")?;
    let sections = selected(query.sections.as_deref())?;

    let format = document.get("format").and_then(Value::as_str).unwrap_or("");
    if format != FORMAT {
        return Err(ApiError::unprocessable(format!(
            "this is not a {FORMAT} document"
        )));
    }
    let version = document.get("version").and_then(Value::as_u64).unwrap_or(0);
    if version != u64::from(VERSION) {
        return Err(ApiError::unprocessable(format!(
            "this instance understands version {VERSION} of {FORMAT}, not version {version}"
        )));
    }
    let Some(by_name) = document.get("sections").and_then(Value::as_object) else {
        return Err(ApiError::unprocessable(
            "a settings document carries a `sections` object",
        ));
    };

    let mut tx = state.store().pool().begin().await?;
    let mut sections_out = serde_json::Map::new();
    let mut failed: Option<sqlx::Error> = None;

    for section in sections {
        // A section named on the query string but absent from the document has nothing to
        // say — it is not an error, because a narrowed export is a valid document.
        let Some(value) = by_name.get(section) else {
            continue;
        };
        let mut outcome = Outcome::default();
        let result = match section {
            "rules" => import_rules(&mut tx, value, &mut outcome).await,
            "instance_rules" => import_instance_rules(&mut tx, value, &mut outcome).await,
            "warning_presets" => import_warning_presets(&mut tx, value, &mut outcome).await,
            "escalation" => import_escalation(&mut tx, value, &mut outcome).await,
            "domain_pauses" => import_domain_pauses(&mut tx, value, &mut outcome).await,
            "domain_blocks" => import_domain_blocks(&mut tx, value, &mut outcome).await,
            "email_domain_blocks" => import_email_domain_blocks(&mut tx, value, &mut outcome).await,
            "scanner_rules" => import_scanner_rules(&mut tx, value, &mut outcome).await,
            "scanner_sets" => import_scanner_sets(&mut tx, value, &mut outcome).await,
            _ => unreachable!("section validated by `selected`"),
        };
        if let Err(error) = result {
            // A half-applied rule set is worse than none: stop, roll everything back, and
            // report the section that failed rather than the counts of the ones that did.
            failed = Some(error);
            break;
        }
        sections_out.insert(
            section.to_owned(),
            serde_json::to_value(outcome).unwrap_or_default(),
        );
    }

    if let Some(error) = failed {
        tx.rollback().await?;
        return Err(ApiError::from(error));
    }
    if query.dry_run {
        tx.rollback().await?;
    } else {
        tx.commit().await?;
    }

    Ok(Json(json!({
        "format": FORMAT,
        "version": VERSION,
        "dry_run": query.dry_run,
        "sections": Value::Object(sections_out),
    })))
}

// ---------------------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------------------

async fn export_rules(pool: &sqlx::PgPool) -> ApiResult<Value> {
    let rows: Vec<(String, String, String, String, String, bool)> = sqlx::query_as(
        "SELECT name, pattern, pattern_kind, scope, action, enabled \
           FROM moderation_rule ORDER BY name ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(Value::Array(
        rows.into_iter()
            .map(|(name, pattern, pattern_kind, scope, action, enabled)| {
                json!({
                    "name": name,
                    "pattern": pattern,
                    "pattern_kind": pattern_kind,
                    "scope": scope,
                    "action": action,
                    "enabled": enabled,
                })
            })
            .collect(),
    ))
}

async fn export_instance_rules(pool: &sqlx::PgPool) -> ApiResult<Value> {
    let rows: Vec<(String, Option<String>, i32)> =
        sqlx::query_as("SELECT text, hint, ordinal FROM instance_rule ORDER BY ordinal ASC")
            .fetch_all(pool)
            .await?;
    Ok(Value::Array(
        rows.into_iter()
            .map(|(text_body, hint, ordinal)| {
                json!({ "text": text_body, "hint": hint, "ordinal": ordinal })
            })
            .collect(),
    ))
}

async fn export_warning_presets(pool: &sqlx::PgPool) -> ApiResult<Value> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT title, text FROM warning_preset ORDER BY title ASC")
            .fetch_all(pool)
            .await?;
    Ok(Value::Array(
        rows.into_iter()
            .map(|(title, text_body)| json!({ "title": title, "text": text_body }))
            .collect(),
    ))
}

async fn export_escalation(pool: &sqlx::PgPool) -> ApiResult<Value> {
    let (name, enabled, window_days, steps): (String, bool, i32, Value) =
        sqlx::query_as("SELECT name, enabled, window_days, steps FROM escalation_policy WHERE id")
            .fetch_one(pool)
            .await?;
    Ok(json!({
        "name": name,
        "enabled": enabled,
        "window_days": window_days,
        "steps": steps,
    }))
}

async fn export_domain_pauses(pool: &sqlx::PgPool) -> ApiResult<Value> {
    let rows: Vec<(String, String, Option<DateTime<Utc>>)> =
        sqlx::query_as("SELECT domain::text, reason, expires_at FROM domain_pause ORDER BY domain")
            .fetch_all(pool)
            .await?;
    Ok(Value::Array(
        rows.into_iter()
            .map(|(domain, reason, expires_at)| {
                json!({ "domain": domain, "reason": reason, "expires_at": expires_at })
            })
            .collect(),
    ))
}

async fn export_domain_blocks(pool: &sqlx::PgPool) -> ApiResult<Value> {
    let rows: Vec<(String, String, bool, bool, bool, String)> = sqlx::query_as(
        "SELECT domain::text, severity, reject_media, reject_reports, obfuscate, public_comment \
           FROM instance_block ORDER BY domain",
    )
    .fetch_all(pool)
    .await?;
    Ok(Value::Array(
        rows.into_iter()
            .map(
                |(domain, severity, reject_media, reject_reports, obfuscate, comment)| {
                    json!({
                        "domain": domain,
                        "severity": severity,
                        "reject_media": reject_media,
                        "reject_reports": reject_reports,
                        "obfuscate": obfuscate,
                        "comment": comment,
                    })
                },
            )
            .collect(),
    ))
}

async fn export_email_domain_blocks(pool: &sqlx::PgPool) -> ApiResult<Value> {
    let rows: Vec<(String, bool)> = sqlx::query_as(
        "SELECT domain::text, allow_registration FROM email_domain_block ORDER BY domain",
    )
    .fetch_all(pool)
    .await?;
    Ok(Value::Array(
        rows.into_iter()
            .map(|(domain, allow_registration)| {
                json!({ "domain": domain, "allow_registration": allow_registration })
            })
            .collect(),
    ))
}

async fn export_scanner_rules(pool: &sqlx::PgPool) -> ApiResult<Value> {
    let rows: Vec<(String, String, f64, String)> = sqlx::query_as(
        "SELECT scanner.name, scanner_rule.label, scanner_rule.threshold, scanner_rule.severity \
           FROM scanner_rule JOIN scanner ON scanner.id = scanner_rule.scanner_id \
          ORDER BY scanner.name, scanner_rule.label",
    )
    .fetch_all(pool)
    .await?;
    Ok(Value::Array(
        rows.into_iter()
            .map(|(scanner, label, threshold, severity)| {
                json!({
                    "scanner": scanner,
                    "label": label,
                    "threshold": threshold,
                    "severity": severity,
                })
            })
            .collect(),
    ))
}

async fn export_scanner_sets(pool: &sqlx::PgPool) -> ApiResult<Value> {
    // Name, kind and digest: the hash is what an operator compares, and the bytes are a
    // backup problem, not a settings one.
    let rows: Vec<(String, String, String, i64, String)> = sqlx::query_as(
        "SELECT name, kind, digest, size, content_type FROM scanner_asset ORDER BY name ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(Value::Array(
        rows.into_iter()
            .map(|(name, kind, digest, size, content_type)| {
                json!({
                    "name": name,
                    "kind": kind,
                    "digest": digest,
                    "size": size,
                    "content_type": content_type,
                })
            })
            .collect(),
    ))
}

// ---------------------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------------------

fn rows(value: &Value) -> &[Value] {
    value.as_array().map(Vec::as_slice).unwrap_or(&[])
}

async fn import_rules(
    conn: &mut PgConnection,
    value: &Value,
    outcome: &mut Outcome,
) -> Result<(), sqlx::Error> {
    let existing: Vec<(String, String, String, String, String, String, bool)> = sqlx::query_as(
        "SELECT id::text, name, pattern, pattern_kind, scope, action, enabled FROM moderation_rule",
    )
    .fetch_all(&mut *conn)
    .await?;

    for row in rows(value) {
        let name = text(row, "name");
        let pattern = text(row, "pattern");
        let kind = text(row, "pattern_kind");
        let scope = text(row, "scope");
        let action = text(row, "action");
        let enabled = flag(row, "enabled");
        if let Some((id, _, have_pattern, have_kind, have_scope, have_action, have_enabled)) =
            existing.iter().find(|(_, have, ..)| *have == name)
        {
            if *have_pattern == pattern
                && *have_kind == kind
                && *have_scope == scope
                && *have_action == action
                && *have_enabled == enabled
            {
                outcome.unchanged += 1;
            } else {
                sqlx::query(
                    "UPDATE moderation_rule SET pattern = $2, pattern_kind = $3, scope = $4, \
                     action = $5, enabled = $6, updated_at = now() WHERE id = $1::uuid",
                )
                .bind(id)
                .bind(&pattern)
                .bind(&kind)
                .bind(&scope)
                .bind(&action)
                .bind(enabled)
                .execute(&mut *conn)
                .await?;
                outcome.updated += 1;
            }
        } else {
            sqlx::query(
                "INSERT INTO moderation_rule (name, pattern, pattern_kind, scope, action, enabled) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&name)
            .bind(&pattern)
            .bind(&kind)
            .bind(&scope)
            .bind(&action)
            .bind(enabled)
            .execute(&mut *conn)
            .await?;
            outcome.created += 1;
        }
    }
    Ok(())
}

async fn import_instance_rules(
    conn: &mut PgConnection,
    value: &Value,
    outcome: &mut Outcome,
) -> Result<(), sqlx::Error> {
    let existing: Vec<(String, String, Option<String>)> =
        sqlx::query_as("SELECT id, text, hint FROM instance_rule")
            .fetch_all(&mut *conn)
            .await?;

    for row in rows(value) {
        let body = text(row, "text");
        let hint = row.get("hint").and_then(Value::as_str).map(str::to_owned);
        if let Some((id, _, have_hint)) = existing.iter().find(|(_, have, ..)| *have == body) {
            if *have_hint == hint {
                outcome.unchanged += 1;
            } else {
                sqlx::query("UPDATE instance_rule SET hint = $2, updated_at = now() WHERE id = $1")
                    .bind(id)
                    .bind(&hint)
                    .execute(&mut *conn)
                    .await?;
                outcome.updated += 1;
            }
        } else {
            // Appended: a position in the source document is not a position in this
            // instance's document, and the numbering is the instance's own promise.
            let next: i32 =
                sqlx::query_scalar("SELECT coalesce(max(ordinal) + 1, 0) FROM instance_rule")
                    .fetch_one(&mut *conn)
                    .await?;
            sqlx::query(
                "INSERT INTO instance_rule (id, ordinal, text, hint) VALUES ($1, $2, $3, $4)",
            )
            .bind(Id::new().to_string())
            .bind(next)
            .bind(&body)
            .bind(&hint)
            .execute(&mut *conn)
            .await?;
            outcome.created += 1;
        }
    }
    Ok(())
}

async fn import_warning_presets(
    conn: &mut PgConnection,
    value: &Value,
    outcome: &mut Outcome,
) -> Result<(), sqlx::Error> {
    let existing: Vec<(String, String, String)> =
        sqlx::query_as("SELECT id, title, text FROM warning_preset")
            .fetch_all(&mut *conn)
            .await?;

    for row in rows(value) {
        let title = text(row, "title");
        let body = text(row, "text");
        if let Some((id, _, have_text)) = existing.iter().find(|(_, have, _)| *have == title) {
            if *have_text == body {
                outcome.unchanged += 1;
            } else {
                sqlx::query("UPDATE warning_preset SET text = $2 WHERE id = $1")
                    .bind(id)
                    .bind(&body)
                    .execute(&mut *conn)
                    .await?;
                outcome.updated += 1;
            }
        } else {
            sqlx::query("INSERT INTO warning_preset (id, title, text) VALUES ($1, $2, $3)")
                .bind(Id::new().to_string())
                .bind(&title)
                .bind(&body)
                .execute(&mut *conn)
                .await?;
            outcome.created += 1;
        }
    }
    Ok(())
}

async fn import_escalation(
    conn: &mut PgConnection,
    value: &Value,
    outcome: &mut Outcome,
) -> Result<(), sqlx::Error> {
    let have: (String, bool, i32, Value) =
        sqlx::query_as("SELECT name, enabled, window_days, steps FROM escalation_policy WHERE id")
            .fetch_one(&mut *conn)
            .await?;
    let name = text(value, "name");
    let enabled = flag(value, "enabled");
    let window_days = value
        .get("window_days")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let steps = value
        .get("steps")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));

    if have.0 == name && have.1 == enabled && i64::from(have.2) == window_days && have.3 == steps {
        outcome.unchanged += 1;
        return Ok(());
    }

    let parsed: Vec<nodus_server_store::escalation::Step> = serde_json::from_value(steps.clone())
        .map_err(|error| {
        sqlx::Error::Protocol(format!("the escalation steps do not parse: {error}"))
    })?;
    let input = nodus_server_store::escalation::PolicyInput {
        enabled,
        window_days,
        steps: &parsed,
    };
    if let Err(message) = nodus_server_store::escalation::validate(&input) {
        outcome.conflict("escalation", &name, &message);
        return Ok(());
    }

    sqlx::query(
        "UPDATE escalation_policy SET name = $1, enabled = $2, window_days = $3, steps = $4, \
         updated_at = now(), updated_by = NULL WHERE id",
    )
    .bind(&name)
    .bind(enabled)
    .bind(i32::try_from(window_days).unwrap_or(i32::MAX))
    .bind(&steps)
    .execute(&mut *conn)
    .await?;
    outcome.updated += 1;
    Ok(())
}

async fn import_domain_pauses(
    conn: &mut PgConnection,
    value: &Value,
    outcome: &mut Outcome,
) -> Result<(), sqlx::Error> {
    let existing: Vec<(String, String, Option<DateTime<Utc>>)> =
        sqlx::query_as("SELECT domain::text, reason, expires_at FROM domain_pause")
            .fetch_all(&mut *conn)
            .await?;

    for row in rows(value) {
        let domain = text(row, "domain");
        let reason = text(row, "reason");
        let expires_at: Option<DateTime<Utc>> = row
            .get("expires_at")
            .and_then(|value| serde_json::from_value(value.clone()).ok());
        if let Some((_, have_reason, have_expiry)) =
            existing.iter().find(|(have, ..)| *have == domain)
        {
            if *have_reason == reason && *have_expiry == expires_at {
                outcome.unchanged += 1;
            } else {
                sqlx::query(
                    "UPDATE domain_pause SET reason = $2, expires_at = $3 WHERE domain = $1",
                )
                .bind(&domain)
                .bind(&reason)
                .bind(expires_at)
                .execute(&mut *conn)
                .await?;
                outcome.updated += 1;
            }
        } else {
            sqlx::query(
                "INSERT INTO domain_pause (domain, reason, expires_at) VALUES ($1, $2, $3)",
            )
            .bind(&domain)
            .bind(&reason)
            .bind(expires_at)
            .execute(&mut *conn)
            .await?;
            outcome.created += 1;
        }
    }
    Ok(())
}

/// How much of a domain's reach a block takes away. Used only to refuse a downgrade.
fn severity_weight(severity: &str) -> i32 {
    match severity {
        "suspend" => 2,
        "silence" => 1,
        _ => 0,
    }
}

async fn import_domain_blocks(
    conn: &mut PgConnection,
    value: &Value,
    outcome: &mut Outcome,
) -> Result<(), sqlx::Error> {
    let existing: Vec<(String, String, String, bool, bool, bool, String)> = sqlx::query_as(
        "SELECT id, domain::text, severity, reject_media, reject_reports, obfuscate, public_comment \
           FROM instance_block",
    )
    .fetch_all(&mut *conn)
    .await?;

    for row in rows(value) {
        let domain = text(row, "domain");
        let severity = text(row, "severity");
        let reject_media = flag(row, "reject_media");
        let reject_reports = flag(row, "reject_reports");
        let obfuscate = flag(row, "obfuscate");
        let comment = text(row, "comment");
        if let Some((
            id,
            _,
            have_severity,
            have_media,
            have_reports,
            have_obfuscate,
            have_comment,
        )) = existing.iter().find(|(_, have, ..)| *have == domain)
        {
            // Severity is a protection, and protecting less is a decision. A document
            // that would turn a suspend into a silence is reported, never applied: the
            // operator can still do it by hand, deliberately.
            if severity_weight(&severity) < severity_weight(have_severity) {
                outcome.conflict(
                    "domain_blocks",
                    &domain,
                    &format!(
                        "refusing to lower severity from {have_severity} to {severity}; \
                         change it by hand if that is intended"
                    ),
                );
                continue;
            }
            if *have_severity == severity
                && *have_media == reject_media
                && *have_reports == reject_reports
                && *have_obfuscate == obfuscate
                && *have_comment == comment
            {
                outcome.unchanged += 1;
            } else {
                sqlx::query(
                    "UPDATE instance_block SET severity = $2, reject_media = $3, \
                     reject_reports = $4, obfuscate = $5, public_comment = $6 WHERE id = $1",
                )
                .bind(id)
                .bind(&severity)
                .bind(reject_media)
                .bind(reject_reports)
                .bind(obfuscate)
                .bind(&comment)
                .execute(&mut *conn)
                .await?;
                outcome.updated += 1;
            }
        } else {
            sqlx::query(
                "INSERT INTO instance_block (id, domain, severity, reject_media, \
                 reject_reports, obfuscate, public_comment) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(Id::new().to_string())
            .bind(&domain)
            .bind(&severity)
            .bind(reject_media)
            .bind(reject_reports)
            .bind(obfuscate)
            .bind(&comment)
            .execute(&mut *conn)
            .await?;
            outcome.created += 1;
        }
    }
    Ok(())
}

async fn import_email_domain_blocks(
    conn: &mut PgConnection,
    value: &Value,
    outcome: &mut Outcome,
) -> Result<(), sqlx::Error> {
    let existing: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT id, domain::text, allow_registration FROM email_domain_block")
            .fetch_all(&mut *conn)
            .await?;

    for row in rows(value) {
        let domain = text(row, "domain");
        let allow_registration = flag(row, "allow_registration");
        if let Some((id, _, have_allow)) = existing.iter().find(|(_, have, _)| *have == domain) {
            if *have_allow == allow_registration {
                outcome.unchanged += 1;
            } else {
                sqlx::query("UPDATE email_domain_block SET allow_registration = $2 WHERE id = $1")
                    .bind(id)
                    .bind(allow_registration)
                    .execute(&mut *conn)
                    .await?;
                outcome.updated += 1;
            }
        } else {
            sqlx::query(
                "INSERT INTO email_domain_block (id, domain, allow_registration) \
                 VALUES ($1, $2, $3)",
            )
            .bind(Id::new().to_string())
            .bind(&domain)
            .bind(allow_registration)
            .execute(&mut *conn)
            .await?;
            outcome.created += 1;
        }
    }
    Ok(())
}

async fn import_scanner_rules(
    conn: &mut PgConnection,
    value: &Value,
    outcome: &mut Outcome,
) -> Result<(), sqlx::Error> {
    let scanners: Vec<(String, String)> = sqlx::query_as("SELECT id, name FROM scanner")
        .fetch_all(&mut *conn)
        .await?;
    let existing: Vec<(String, String, String, f64, String)> =
        sqlx::query_as("SELECT id, scanner_id, label, threshold, severity FROM scanner_rule")
            .fetch_all(&mut *conn)
            .await?;

    for row in rows(value) {
        let scanner = text(row, "scanner");
        let label = text(row, "label");
        let threshold = row.get("threshold").and_then(Value::as_f64).unwrap_or(0.0);
        let severity = text(row, "severity");
        let Some((scanner_id, _)) = scanners.iter().find(|(_, name)| *name == scanner) else {
            // The scanner registry is not carried (it holds endpoints and secrets), so a
            // rule for a scanner this instance does not have cannot be attached to
            // anything. Skipped, and said so.
            outcome.skipped(
                "scanner_rules",
                &format!("{scanner}/{label}"),
                "no scanner with that name on this instance; the registry is not exported",
            );
            continue;
        };
        if let Some((id, _, _, have_threshold, have_severity)) =
            existing.iter().find(|(_, have_scanner, have_label, ..)| {
                have_scanner == scanner_id && *have_label == label
            })
        {
            if (*have_threshold - threshold).abs() < f64::EPSILON && *have_severity == severity {
                outcome.unchanged += 1;
            } else {
                sqlx::query("UPDATE scanner_rule SET threshold = $2, severity = $3 WHERE id = $1")
                    .bind(id)
                    .bind(threshold)
                    .bind(&severity)
                    .execute(&mut *conn)
                    .await?;
                outcome.updated += 1;
            }
        } else {
            sqlx::query(
                "INSERT INTO scanner_rule (id, scanner_id, label, threshold, severity) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(Id::new().to_string())
            .bind(scanner_id)
            .bind(&label)
            .bind(threshold)
            .bind(&severity)
            .execute(&mut *conn)
            .await?;
            outcome.created += 1;
        }
    }
    Ok(())
}

async fn import_scanner_sets(
    conn: &mut PgConnection,
    value: &Value,
    outcome: &mut Outcome,
) -> Result<(), sqlx::Error> {
    let existing: Vec<(String, String, String)> =
        sqlx::query_as("SELECT name, digest, kind FROM scanner_asset")
            .fetch_all(&mut *conn)
            .await?;

    for row in rows(value) {
        let name = text(row, "name");
        let digest = text(row, "digest");
        match existing.iter().find(|(have, ..)| *have == name) {
            Some((_, have_digest, _)) if *have_digest == digest => outcome.unchanged += 1,
            Some((_, have_digest, _)) => outcome.conflict(
                "scanner_sets",
                &name,
                &format!(
                    "a different set is registered under this name (digest {have_digest}, \
                     document says {digest}); the bytes are never carried"
                ),
            ),
            None => outcome.skipped(
                "scanner_sets",
                &name,
                "the document carries the hash, not the bytes; upload the set on this instance",
            ),
        }
    }
    Ok(())
}

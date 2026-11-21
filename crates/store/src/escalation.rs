//! Strikes, and the escalation policy that gives them meaning.
//!
//! A strike is a fact: this account was silenced, suspended or warned, by this rule, at this
//! moment, and it counts until the window closes. The policy is a judgement: how many live
//! strikes mean what. Keeping them apart is what lets an administrator disable escalation
//! without deleting the history that justified it.
//!
//! Everything here is written on the caller's connection. A strike and the decision that
//! produced it commit together, or neither does.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{FromRow, PgConnection, PgPool};

use nodus_server_core::Id;

use crate::moderation;

/// The most steps a policy may hold. A longer one is not a policy, it is a database.
pub const MAX_STEPS: usize = 10;

/// The longest window, and the longest duration, in days: ten years.
pub const MAX_DAYS: i64 = 3650;

/// One rung of the policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// The live strike count at which this step applies.
    pub strikes: i64,
    /// `warn`, `flag`, `silence` or `suspend`.
    pub action: String,
    /// How long the restriction lasts, when the action has a length.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_days: Option<i64>,
}

impl Step {
    /// How much of the account this step takes away, used to refuse a step that would lift a
    /// restriction already in force. A warning and a flag change nothing, so both are zero.
    fn weight(&self) -> i32 {
        match self.action.as_str() {
            "silence" => 1,
            "suspend" => 2,
            _ => 0,
        }
    }
}

/// The policy row as stored.
#[derive(Debug, Clone, FromRow)]
pub struct Policy {
    pub name: String,
    pub enabled: bool,
    pub window_days: i32,
    pub steps: Value,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<String>,
}

impl Policy {
    /// The steps, parsed. A row whose steps cannot be understood yields none, which stops
    /// escalation rather than applying a policy nobody can read.
    #[must_use]
    pub fn steps(&self) -> Vec<Step> {
        serde_json::from_value(self.steps.clone()).unwrap_or_default()
    }
}

/// The storable shape of a policy write, validated before it reaches the row.
#[derive(Debug, Clone, Copy)]
pub struct PolicyInput<'a> {
    pub enabled: bool,
    pub window_days: i64,
    pub steps: &'a [Step],
}

/// Reads the one policy row.
pub async fn policy(pool: &PgPool) -> Result<Policy, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    policy_in(&mut conn).await
}

/// The same read on a caller's connection, so enforcement sees the policy it commits under.
pub async fn policy_in(conn: &mut PgConnection) -> Result<Policy, sqlx::Error> {
    sqlx::query_as::<_, Policy>(
        "SELECT name, enabled, window_days, steps, updated_at, updated_by \
         FROM escalation_policy WHERE id",
    )
    .fetch_one(&mut *conn)
    .await
}

/// Refuses a policy a moderator could not reason about, naming the step at fault.
///
/// The step is named by its position, not its strike count: a duplicate count makes "step 3"
/// the only unambiguous way to point at the row that is wrong.
pub fn validate(input: &PolicyInput<'_>) -> Result<(), String> {
    if !(1..=MAX_DAYS).contains(&input.window_days) {
        return Err(format!("window_days must be between 1 and {MAX_DAYS}"));
    }
    if input.steps.is_empty() || input.steps.len() > MAX_STEPS {
        return Err(format!(
            "steps must hold between 1 and {MAX_STEPS} entries, got {}",
            input.steps.len()
        ));
    }
    let mut previous = 0i64;
    for (index, step) in input.steps.iter().enumerate() {
        let at = index + 1;
        if step.strikes < 1 {
            return Err(format!("step {at}: strikes must be at least 1"));
        }
        if step.strikes <= previous {
            return Err(format!(
                "step {at}: strike counts must ascend, {} does not follow {previous}",
                step.strikes
            ));
        }
        if !matches!(
            step.action.as_str(),
            "warn" | "flag" | "silence" | "suspend"
        ) {
            return Err(format!(
                "step {at}: unknown action {:?}, expected warn, flag, silence or suspend",
                step.action
            ));
        }
        if let Some(days) = step.duration_days {
            if !(1..=MAX_DAYS).contains(&days) {
                return Err(format!(
                    "step {at}: duration_days must be between 1 and {MAX_DAYS}"
                ));
            }
            if step.action != "silence" && step.action != "suspend" {
                return Err(format!(
                    "step {at}: duration_days only applies to silence and suspend"
                ));
            }
        }
        previous = step.strikes;
    }
    Ok(())
}

/// Writes the policy the administrator edited, after validating it.
pub async fn save_policy(
    pool: &PgPool,
    input: &PolicyInput<'_>,
    actor_id: &str,
) -> Result<Result<Policy, String>, sqlx::Error> {
    if let Err(message) = validate(input) {
        return Ok(Err(message));
    }
    let steps = serde_json::to_value(input.steps).unwrap_or_else(|_| Value::Array(Vec::new()));
    let row = sqlx::query_as::<_, Policy>(
        "UPDATE escalation_policy \
            SET enabled = $1, window_days = $2, steps = $3, updated_at = now(), updated_by = $4 \
          WHERE id \
         RETURNING name, enabled, window_days, steps, updated_at, updated_by",
    )
    .bind(input.enabled)
    .bind(i32::try_from(input.window_days).unwrap_or(i32::MAX))
    .bind(steps)
    .bind(actor_id)
    .fetch_one(pool)
    .await?;
    Ok(Ok(row))
}

/// One strike, as the console lists it.
#[derive(Debug, Clone, FromRow)]
pub struct StrikeRow {
    pub id: String,
    pub account_id: String,
    pub rule_id: Option<String>,
    /// The rule's name at read time. A deleted rule leaves the citation stale, not the strike.
    pub rule_name: Option<String>,
    pub action: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// An account's strikes, newest first, live and expired alike.
pub async fn strikes(pool: &PgPool, account_id: &str) -> Result<Vec<StrikeRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT s.id, s.account_id, s.rule_id::text AS rule_id, r.name AS rule_name, \
             s.action, s.reason, s.created_at, s.expires_at \
         FROM moderation_strike s \
         LEFT JOIN moderation_rule r ON r.id = s.rule_id \
         WHERE s.account_id = $1 \
         ORDER BY s.created_at DESC, s.id DESC",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
}

/// How many of an account's strikes are still live.
pub async fn live_count_in(conn: &mut PgConnection, account_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM moderation_strike \
         WHERE account_id = $1 AND expires_at > now()",
    )
    .bind(account_id)
    .fetch_one(&mut *conn)
    .await
}

/// Writes the strike a decision leaves behind, stamped with the window it was written under.
pub async fn record_strike_in(
    conn: &mut PgConnection,
    account_id: &str,
    rule_id: Option<&str>,
    action: &str,
    reason: &str,
    window_days: i32,
) -> Result<(), sqlx::Error> {
    let expires_at = Utc::now() + Duration::days(i64::from(window_days.max(1)));
    sqlx::query(
        "INSERT INTO moderation_strike (id, account_id, rule_id, action, reason, expires_at) \
         VALUES ($1, $2, $3::uuid, $4, $5, $6)",
    )
    .bind(Id::new().to_string())
    .bind(account_id)
    .bind(rule_id)
    .bind(action)
    .bind(reason)
    .bind(expires_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// What an escalation did, for the caller that wants to report it.
#[derive(Debug, Clone)]
pub struct Applied {
    pub strikes: i64,
    pub action: String,
    /// False when the step was reached but skipped as a weakening.
    pub applied: bool,
}

/// Applies the highest step the account has reached, and records what it did.
///
/// Called at the one place every restriction goes through, so a rule, a bulk action and a
/// single click all escalate the same way. The account change here deliberately bypasses
/// [`crate::moderation::apply_action_noted_in`]: the escalated action is a consequence of a
/// strike, not another offence, and counting it again would let one silence suspend somebody.
pub async fn escalate_in(
    conn: &mut PgConnection,
    account_id: &str,
    actor_id: Option<&str>,
    policy: &Policy,
) -> Result<Option<Applied>, sqlx::Error> {
    if !policy.enabled {
        return Ok(None);
    }
    let steps = policy.steps();
    let count = live_count_in(conn, account_id).await?;
    let Some(step) = steps
        .iter()
        .filter(|step| step.strikes <= count)
        .max_by_key(|step| step.strikes)
    else {
        return Ok(None);
    };

    // What the account may not do right now, so a step that reaches for less cannot lift it.
    let (silenced, suspended): (bool, bool) = sqlx::query_as(
        "SELECT silenced_at IS NOT NULL, suspended_at IS NOT NULL FROM account WHERE id = $1",
    )
    .bind(account_id)
    .fetch_optional(&mut *conn)
    .await?
    .unwrap_or((false, false));
    let current = if suspended {
        2
    } else {
        i32::from(silenced)
    };
    let strengthens = step.weight() > current;

    let outcome = if strengthens {
        apply_step(conn, account_id, actor_id, policy, step, count).await?
    } else {
        false
    };

    moderation::audit_in_as(
        conn,
        actor_id,
        "moderation_escalated",
        "account",
        Some(account_id),
        &json!({
            "policy": policy.name,
            "strikes": count,
            "window_days": policy.window_days,
            "step": step,
            "applied": outcome,
            // Why nothing happened, when nothing happened: the console should not have to
            // infer "the suspension was already in force".
            "skipped": if outcome { None } else { Some("would_not_strengthen") },
            "current": { "silenced": silenced, "suspended": suspended },
        }),
    )
    .await?;

    Ok(Some(Applied {
        strikes: count,
        action: step.action.clone(),
        applied: outcome,
    }))
}

/// Applies one step. Returns whether anything about the account changed.
async fn apply_step(
    conn: &mut PgConnection,
    account_id: &str,
    actor_id: Option<&str>,
    policy: &Policy,
    step: &Step,
    count: i64,
) -> Result<bool, sqlx::Error> {
    let expires_at = step
        .duration_days
        .map(|days| Utc::now() + Duration::days(days));
    // The sentence the person reads. Built here and handed to the same notice machinery a
    // moderator's own click uses, so there is one notification shape and one place to read.
    let reason = match step.duration_days {
        Some(days) => format!(
            "Strike {count} of your last {} days reached step {} of this instance's escalation policy: {} for {days} day(s).",
            policy.window_days, step.strikes, step.action
        ),
        None => format!(
            "Strike {count} of your last {} days reached step {} of this instance's escalation policy: {}.",
            policy.window_days, step.strikes, step.action
        ),
    };
    let notice = moderation::Notice {
        reason: &reason,
        rule: None,
        rule_id: None,
        actor_id,
        expires_at,
        strike: Some(count),
    };
    let action = match step.action.as_str() {
        "silence" => Some(moderation::Action::Silence),
        "suspend" => Some(moderation::Action::Suspend),
        // A warning escalates by telling the person; a flag escalates by putting the account
        // in front of a moderator, which the audit row already does.
        _ => None,
    };
    match action {
        Some(action) => {
            moderation::apply_core_in(conn, account_id, action, &notice).await?;
            Ok(true)
        }
        None if step.action == "warn" => {
            moderation::notice_for(conn, account_id, moderation::WARN, &notice).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// The next thing the policy would do to this account, and at how many strikes.
#[must_use]
pub fn next_step(policy: &Policy, live: i64) -> Option<Value> {
    if !policy.enabled {
        return None;
    }
    policy
        .steps()
        .into_iter()
        .filter(|step| step.strikes > live)
        .min_by_key(|step| step.strikes)
        .map(|step| {
            json!({
                "strikes": step.strikes,
                "action": step.action,
                "duration_days": step.duration_days,
            })
        })
}

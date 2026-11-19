//! The instance's rules: the code of conduct a report is actually about.
//!
//! A rule's `ordinal` is its position in the list, zero-based and contiguous. That is the
//! number a person cites ("rule 3"), so it has to mean the same thing before and after an
//! edit, and two rules may never share it — the table enforces that with a unique
//! constraint and this module keeps the sequence compact whenever it writes.
//!
//! Ids are opaque and stay stable across an edit; a report keeps the ids it cited even
//! after the rule is deleted, which is why [`by_ids`] returns only the rows that still
//! exist and the caller decides what to say about the rest.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgConnection, PgPool};

use nodus_server_core::Id;

/// One instance rule as stored.
#[derive(Debug, Clone, FromRow)]
pub struct RuleRow {
    pub id: String,
    /// Zero-based position; unique and contiguous across the list.
    pub ordinal: i32,
    pub text: String,
    /// Mastodon's optional longer explanation. Rules written before the admin surface
    /// existed may carry one; new ones are written without it.
    pub hint: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const COLUMNS: &str = "id, ordinal, text, hint, created_at, updated_at";

/// Every rule, in the order a client renders them.
pub async fn rules(pool: &PgPool) -> Result<Vec<RuleRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM instance_rule ORDER BY ordinal ASC"
    ))
    .fetch_all(pool)
    .await
}

/// One rule, or `None` if it was deleted.
pub async fn rule(pool: &PgPool, id: &str) -> Result<Option<RuleRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM instance_rule WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// The rules among `ids` that still exist.
///
/// Returned unordered on purpose: a report's cited ids are written in the order the
/// reporter picked them, and the caller already has that order.
pub async fn by_ids(pool: &PgPool, ids: &[String]) -> Result<Vec<RuleRow>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM instance_rule WHERE id = ANY($1)"
    ))
    .bind(ids)
    .fetch_all(pool)
    .await
}

/// Which of `ids` exist, so a report can name the first one that does not.
pub async fn existing_ids(pool: &PgPool, ids: &[String]) -> Result<Vec<String>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_scalar("SELECT id FROM instance_rule WHERE id = ANY($1)")
        .bind(ids)
        .fetch_all(pool)
        .await
}

/// Appends a rule, or inserts it at `ordinal` and shifts the rest down.
///
/// `ordinal` is clamped to the list: a caller that guessed one position too far appends,
/// which is what a person pressing "add after the last rule" means.
pub async fn create(
    pool: &PgPool,
    text: &str,
    ordinal: Option<i32>,
) -> Result<RuleRow, sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_list(&mut tx).await?;
    let order = ordered_ids(&mut tx).await?;
    let count = order.len();
    let at = ordinal.map_or(count, |value| {
        usize::try_from(value).unwrap_or(0).min(count)
    });

    let id = Id::new().to_string();
    // Insert past the end first: that position is certainly free, and the renumber below
    // puts it where the caller asked. Writing the final position directly could collide
    // with the row that is about to move.
    let free = current_max(&mut tx).await?.saturating_add(1);
    sqlx::query("INSERT INTO instance_rule (id, ordinal, text) VALUES ($1, $2, $3)")
        .bind(&id)
        .bind(free)
        .bind(text)
        .execute(&mut *tx)
        .await?;

    let mut positions = order;
    positions.insert(at, id.clone());
    // The offset has to clear every value the table now holds, and the row just inserted
    // is at `free`, so one past it is the first offset that cannot collide with a row
    // that has not been renumbered yet.
    write_positions(&mut tx, free.saturating_add(1), &positions).await?;

    let row = fetch_one(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(row)
}

/// Rewrites a rule's text and/or moves it to `ordinal`, shifting the others.
///
/// `None` for either field means "leave it alone", so a reorder does not have to resend
/// text that is not changing. Returns `None` when the rule does not exist.
pub async fn update(
    pool: &PgPool,
    id: &str,
    text: Option<&str>,
    ordinal: Option<i32>,
) -> Result<Option<RuleRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_list(&mut tx).await?;
    let mut positions = ordered_ids(&mut tx).await?;
    if !positions.iter().any(|row_id| row_id == id) {
        return Ok(None);
    }

    if let Some(text) = text {
        sqlx::query("UPDATE instance_rule SET text = $1, updated_at = now() WHERE id = $2")
            .bind(text)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }

    if let Some(target) = ordinal {
        let last = positions.len().saturating_sub(1);
        let to = usize::try_from(target).unwrap_or(0).min(last);
        let from = positions
            .iter()
            .position(|row_id| row_id == id)
            .unwrap_or_default();
        if from != to {
            let moved = positions.remove(from);
            positions.insert(to, moved);
            // The list is about to be renumbered, so the offset only has to be larger
            // than every position it currently holds.
            let free = current_max(&mut tx).await?.saturating_add(1);
            write_positions(&mut tx, free, &positions).await?;
        }
    }

    let row = fetch_one(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Some(row))
}

/// Deletes a rule and closes the gap, so positions stay contiguous.
///
/// Reports that cited it keep the id: the caller's payload marks it as no longer there.
pub async fn delete(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_list(&mut tx).await?;
    let positions = ordered_ids(&mut tx).await?;
    if !positions.iter().any(|row_id| row_id == id) {
        return Ok(false);
    }
    sqlx::query("DELETE FROM instance_rule WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let remaining: Vec<String> = positions
        .into_iter()
        .filter(|row_id| row_id != id)
        .collect();
    let free = current_max(&mut tx).await?.saturating_add(1);
    write_positions(&mut tx, free, &remaining).await?;
    tx.commit().await?;
    Ok(true)
}

// ---------------------------------------------------------------------------------------
// The ordering machinery
// ---------------------------------------------------------------------------------------

/// Serializes writers for the length of one transaction.
///
/// The list is a handful of rows; taking the table means two administrators reordering at
/// the same moment produce two complete orders rather than one interleaved one. Readers
/// are not blocked (`EXCLUSIVE`, not `ACCESS EXCLUSIVE`).
async fn lock_list(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("LOCK TABLE instance_rule IN EXCLUSIVE MODE")
        .execute(conn)
        .await?;
    Ok(())
}

async fn ordered_ids(conn: &mut PgConnection) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM instance_rule ORDER BY ordinal ASC")
        .fetch_all(conn)
        .await
}

async fn current_max(conn: &mut PgConnection) -> Result<i32, sqlx::Error> {
    sqlx::query_scalar("SELECT COALESCE(MAX(ordinal), -1)::int FROM instance_rule")
        .fetch_one(conn)
        .await
}

/// Writes `positions` as `0..n`, in that order, in one transaction.
///
/// The unique constraint is checked row by row, so moving a rule onto the position of a
/// rule that has not moved yet would collide. Every row is shifted by `offset` first:
/// `offset` is chosen above every value the table currently holds, so no shifted value
/// can equal a value that has not been shifted, and the constraint holds at every
/// statement. The final `0..n` sequence is then free.
async fn write_positions(
    conn: &mut PgConnection,
    offset: i32,
    positions: &[String],
) -> Result<(), sqlx::Error> {
    if positions.is_empty() {
        return Ok(());
    }
    sqlx::query("UPDATE instance_rule SET ordinal = ordinal + $1")
        .bind(offset)
        .execute(&mut *conn)
        .await?;
    for (index, id) in positions.iter().enumerate() {
        sqlx::query("UPDATE instance_rule SET ordinal = $1, updated_at = now() WHERE id = $2")
            .bind(i32::try_from(index).unwrap_or(i32::MAX))
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

async fn fetch_one(conn: &mut PgConnection, id: &str) -> Result<RuleRow, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM instance_rule WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(conn)
    .await
}

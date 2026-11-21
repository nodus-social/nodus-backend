//! The viewer's relationship to every author on a page, in one pass.

use crate::social::Relationship;

use super::RowMap;

/// `(target id, follow state, reblogs, notify, blocked, muting, notify-on-mute, followed by, blocked by)`.
type RelationshipKeyRow = (
    String,
    Option<String>,
    Option<bool>,
    Option<bool>,
    bool,
    bool,
    bool,
    bool,
    bool,
);

pub(super) async fn fetch_relationships<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    viewer: &str,
    ids: &[String],
) -> Result<RowMap<Relationship>, sqlx::Error> {
    // One pass over the requested ids. The scalar `social::relationship` asks the same questions with four correlated `EXISTS` subqueries per call, which a page of twenty ids pays twenty times.
    let rows = sqlx::query_as::<_, RelationshipKeyRow>(
        "SELECT t.target_id, f.state, f.reblogs, f.notify, \
                b.account_id IS NOT NULL, m.account_id IS NOT NULL, COALESCE(m.notifications, false), \
                back.state IS NOT NULL, bb.account_id IS NOT NULL \
           FROM unnest($2::text[]) AS t(target_id) \
           LEFT JOIN follow f ON f.account_id = $1 AND f.target_account_id = t.target_id \
           LEFT JOIN account_relation b ON b.account_id = $1 AND b.target_account_id = t.target_id AND b.kind = 'block' \
           LEFT JOIN account_relation m ON m.account_id = $1 AND m.target_account_id = t.target_id AND m.kind = 'mute' \
           LEFT JOIN follow back ON back.account_id = t.target_id AND back.target_account_id = $1 AND back.state = 'accepted' \
           LEFT JOIN account_relation bb ON bb.account_id = t.target_id AND bb.target_account_id = $1 AND bb.kind = 'block'",
    )
    .bind(viewer)
    .bind(ids)
    .fetch_all(executor)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let relationship = Relationship {
                following: row.1.as_deref() == Some("accepted"),
                requested: row.1.as_deref() == Some("pending"),
                showing_reblogs: row.2.unwrap_or(false),
                notifying: row.3.unwrap_or(false),
                blocked: row.4,
                muting: row.5,
                muting_notifications: row.6,
                followed_by: row.7,
                blocked_by: row.8,
            };
            (row.0, relationship)
        })
        .collect())
}

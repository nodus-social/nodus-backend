//! A page's polls: the question, its tallies and the viewer's own choices.
//!
//! The poll document used to read the tally and the viewer's vote per status, so a page
//! of twenty questions paid up to eighty statements for facts that fit in four. The
//! tallies of a local poll and a federated one are the same fact (votes per option) read
//! from the table that owns it, so one statement covers both; the row's own
//! `voters_count` is the peer's snapshot, never recomputed from local rows.

use std::collections::HashMap;

use sqlx::PgConnection;

use crate::hydrate::RowMap;
use crate::polls::PollRow;

/// One poll with the vote facts a poll document is built from.
pub struct PollFacts {
    pub poll: PollRow,
    /// Votes per option, in option order.
    pub counts: Vec<i64>,
    /// Distinct local voters, or the peer's snapshot on a federated poll.
    pub voters_count: i64,
    /// `None` when the reader is signed out.
    pub voted: Option<bool>,
    /// The options the viewer chose, ascending; `None` when signed out.
    pub own_votes: Option<Vec<i32>>,
}

/// The raw vote rows for a page of polls: per-option counts, distinct voters, and the
/// viewer's own choices (empty when signed out).
struct Votes {
    tallies: Vec<(String, i32, i64)>,
    voters: Vec<(String, i64)>,
    own: Vec<(String, i32)>,
}

async fn read_votes(
    conn: &mut PgConnection,
    poll_ids: &[String],
    viewer: Option<&str>,
) -> Result<Votes, sqlx::Error> {
    let tallies: Vec<(String, i32, i64)> = sqlx::query_as(
        "SELECT poll_id, option_index, COUNT(*)::bigint AS votes FROM poll_vote \
           WHERE poll_id = ANY($1) GROUP BY poll_id, option_index \
         UNION ALL \
         SELECT poll_id, option_index, votes FROM poll_tally WHERE poll_id = ANY($1)",
    )
    .bind(poll_ids)
    .fetch_all(&mut *conn)
    .await?;
    let voters: Vec<(String, i64)> = sqlx::query_as(
        "SELECT poll_id, COUNT(DISTINCT account_id) AS voters FROM poll_vote \
          WHERE poll_id = ANY($1) GROUP BY poll_id",
    )
    .bind(poll_ids)
    .fetch_all(&mut *conn)
    .await?;
    let own: Vec<(String, i32)> = match viewer {
        Some(account_id) => {
            sqlx::query_as(
                "SELECT poll_id, option_index FROM poll_vote \
                  WHERE poll_id = ANY($1) AND account_id = $2 ORDER BY poll_id, option_index",
            )
            .bind(poll_ids)
            .bind(account_id)
            .fetch_all(&mut *conn)
            .await?
        }
        None => Vec::new(),
    };
    Ok(Votes {
        tallies,
        voters,
        own,
    })
}

/// Reads every poll attached to a page of statuses, keyed by status id.
///
/// A status with no poll, or whose status has been deleted, is absent from the map: the
/// caller renders no poll rather than an empty one.
pub(crate) async fn fetch_polls(
    conn: &mut PgConnection,
    status_ids: &[String],
    viewer: Option<&str>,
) -> Result<RowMap<PollFacts>, sqlx::Error> {
    if status_ids.is_empty() {
        return Ok(RowMap::new());
    }
    let polls = sqlx::query_as::<_, PollRow>(&format!(
        "SELECT {} FROM poll p JOIN status s ON s.id = p.status_id \
         WHERE p.status_id = ANY($1) AND s.deleted_at IS NULL",
        crate::polls::COLUMNS
    ))
    .bind(status_ids)
    .fetch_all(&mut *conn)
    .await?;
    if polls.is_empty() {
        return Ok(RowMap::new());
    }
    let poll_ids: Vec<String> = polls.iter().map(|poll| poll.id.clone()).collect();

    let Votes {
        tallies,
        voters,
        own,
    } = read_votes(&mut *conn, &poll_ids, viewer).await?;

    let mut counts_by_poll: HashMap<&str, Vec<(i32, i64)>> = HashMap::new();
    for (poll_id, index, count) in &tallies {
        counts_by_poll
            .entry(poll_id.as_str())
            .or_default()
            .push((*index, *count));
    }
    let voters_by_poll: HashMap<&str, i64> = voters
        .iter()
        .map(|(poll_id, total)| (poll_id.as_str(), *total))
        .collect();
    let mut own_by_poll: HashMap<&str, Vec<i32>> = HashMap::new();
    for (poll_id, index) in &own {
        own_by_poll
            .entry(poll_id.as_str())
            .or_default()
            .push(*index);
    }

    let mut map: RowMap<PollFacts> = RowMap::new();
    for poll in polls {
        let mut counts = vec![0; poll.options.0.len()];
        for (index, votes) in counts_by_poll
            .get(poll.id.as_str())
            .map_or(&[][..], Vec::as_slice)
        {
            if let Ok(index) = usize::try_from(*index) {
                if let Some(slot) = counts.get_mut(index) {
                    *slot = *votes;
                }
            }
        }
        let voters_count = if poll.local {
            voters_by_poll.get(poll.id.as_str()).copied().unwrap_or(0)
        } else {
            poll.voters_count
        };
        let (voted, own_votes) = match viewer {
            Some(_) => {
                let chosen = own_by_poll
                    .get(poll.id.as_str())
                    .cloned()
                    .unwrap_or_default();
                (Some(!chosen.is_empty()), Some(chosen))
            }
            None => (None, None),
        };
        map.insert(
            poll.status_id.clone(),
            PollFacts {
                poll,
                counts,
                voters_count,
                voted,
                own_votes,
            },
        );
    }
    Ok(map)
}

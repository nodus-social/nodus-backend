//! Acting on inbound media with the instance's own content sets.
//!
//! A content set is a list an administrator uploaded as `scanner_asset.kind = 'hashes'`:
//! one entry per line, 64 hex characters for a SHA-256 or 16 for a dHash. Until this module
//! existed the sets only sat there to be downloaded by a scanner service that nothing
//! pointed at federated media, so a hostile picture federated into a thread stayed visible
//! until a moderator happened to look.
//!
//! Two rules shape what happens here. The bytes are hashed in flight and dropped — the peer
//! keeps the only copy, and keeping an archive of everything strangers post is exactly what
//! `nodus_server_media` says this instance must not grow. And a match quarantines, it does
//! not delete: a false positive on a hash set is a decision for a human, and a post that
//! vanished without a trace is indistinguishable from a bug.

use std::collections::HashSet;
use std::time::Duration;

use serde_json::json;
use sqlx::PgPool;

use crate::state::AppState;

use nodus_server_media::hash::Hashes;
use nodus_server_store::media::{self, MediaRow};
use nodus_server_store::moderation::{self, NewReport};
use nodus_server_store::statuses;

use crate::remote::fetch_media_bytes;

/// How far a dHash may drift and still be the same picture, in flipped bits out of 64.
///
/// A dHash is deliberately blunt: it compares each pixel of an 8x8 luma copy with its
/// right-hand neighbour, so re-encoding a JPEG, changing its size or re-compressing it
/// typically flips two or three bits. Ten bits (about 15%) leaves room for that kind of
/// damage while staying far below the roughly 32 bits two unrelated photographs differ by,
/// which is where a threshold stops rejecting anything at all. Wider than ten starts
/// matching "a photo with the same overall gradient", and a quarantine on that basis is a
/// report a moderator has to dismiss by hand.
pub const PERCEPTUAL_DISTANCE_MAX: u32 = 10;

/// How long the whole check may take for one status, including its fetches.
///
/// Ingest is on the delivery path: a peer that answers in eight seconds because its media
/// host is slow must not hold the status row open, and the check can always be re-run.
const SCREEN_BUDGET: Duration = Duration::from_secs(8);

/// What a set matched, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// The `scanner_asset.name` of the set that matched.
    pub set: String,
    /// Bits that differed, when the match was perceptual rather than exact.
    pub distance: Option<u32>,
}

impl Hit {
    fn describe(&self) -> String {
        match self.distance {
            None => "exactly".to_owned(),
            Some(0) => "exactly, by dHash".to_owned(),
            Some(bits) => format!("within {bits} of 64 dHash bits"),
        }
    }
}

/// One loaded content set.
#[derive(Debug, Default)]
struct Set {
    name: String,
    exact: HashSet<String>,
    perceptual: Vec<u64>,
}

/// Every registered hash set, parsed once per check.
#[derive(Debug, Default)]
pub struct Sets {
    sets: Vec<Set>,
}

impl Sets {
    /// Reads the sets named `kind = 'hashes'` and parses them.
    ///
    /// One query per status, not one per attachment: a set is up to sixty-four megabytes
    /// and the ingest path already knows how many attachments it has.
    pub async fn load(pool: &PgPool) -> Result<Self, sqlx::Error> {
        let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT name, content FROM scanner_asset WHERE kind = 'hashes' \
             ORDER BY created_at ASC",
        )
        .fetch_all(pool)
        .await?;
        Ok(Self::parse(rows))
    }

    /// Parses `(name, bytes)` pairs.
    ///
    /// One entry per line. `#` starts a comment, blank lines are ignored, and the length of
    /// the entry decides what it is: 64 hex characters is a SHA-256, 16 is a dHash. Case is
    /// not significant, so a set copied out of a spreadsheet or a tool still works.
    #[must_use]
    pub fn parse(rows: Vec<(String, Vec<u8>)>) -> Self {
        let mut sets = Vec::with_capacity(rows.len());
        for (name, content) in rows {
            let mut set = Set {
                name,
                ..Set::default()
            };
            for line in String::from_utf8_lossy(&content).lines() {
                let entry = line.split('#').next().unwrap_or_default().trim();
                if entry.len() == 64 && entry.bytes().all(|b| b.is_ascii_hexdigit()) {
                    set.exact.insert(entry.to_ascii_lowercase());
                } else if entry.len() == 16 && entry.bytes().all(|b| b.is_ascii_hexdigit()) {
                    if let Ok(bits) = u64::from_str_radix(entry, 16) {
                        set.perceptual.push(bits);
                    }
                }
            }
            if !set.exact.is_empty() || !set.perceptual.is_empty() {
                sets.push(set);
            }
        }
        Self { sets }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }

    /// The set a pair of hashes belongs to, exact matches first.
    ///
    /// An exact match is evidence; a near one is a suspicion. Reporting the exact set when
    /// there is one keeps the reason text honest when a picture is listed twice.
    #[must_use]
    pub fn matches(&self, hashes: &Hashes) -> Option<Hit> {
        for set in &self.sets {
            if set.exact.contains(&hashes.content_hash) {
                return Some(Hit {
                    set: set.name.clone(),
                    distance: None,
                });
            }
        }
        let bits = hashes.perceptual_bits()?;
        let mut best: Option<Hit> = None;
        for set in &self.sets {
            for candidate in &set.perceptual {
                let distance = (bits ^ candidate).count_ones();
                let better = match &best {
                    None => true,
                    Some(hit) => hit.distance.is_none_or(|seen| distance < seen),
                };
                if distance <= PERCEPTUAL_DISTANCE_MAX && better {
                    best = Some(Hit {
                        set: set.name.clone(),
                        distance: Some(distance),
                    });
                }
            }
        }
        best
    }
}

/// Checks one ingested status against the registered sets, and quarantines what matches.
///
/// Returns how many attachments were newly quarantined. Runs only for federated media:
///
/// **Local uploads are never quarantined.** An upload is already ours — it was accepted
/// under this instance's rules, its author is an account we admitted, and the media path
/// has a report button on it. Running a hash set against our own members' files would turn
/// a false positive into this instance silently hiding its own user's post, with nobody to
/// appeal to but the moderator who sees the queue. Only `remote` rows are considered; see
/// the filter below.
pub async fn screen_status(
    pool: &PgPool,
    status_id: &str,
    account_id: &str,
) -> Result<usize, sqlx::Error> {
    Ok(screen(pool, status_id, account_id).await?.0)
}

/// The same check, with the one thing a pool alone cannot do: when a post is hidden, its
/// id leaves every follower's cached home timeline too, and the removal is published to
/// the other replicas through the invalidation sink.
pub async fn screen_status_with(
    state: &AppState,
    status_id: &str,
    account_id: &str,
) -> Result<usize, sqlx::Error> {
    let pool = state.store().pool();
    let (matched, hidden) = screen(pool, status_id, account_id).await?;
    if hidden {
        crate::home::hide(state, account_id, status_id).await;
    }
    Ok(matched)
}

/// The check itself: `(attachments matched, post newly hidden)`.
async fn screen(
    pool: &PgPool,
    status_id: &str,
    account_id: &str,
) -> Result<(usize, bool), sqlx::Error> {
    let rows = media::by_status(pool, status_id).await?;
    let pending: Vec<MediaRow> = rows
        .into_iter()
        // Federated only — see the note on this function. `released` is not re-checked: a
        // moderator has already looked at that picture and said it is fine.
        .filter(|row| row.remote && row.quarantine_state == "none" && row.remote_url.is_some())
        .collect();
    if pending.is_empty() {
        return Ok((0, false));
    }

    let sets = Sets::load(pool).await?;
    if sets.is_empty() {
        // No set to compare against: the check is a read and a no-op, which is why an
        // instance that never uploaded one pays nothing for this path.
        return Ok((0, false));
    }

    let outcome = tokio::time::timeout(SCREEN_BUDGET, async {
        let mut matched = 0;
        let mut hidden = false;
        for row in pending {
            let hashes = match hash_row(pool, &row).await {
                Ok(Some(hashes)) => hashes,
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(media = %row.id, %error, "could not hash inbound media");
                    continue;
                }
            };
            let Some(hit) = sets.matches(&hashes) else {
                continue;
            };
            hidden |= quarantine(pool, &row, account_id, &hit).await?;
            matched += 1;
        }
        Ok::<(usize, bool), sqlx::Error>((matched, hidden))
    })
    .await;

    if let Ok(result) = outcome {
        result
    } else {
        tracing::warn!(status = %status_id, "media check ran out of its time budget");
        Ok((0, false))
    }
}

/// The hashes of one attachment, fetched and computed only if this row has none yet.
async fn hash_row(pool: &PgPool, row: &MediaRow) -> Result<Option<Hashes>, sqlx::Error> {
    if let Some(content_hash) = row.content_hash.clone() {
        return Ok(Some(Hashes {
            content_hash,
            perceptual_hash: row.perceptual_hash.clone(),
        }));
    }
    let Some(url) = row.remote_url.as_deref() else {
        return Ok(None);
    };
    let Some(bytes) = fetch_media_bytes(url).await else {
        // A media host that does not answer is not a reason to refuse the post: the check
        // is best-effort, and the row keeps no hash so a later fetch can still catch it.
        return Ok(None);
    };
    let hashes = Hashes::of_bytes(&bytes, row.content_type.starts_with("image/"));
    media::set_hashes(
        pool,
        &row.id,
        &hashes.content_hash,
        hashes.perceptual_hash.as_deref(),
    )
    .await?;
    Ok(Some(hashes))
}

/// Hides the attachment and its post, and puts the match in the queue with a name on it.
///
/// Returns whether this call is what hid the post: the caller invalidates the cached
/// timelines only when something changed.
async fn quarantine(
    pool: &PgPool,
    row: &MediaRow,
    account_id: &str,
    hit: &Hit,
) -> Result<bool, sqlx::Error> {
    if !media::quarantine(pool, &row.id, &hit.set).await? {
        return Ok(false);
    }
    let Some(status_id) = row.status_id.as_deref() else {
        return Ok(false);
    };
    let hidden = statuses::quarantine(pool, status_id).await?;

    // The report is the queue entry: it names the set, so a moderator sees why the post is
    // gone from the timeline instead of a hole they have to guess about.
    if moderation::open_report_for_status(pool, status_id)
        .await?
        .is_none()
    {
        let comment = format!(
            "An attachment on this post matched the content set \"{}\" {} ({}). \
             The post is hidden from public timelines until a moderator decides.",
            hit.set,
            hit.describe(),
            row.remote_url.as_deref().unwrap_or("an unknown address"),
        );
        moderation::create_report(
            pool,
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
    }

    moderation::audit_system(
        pool,
        "quarantine_media",
        "media",
        Some(&row.id),
        &json!({
            "status_id": status_id,
            "set": hit.set,
            "distance": hit.distance,
            "content_hash": row.content_hash,
            "url": row.remote_url,
        }),
    )
    .await?;
    tracing::info!(
        media = %row.id,
        status = %status_id,
        set = %hit.set,
        "quarantined inbound media"
    );
    Ok(hidden)
}

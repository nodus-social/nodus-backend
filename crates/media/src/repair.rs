//! The repair walk: make every member hold what placement says it should.
//!
//! Replication on write covers the normal case, but it is best effort by design — an
//! upload is answered before any peer is asked, and a node that was down at that moment
//! never hears about the digest. The walk is the slow, periodic answer: page the
//! catalogue, compare each digest against the members that should hold it, and move the
//! bytes that are missing on either side.
//!
//! Nothing here deletes. A membership change moves keys for a moment, so a copy that
//! looks "extra" against today's placement may be exactly what protects the digest until
//! the next write repairs the new owner; deleting it would be a data loss that no later
//! pass could undo. Extras are counted so an operator can see the drift, not removed.

use std::path::Path;

use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::cluster::{self, placement, Member, REPLICAS};
use crate::hash::hex;
use crate::serve::write_atomically;
use nodus_server_store::{media, media_nodes};

/// Digests per catalogue page. Large enough that a pass is a few hundred queries rather
/// than a few thousand, small enough that one page of digests stays a cheap vector.
pub const PAGE: i64 = 500;

/// What one pass did. `extra` is informational: those copies are deliberately kept.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// Copies taken from a peer because the local file was missing.
    pub repaired: u32,
    /// Copies sent to a replica that did not have the digest.
    pub pushed: u32,
    /// Digests no member of the placement holds at all.
    pub unreadable: u32,
    /// Copies held outside the current placement. Counted, never deleted.
    pub extra: u32,
}

impl Summary {
    /// The one line the background task logs for a pass.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "repaired={} pushed={} unreadable={} extra={}",
            self.repaired, self.pushed, self.unreadable, self.extra
        )
    }

    fn add(&mut self, other: Self) {
        self.repaired += other.repaired;
        self.pushed += other.pushed;
        self.unreadable += other.unreadable;
        self.extra += other.extra;
    }
}

/// Walks the whole catalogue, one page at a time.
///
/// A failure on one digest, or one page, is logged and left for the next pass: the walk
/// exists to make progress on a cluster that is partly broken, so stopping at the first
/// error would make a single bad row hide every row after it.
pub async fn pass(pool: &PgPool, root: &Path, node: &str, token: &str) -> Summary {
    let mut summary = Summary::default();
    let mut after: Option<String> = None;
    loop {
        let page = match media::digest_page(pool, after.as_deref(), PAGE).await {
            Ok(page) => page,
            Err(error) => {
                tracing::warn!(%error, "could not page the media catalogue for repair");
                break;
            }
        };
        if page.is_empty() {
            break;
        }
        let full = i64::try_from(page.len()).unwrap_or(i64::MAX) == PAGE;
        after = page.last().map(|(id, _)| id.clone());
        // Membership is read per page: a pass over a large catalogue takes long enough
        // that a node may join or leave while it runs, and repairing against a stale
        // member set would push bytes at an address that no longer exists.
        let nodes = match media_nodes::members(pool, cluster::MEMBER_MAX_AGE).await {
            Ok(nodes) => nodes,
            Err(error) => {
                tracing::warn!(%error, "could not read the membership for repair");
                break;
            }
        };
        if nodes.len() < 2 {
            break;
        }
        let members: Vec<Member> = nodes
            .into_iter()
            .map(|node| Member {
                name: node.name,
                endpoint: node.endpoint,
            })
            .collect();
        let digests: Vec<String> = page.into_iter().map(|(_, digest)| digest).collect();
        summary.add(repair_digests(root, node, Some(token), &digests, &members).await);
        if !full {
            break;
        }
    }
    summary
}

/// Repairs an explicit list of digests against an explicit member set.
///
/// Split out from [`pass`] so a test can run the walk over a temporary directory and
/// fake peers without a database. `None` for the token means the instance is single
/// node: there is nobody to compare against, and nothing is read, written or waited for.
pub async fn repair_digests(
    root: &Path,
    node: &str,
    token: Option<&str>,
    digests: &[String],
    members: &[Member],
) -> Summary {
    let Some(token) = token else {
        return Summary::default();
    };
    if members.len() < 2 {
        return Summary::default();
    }
    let mut summary = Summary::default();
    for digest in digests {
        summary.add(repair_one(root, node, token, digest, members).await);
    }
    summary
}

/// One digest: fetch it here if a replica has it, push it out if a replica lacks it.
async fn repair_one(
    root: &Path,
    node: &str,
    token: &str,
    digest: &str,
    members: &[Member],
) -> Summary {
    let mut summary = Summary::default();
    let placed = placement(digest, members, REPLICAS);
    let mut local = tokio::fs::metadata(root.join(digest))
        .await
        .is_ok_and(|metadata| metadata.is_file());
    let peers: Vec<&Member> = placed
        .iter()
        .copied()
        .filter(|member| member.name != node && !member.endpoint.is_empty())
        .collect();

    if local {
        for peer in &peers {
            if cluster::has(&peer.endpoint, token, digest).await {
                continue;
            }
            let Ok(bytes) = tokio::fs::read(root.join(digest)).await else {
                break;
            };
            if hex(&Sha256::digest(&bytes)) != digest {
                tracing::warn!(%digest, "the local copy does not hash to its digest");
                summary.unreadable += 1;
                break;
            }
            if cluster::put(&peer.endpoint, token, digest, &bytes).await {
                summary.pushed += 1;
            }
        }
    } else {
        let mut found = false;
        for peer in &peers {
            let Some(bytes) = cluster::fetch(&peer.endpoint, token, digest).await else {
                continue;
            };
            found = true;
            match write_atomically(root, digest, &bytes).await {
                Ok(()) => {
                    summary.repaired += 1;
                    local = true;
                    break;
                }
                Err(error) => {
                    tracing::warn!(%error, %digest, "could not keep repaired bytes");
                    break;
                }
            }
        }
        if !found {
            summary.unreadable += 1;
        }
    }

    // Copies outside the placement are counted, never removed: see the module comment.
    for member in members {
        if placed.iter().any(|held| held.name == member.name) {
            continue;
        }
        let holds = if member.name == node {
            local
        } else if member.endpoint.is_empty() {
            false
        } else {
            cluster::has(&member.endpoint, token, digest).await
        };
        if holds {
            summary.extra += 1;
        }
    }
    summary
}

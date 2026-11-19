//! Rendezvous placement of media among live nodes.
//!
//! Media is content-addressed, so which node holds a digest is a pure function of the
//! digest and the member set: no catalogue of "this node has that file" has to be kept in
//! sync, and no request needs a lookup before it knows where to go.
//!
//! Rendezvous (highest-random-weight) hashing is used rather than modulo because adding a
//! node moves only the keys that node now wins — about `1/n` of them — instead of
//! reshuffling almost everything as `hash % n` would. Replication is the same ranking cut
//! at `R`: the owner is the highest score, the replica is the next one.

use sha2::{Digest, Sha256};

use crate::hash::hex;

/// How many nodes hold a digest: the owner and one replica.
pub const REPLICAS: usize = 2;

/// How old a heartbeat may be before a node stops being a placement target.
pub const MEMBER_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(600);

/// The shared secret every internal request presents.
pub const TOKEN_HEADER: &str = "x-nodus-cluster";

/// Marks a delete that has already been fanned out, so the peer removes its own copy and
/// does not fan it out again — otherwise two nodes would bounce the same delete forever.
pub const NO_FANOUT_HEADER: &str = "x-nodus-no-fanout";

/// How long one peer gets to answer before it counts as absent.
pub const PEER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

/// How long the caller of a cluster-wide delete waits for the node it asked.
///
/// Longer than one peer deadline because that node then fans out to the rest, and its
/// answer only arrives once its own peers were tried.
const DELETE_BUDGET: std::time::Duration = std::time::Duration::from_secs(15);

/// A node that is currently a member of the cluster.
///
/// The endpoint is carried alongside the name because a peer that has to fetch a digest
/// needs somewhere to send the request; placement itself only reads the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub endpoint: String,
}

/// One shared client for every peer call: a client owns the connection pool, and building
/// one per miss would throw that away on every request.
fn client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

/// `{endpoint}/internal/media/{digest}`, with the endpoint's trailing slash tolerated.
fn media_url(endpoint: &str, digest: &str) -> String {
    format!("{}/internal/media/{digest}", endpoint.trim_end_matches('/'))
}

/// `GET /internal/media/{digest}` from one peer, bounded by [`PEER_DEADLINE`].
///
/// A peer that answers with a 404, with bytes that do not hash to the digest, or not at
/// all is `None`: a miss on a replica is not an error the client should see, it is the
/// next step of the search.
#[must_use]
pub async fn fetch(endpoint: &str, token: &str, digest: &str) -> Option<Vec<u8>> {
    let request = client()
        .get(media_url(endpoint, digest))
        .header(TOKEN_HEADER, token)
        .send();
    let attempt = async {
        let response = request.await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        response.bytes().await.ok()
    };
    match tokio::time::timeout(PEER_DEADLINE, attempt).await {
        Ok(Some(bytes)) if hex(&Sha256::digest(&bytes)) == digest => Some(bytes.to_vec()),
        _ => None,
    }
}

/// `DELETE /internal/media/{digest}` on one peer, best effort.
///
/// The fan-out marker says "delete your copy, but do not pass this on": the node that
/// received the original request already asked every member it knows about.
#[must_use]
pub async fn delete_peer(endpoint: &str, token: &str, digest: &str) -> bool {
    let request = client()
        .delete(media_url(endpoint, digest))
        .header(TOKEN_HEADER, token)
        .header(NO_FANOUT_HEADER, "1")
        .send();
    matches!(
        tokio::time::timeout(PEER_DEADLINE, request).await,
        Ok(Ok(response)) if response.status().is_success()
    )
}

/// Asks a media node to delete a digest everywhere, which it fans out to its members.
///
/// Returns whether the node confirmed. A `false` is not an error for the caller: the
/// bytes are unreferenced either way, and the local copy is still there to remove.
#[must_use]
pub async fn request_delete(base: &str, token: &str, digest: &str) -> bool {
    let request = client()
        .delete(media_url(base, digest))
        .header(TOKEN_HEADER, token)
        .send();
    matches!(
        tokio::time::timeout(DELETE_BUDGET, request).await,
        Ok(Ok(response)) if response.status().is_success()
    )
}

/// The nodes that own a digest, best first: `[0]` is the owner, the rest are replicas.
///
/// `replicas` is clamped to the member count and is at least 1 whenever there is a member,
/// so a caller can ask for "two, if there are two". With no members the result is empty
/// rather than a panic: an instance before its first heartbeat still has to serve.
#[must_use]
pub fn placement<'a>(digest: &str, members: &'a [Member], replicas: usize) -> Vec<&'a Member> {
    if members.is_empty() {
        return Vec::new();
    }
    let mut ranked: Vec<(u64, &Member)> = members
        .iter()
        .map(|member| (score(digest, &member.name), member))
        .collect();
    // Descending score; ties broken by name so two processes given the same set always
    // produce the same owner, no matter what order the database returned the rows in.
    ranked.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.name.cmp(&right.1.name))
    });
    let wanted = replicas.clamp(1, members.len());
    ranked
        .into_iter()
        .take(wanted)
        .map(|(_, member)| member)
        .collect()
}

/// The first eight bytes of `SHA-256(digest || NUL || name)`, big-endian.
///
/// The NUL is a separator rather than a delimiter that can appear in either input: a
/// digest is hex and a name is operator-supplied text, and hashing `"ab" + "c"` the same
/// as `"a" + "bc"` would let two different pairs collide by construction.
fn score(digest: &str, name: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(digest.as_bytes());
    hasher.update([0u8]);
    hasher.update(name.as_bytes());
    let bytes = hasher.finalize();
    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members(names: &[&str]) -> Vec<Member> {
        names
            .iter()
            .map(|name| Member {
                name: (*name).to_owned(),
                endpoint: format!("http://{name}:3003"),
            })
            .collect()
    }

    fn names(placed: &[&Member]) -> Vec<String> {
        placed.iter().map(|member| member.name.clone()).collect()
    }

    #[test]
    fn a_shuffled_member_list_places_identically() {
        let digest = "a3f1c8e0b7d94a52c6e18f0d3b7a95e2c4d6f8a0b1c3e5d7f9a2b4c6d8e0f1a3";
        let forward = members(&["alpha", "beta", "gamma", "delta"]);
        let mut shuffled = forward.clone();
        shuffled.reverse();
        assert_eq!(
            names(&placement(digest, &forward, 3)),
            names(&placement(digest, &shuffled, 3))
        );
    }

    #[test]
    fn adding_a_member_moves_fewer_than_half_of_the_digests() {
        let before = members(&["alpha", "beta"]);
        let after = members(&["alpha", "beta", "gamma"]);
        let mut moved = 0;
        for index in 0..200u32 {
            let digest = format!("{index:064x}");
            if placement(&digest, &before, 1)[0].name != placement(&digest, &after, 1)[0].name {
                moved += 1;
            }
        }
        // A loose sanity bound, not a proof of the hashing: modulo placement would move
        // roughly every key here, so anything near 100 means the ranking is broken.
        assert!(moved < 100, "adding a member moved {moved} of 200 digests");
    }

    #[test]
    fn replicas_are_clamped_to_the_member_count_and_never_zero() {
        let members = members(&["alpha", "beta"]);
        assert_eq!(placement("aa", &members, 0).len(), 1);
        assert_eq!(placement("aa", &members, 99).len(), 2);
        assert_eq!(placement("aa", &[], 2), Vec::<&Member>::new());
    }

    /// Pins one literal answer. A refactor may change the ranking of every other digest,
    /// but not by accident: this test has to be edited deliberately.
    #[test]
    fn a_known_digest_has_a_known_owner() {
        let members = members(&["alpha", "beta", "gamma"]);
        let digest = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            names(&placement(digest, &members, 3)),
            vec!["gamma", "alpha", "beta"]
        );
    }
}

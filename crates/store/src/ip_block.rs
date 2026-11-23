//! Source-address blocks: what a network may do before it has an account.
//!
//! An address is matched at the granularity the session table records — `/24` for IPv4 and
//! `/48` for IPv6 — because that truncation is the only address the instance keeps. A block
//! written as a single host is widened to that prefix at write time, and a wider CIDR is
//! kept as written: "one host" and "this /16" are different intentions, and only the first
//! one has to be widened to be enforceable.
//!
//! Expiry is filtered in every query rather than swept. A row past `expires_at` stops
//! matching the next time it is read, with no cron to trust and no window in which a lapsed
//! block still applies.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::PgPool;

/// New registrations from the address wait for a moderator instead of going live.
pub const SIGN_UP_REQUIRES_APPROVAL: &str = "sign_up_requires_approval";
/// New registrations from the address are refused.
pub const SIGN_UP_BLOCK: &str = "sign_up_block";
/// No request from the address reaches the instance.
pub const NO_ACCESS: &str = "no_access";

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct IpBlock {
    pub id: String,
    /// The canonical CIDR, e.g. `203.0.113.0/24`.
    pub ip: String,
    pub severity: String,
    pub comment: String,
    pub created_at: DateTime<Utc>,
    /// `None` means the block has no end.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Which severity a block on `prefix` carries, strongest first.
///
/// `None` means no live block covers the address. A caller that only cares about one
/// severity still gets the strongest answer, so it can tell "blocked from signing up" from
/// "blocked from everything" without a second query.
pub async fn verdict(pool: &PgPool, prefix: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT severity FROM ip_block \
         WHERE (expires_at IS NULL OR expires_at > now()) AND $1::inet <<= ip::inet \
         ORDER BY CASE severity WHEN 'no_access' THEN 0 WHEN 'sign_up_block' THEN 1 ELSE 2 END \
         LIMIT 1",
    )
    .bind(prefix)
    .fetch_optional(pool)
    .await
}

/// One block by id, expired or not: an edit's audit row needs the state it replaced even
/// after that state stopped applying.
pub async fn find(pool: &PgPool, id: &str) -> Result<Option<IpBlock>, sqlx::Error> {
    sqlx::query_as::<_, IpBlock>(
        "SELECT id, ip::text AS ip, severity, comment, created_at, expires_at \
         FROM ip_block WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Whether requests from `prefix` are refused outright.
pub async fn no_access(pool: &PgPool, prefix: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM ip_block \
         WHERE severity = 'no_access' \
           AND (expires_at IS NULL OR expires_at > now()) \
           AND $1::inet <<= ip::inet)",
    )
    .bind(prefix)
    .fetch_one(pool)
    .await
}

pub async fn list(pool: &PgPool) -> Result<Vec<IpBlock>, sqlx::Error> {
    sqlx::query_as::<_, IpBlock>(
        "SELECT id, ip::text AS ip, severity, comment, created_at, expires_at \
         FROM ip_block WHERE expires_at IS NULL OR expires_at > now() \
         ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
}

/// The id a new block is stored under.
///
/// One table, one key: the API hands the caller back the same id Mastodon's numeric column
/// would have, and nothing downstream has to know which form it is.
fn new_id() -> String {
    ulid::Ulid::new().to_string()
}

pub async fn insert(
    pool: &PgPool,
    ip: &str,
    severity: &str,
    comment: &str,
    expires_in: Option<i64>,
) -> Result<IpBlock, sqlx::Error> {
    let expires_at = expires_in.map(|seconds| Utc::now() + Duration::seconds(seconds));
    sqlx::query_as::<_, IpBlock>(
        "INSERT INTO ip_block (id, ip, severity, comment, expires_at) \
         VALUES ($1, $2::cidr, $3, $4, $5) \
         RETURNING id, ip::text AS ip, severity, comment, created_at, expires_at",
    )
    .bind(new_id())
    .bind(ip)
    .bind(severity)
    .bind(comment)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

/// Rewrites a block's severity, comment and expiry.
///
/// `expires_in` of `None` means "no end", matching the create body: an edit that omits the
/// field clears the end rather than leaving the old one in place, because a form that shows
/// an empty expiry is showing what the administrator meant.
pub async fn update(
    pool: &PgPool,
    id: &str,
    severity: &str,
    comment: &str,
    expires_in: Option<i64>,
) -> Result<Option<IpBlock>, sqlx::Error> {
    let expires_at = expires_in.map(|seconds| Utc::now() + Duration::seconds(seconds));
    sqlx::query_as::<_, IpBlock>(
        "UPDATE ip_block SET severity = $2, comment = $3, expires_at = $4 \
         WHERE id = $1 \
         RETURNING id, ip::text AS ip, severity, comment, created_at, expires_at",
    )
    .bind(id)
    .bind(severity)
    .bind(comment)
    .bind(expires_at)
    .fetch_optional(pool)
    .await
}

pub async fn delete(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM ip_block WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Parses an administrator's address or CIDR into the canonical form the table stores.
///
/// The result is never narrower than the session truncation: a bare `203.0.113.7` and an
/// explicit `/32` both become `203.0.113.0/24`, because a block on a host the instance
/// cannot distinguish from its neighbours would be a promise it cannot keep. A wider
/// prefix (`/16`, `/48`, …) is kept and masked to its network address.
pub fn normalize(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("an address or CIDR is required".to_owned());
    }
    let explicit = raw.split_once('/');
    let (address, bits) = match explicit {
        Some((address, bits)) => (
            address,
            bits.parse::<u8>()
                .map_err(|_| "the prefix length is not a number".to_owned())?,
        ),
        // A single address is not a /32 or /128: it is the session prefix that will
        // actually be compared against it.
        None => (raw, 0),
    };
    let address: IpAddr = address
        .parse()
        .map_err(|_| "that is not an IPv4 or IPv6 address".to_owned())?;
    // A dual-stack listener reports IPv4 callers as `::ffff:a.b.c.d`; they must be widened
    // as IPv4 or every one of them collapses into one useless IPv6 prefix.
    let address = match address {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        IpAddr::V4(ip) => IpAddr::V4(ip),
    };
    let (bits, network) = match address {
        IpAddr::V4(ip) => {
            let bits = if explicit.is_some() { bits } else { PRIVACY_V4 };
            if bits == 0 || bits > 32 {
                return Err("an IPv4 prefix is between 1 and 32 bits".to_owned());
            }
            let bits = bits.min(PRIVACY_V4);
            (bits, mask_v4(ip, bits))
        }
        IpAddr::V6(ip) => {
            let bits = if explicit.is_some() { bits } else { PRIVACY_V6 };
            if bits == 0 || bits > 128 {
                return Err("an IPv6 prefix is between 1 and 128 bits".to_owned());
            }
            let bits = bits.min(PRIVACY_V6);
            (bits, mask_v6(ip, bits))
        }
    };
    Ok(match network {
        IpAddr::V4(ip) => format!("{ip}/{bits}"),
        IpAddr::V6(ip) => format!("{ip}/{bits}"),
    })
}

const PRIVACY_V4: u8 = 24;
const PRIVACY_V6: u8 = 48;

fn mask_v4(ip: Ipv4Addr, bits: u8) -> IpAddr {
    let mask = u32::MAX << (32 - u32::from(bits));
    IpAddr::V4(Ipv4Addr::from(u32::from(ip) & mask))
}

fn mask_v6(ip: Ipv6Addr, bits: u8) -> IpAddr {
    let mask = u128::MAX << (128 - u32::from(bits));
    IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_host_is_widened_to_the_session_prefix() {
        assert_eq!(normalize("203.0.113.7").expect("v4"), "203.0.113.0/24");
        assert_eq!(normalize("203.0.113.7/32").expect("v4"), "203.0.113.0/24");
        assert_eq!(
            normalize("2001:db8:1234::1").expect("v6"),
            "2001:db8:1234::/48"
        );
    }

    #[test]
    fn a_wider_prefix_is_kept() {
        assert_eq!(normalize("203.0.0.0/16").expect("v4"), "203.0.0.0/16");
        assert_eq!(normalize("2001:db8::/32").expect("v6"), "2001:db8::/32");
    }

    #[test]
    fn an_ipv4_mapped_address_is_an_ipv4_block() {
        assert_eq!(
            normalize("::ffff:203.0.113.7").expect("mapped"),
            "203.0.113.0/24"
        );
    }

    #[test]
    fn a_malformed_address_is_refused() {
        assert!(normalize("not-an-address").is_err());
        assert!(normalize("203.0.113.7/33").is_err());
        assert!(normalize("").is_err());
    }
}

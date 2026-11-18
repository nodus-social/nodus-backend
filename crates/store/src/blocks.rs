//! Remote actors that told us they block this instance.
//!
//! A block is a delivery instruction, not a moderation decision: the peer stays readable
//! and keeps its posts here, but the outbound queue stops addressing its host.

use sqlx::PgPool;

use nodus_server_core::Id;

/// Records that `actor_uri` blocks this instance.
pub async fn record_remote_block(pool: &PgPool, actor_uri: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO remote_block (id, actor_uri) VALUES ($1, $2) \
         ON CONFLICT (actor_uri) DO NOTHING",
    )
    .bind(Id::new().to_string())
    .bind(actor_uri)
    .execute(pool)
    .await?;
    Ok(())
}

/// The hosts whose actors block this instance, lowercased and without ports.
pub async fn blocked_hosts(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    let actors: Vec<String> = sqlx::query_scalar("SELECT actor_uri FROM remote_block")
        .fetch_all(pool)
        .await?;
    let mut hosts: Vec<String> = actors.iter().filter_map(|uri| host_of(uri)).collect();
    hosts.sort();
    hosts.dedup();
    Ok(hosts)
}

/// The host an absolute URL names.
///
/// Delivery compares only hosts, so userinfo and the port are dropped: an inbox on
/// `example.test:8443` still belongs to `example.test`.
pub(crate) fn host_of(uri: &str) -> Option<String> {
    let rest = uri.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let host = match authority.strip_prefix('[') {
        Some(bracketed) => bracketed.split(']').next()?,
        None => authority.split(':').next()?,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_host_is_read_without_scheme_userinfo_or_port() {
        assert_eq!(
            super::host_of("https://remote.test/users/a/inbox").as_deref(),
            Some("remote.test")
        );
        assert_eq!(
            super::host_of("https://user@remote.test:8443/inbox").as_deref(),
            Some("remote.test")
        );
        assert_eq!(
            super::host_of("https://Remote.Test./inbox").as_deref(),
            Some("remote.test")
        );
        assert_eq!(super::host_of("not a url"), None);
        assert_eq!(super::host_of("https:///inbox"), None);
    }
}

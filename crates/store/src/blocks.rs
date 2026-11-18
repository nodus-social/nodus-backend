//! Remote actors that told us they block this instance.
//!
//! A block is a delivery instruction, not a moderation decision: the peer stays readable
//! and keeps its posts here, but the outbound queue stops addressing its host.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use nodus_server_core::Id;

/// One host that told us it blocks this instance, with the actor that said so.
#[derive(Debug, Clone)]
pub struct RemoteBlockRow {
    pub actor: String,
    pub host: String,
    pub created_at: DateTime<Utc>,
}

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

/// Everything we recorded a block for, newest first.
pub async fn remote_blocks(pool: &PgPool) -> Result<Vec<RemoteBlockRow>, sqlx::Error> {
    let rows: Vec<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT actor_uri, created_at FROM remote_block ORDER BY created_at DESC, actor_uri",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(actor, created_at)| {
            host_of(&actor).map(|host| RemoteBlockRow {
                actor,
                host,
                created_at,
            })
        })
        .collect())
}

/// Forgets every block whose actor lives on `host`.
///
/// The host is not a column: it is derived with the same parser delivery uses, so a block
/// recorded from `https://example.test:8443/users/a` is cleared by `example.test` too.
pub async fn clear_remote_blocks(pool: &PgPool, host: &str) -> Result<u64, sqlx::Error> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT id, actor_uri FROM remote_block")
        .fetch_all(pool)
        .await?;
    let ids: Vec<String> = rows
        .into_iter()
        .filter(|(_, actor)| host_of(actor).as_deref() == Some(host.as_str()))
        .map(|(id, _)| id)
        .collect();
    if ids.is_empty() {
        return Ok(0);
    }
    sqlx::query("DELETE FROM remote_block WHERE id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await?;
    Ok(ids.len() as u64)
}

/// The host an absolute URL names.
///
/// Delivery compares only hosts, so userinfo and the port are dropped: an inbox on
/// `example.test:8443` still belongs to `example.test`.
pub fn host_of(uri: &str) -> Option<String> {
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

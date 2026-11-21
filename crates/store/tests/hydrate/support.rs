//! Fixtures for the batched read seam's tests: a schema of their own, raw-SQL seeds, and
//! the one session setting the ordering test needs.

use nodus_server_core::Id;
use nodus_server_store::Store;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub async fn setup() -> Option<(Store, PgPool, String)> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect to postgres");

    // Lower case, because `search_path` folds unquoted identifiers: a name with capitals would land in `public` instead.
    let schema = format!("pgtest_hydrate_{}", Id::new()).to_lowercase();
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&admin)
        .await
        .expect("create the test schema");
    let separator = if url.contains('?') { '&' } else { '?' };
    let schema_url = format!("{url}{separator}options=-csearch_path%3D{schema}%2Cpublic");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&schema_url)
        .await
        .expect("connect the isolated pool");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    let store = Store::connect(&schema_url, 4)
        .await
        .expect("connect the store");
    Some((store, pool, schema))
}

pub async fn cleanup(pool: &PgPool, schema: &str) {
    sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(pool)
        .await
        .expect("drop the test schema");
}

/// Seeds through raw SQL: the hydration ops only read accounts by id, so the fixture needs the required columns (id, username) and nothing else.
pub async fn account(pool: &PgPool, username: &str) -> String {
    let id = Id::new().to_string();
    sqlx::query("INSERT INTO account (id, username) VALUES ($1, $2)")
        .bind(&id)
        .bind(username)
        .execute(pool)
        .await
        .expect("seed account");
    id
}

pub async fn status(pool: &PgPool, author: &str, content: &str) -> String {
    let id = Id::new().to_string();
    sqlx::query("INSERT INTO status (id, account_id, content, content_html, visibility) VALUES ($1, $2, $3, $3, 'public')")
        .bind(&id)
        .bind(author)
        .bind(content)
        .execute(pool)
        .await
        .expect("seed status");
    id
}

/// Same reasoning as `status`: the reader only needs the attachment row, so seed the required columns.
pub async fn attachment(pool: &PgPool, author: &str, status_id: &str) {
    sqlx::query("INSERT INTO media_attachment (id, account_id, status_id, digest, content_type, size) VALUES ($1, $2, $3, $4, 'image/png', 128)")
        .bind(Id::new().to_string())
        .bind(author)
        .bind(status_id)
        .bind(Id::new().to_string())
        .execute(pool)
        .await
        .expect("seed attachment");
}

pub async fn execute<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::Postgres>,
    sql: &str,
    binds: &[&str],
) {
    let mut query = sqlx::query(sql);
    for bind in binds {
        query = query.bind(*bind);
    }
    query.execute(executor).await.expect(sql);
}

/// Pins `statement_timeout` on every connection the pool can hand out: holding all of them at once means the batch's own connection is covered (the pool cannot open a fifth). The store has a pool of its own, so callers pass `store.pool()`, not the test's second pool.
pub async fn shorten_statement_timeout(pool: &PgPool) {
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(pool.acquire().await.expect("hold a connection"));
    }
    for conn in &mut held {
        sqlx::query("SET statement_timeout = 500")
            .execute(&mut **conn)
            .await
            .expect("set statement_timeout");
    }
    drop(held);
}

//! The two things `deploy/proof/media-cluster.sh` needs from a database, without `psql`.
//!
//! A proof has to run on a throwaway database — it seeds a catalogue row and it deletes
//! media files — so the script must be able to create that database and insert into it.
//! The development container has no postgres client, but it has this workspace, so the
//! proof borrows the same `sqlx` the services use:
//!
//! ```text
//! cargo run -q -p nodus-server-store --example proofdb -- create nodus_proof
//! cargo run -q -p nodus-server-store --example proofdb -- sql "INSERT ..."
//! ```
//!
//! `DATABASE_URL` names the server. `create` connects to the `postgres` database on it and
//! creates the named one if it is absent, so the script can always ask for its database
//! and stay ignorant of whether this is the first run. `sql` runs the statement against
//! `DATABASE_URL`'s own database, as written: the proof passes literal digests and ids, so
//! there is nothing to bind and nothing to escape.

use std::error::Error;
use std::str::FromStr;

use sqlx::postgres::PgConnectOptions;
use sqlx::PgPool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let url = std::env::var("DATABASE_URL")?;
    match command.as_str() {
        "create" => {
            let name = args.next().ok_or("proofdb create needs a database name")?;
            let server = PgConnectOptions::from_str(&url)?.database("postgres");
            let pool = PgPool::connect_with(server).await?;
            let existing: Option<String> =
                sqlx::query_scalar("SELECT datname FROM pg_database WHERE datname = $1")
                    .bind(&name)
                    .fetch_optional(&pool)
                    .await?;
            if existing.is_some() {
                println!("database {name} already exists");
                return Ok(());
            }
            // A database name cannot be bound as a parameter, and the proof passes a name
            // it built from `DATABASE_URL`; the quotes below are what makes that safe even
            // if someone puts a strange character in it.
            let quoted = name.replace('"', "\"\"");
            sqlx::query(&format!("CREATE DATABASE \"{quoted}\""))
                .execute(&pool)
                .await?;
            println!("created database {name}");
        }
        "sql" => {
            let statement: Vec<String> = args.collect();
            if statement.is_empty() {
                return Err("proofdb sql needs a statement".into());
            }
            let pool = PgPool::connect(&url).await?;
            sqlx::raw_sql(&statement.join(" ")).execute(&pool).await?;
            println!("ran {} statement(s)", statement.len());
        }
        other => {
            return Err(format!("unknown command {other:?}: use create or sql").into());
        }
    }
    Ok(())
}

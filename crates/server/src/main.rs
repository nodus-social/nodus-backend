#![allow(clippy::doc_markdown)]

//! The monolith runtime.
//!
//! One listener serves the ActivityPub documents, the Mastodon-compatible API and the
//! auth pages. Splitting a service out is a deployment change; this binary is the
//! default composition.

mod scanning;

use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;

use axum::Router;
use nodus_auth::store::PgAuthStore;
use nodus_server_api::{AppState, InstanceConfig};
use nodus_server_store::{media, Store};
use nodus_server_telemetry::{Agent, Node, TelemetryLayer};

const DEFAULT_BIND: &str = "0.0.0.0:3000";
const DEFAULT_DATABASE_URL: &str = "postgres://nodus:nodus@localhost/nodus";
const DEFAULT_ROLES: &str = "api,feed,scan,prune";

/// What this process does, chosen at start so one binary can run as a monolith or as
/// several narrower processes over the same database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The public listener: client API, OAuth pages, ActivityPub documents.
    Api,
    /// The recommendation surface: feeds, browse, events, sharing, sync.
    Feed,
    /// The scan sweep: claims queued scans, calls scanner services, applies policy.
    Scan,
    /// The hourly media prune.
    Prune,
}

impl Role {
    fn all() -> [Self; 4] {
        [Self::Api, Self::Feed, Self::Scan, Self::Prune]
    }

    fn name(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Feed => "feed",
            Self::Scan => "scan",
            Self::Prune => "prune",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "api" => Some(Self::Api),
            "feed" => Some(Self::Feed),
            "scan" => Some(Self::Scan),
            "prune" => Some(Self::Prune),
            _ => None,
        }
    }
}

/// The roles this process runs, from `--roles=api,scan` or `NODUS_ROLES`.
///
/// An empty value means every role: a deployment that says nothing keeps the monolith.
#[derive(Debug, Clone)]
struct Roles(Vec<Role>);

impl Roles {
    fn from_args() -> Result<Self, Box<dyn Error>> {
        for argument in env::args() {
            if let Some(value) = argument.strip_prefix("--roles=") {
                return Self::parse(value);
            }
        }
        Self::parse(&env::var("NODUS_ROLES").unwrap_or_else(|_| DEFAULT_ROLES.to_owned()))
    }

    fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        let mut roles = Vec::new();
        for name in value.split(',').filter(|name| !name.trim().is_empty()) {
            let role = Role::parse(name).ok_or_else(|| {
                format!(
                    "unknown role \"{name}\"; expected one of {}",
                    Role::all()
                        .iter()
                        .map(|role| role.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
            if !roles.contains(&role) {
                roles.push(role);
            }
        }
        if roles.is_empty() {
            return Err("no roles selected".into());
        }
        Ok(Self(roles))
    }

    fn has(&self, role: Role) -> bool {
        self.0.contains(&role)
    }

    fn names(&self) -> String {
        self.0
            .iter()
            .map(|role| role.name())
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Debug, Clone)]
struct Config {
    bind: nodus_server_transport::Address,
    database_url: String,
    database_connections: u32,
    instance: InstanceConfig,
    secure_cookies: bool,
    /// Whether `/auth/register` accepts new accounts. Off unless the operator opts in.
    registrations_open: bool,
    migrate_only: bool,
    roles: Roles,
    bootstrap: Option<Bootstrap>,
    /// Where this process answers questions about itself, if anywhere.
    telemetry: Option<nodus_server_transport::Address>,
}

#[derive(Debug, Clone)]
struct Bootstrap {
    email: String,
    username: String,
    password: String,
}

impl Config {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        let domain = env::var("NODUS_DOMAIN").unwrap_or_else(|_| "localhost".to_owned());
        let base_url = env::var("NODUS_BASE_URL")
            .unwrap_or_else(|_| format!("https://{domain}"))
            .trim_end_matches('/')
            .to_owned();
        let bind = nodus_server_transport::parse(
            &env::var("NODUS_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_owned()),
        )?;
        let database_connections = env::var("NODUS_DATABASE_CONNECTIONS")
            .ok()
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(10);
        let secure_cookies =
            env::var("NODUS_AUTH_SECURE_COOKIES").map_or(Ok(true), |value| value.parse())?;
        let registrations_open =
            env::var("NODUS_REGISTRATIONS_OPEN").map_or(Ok(false), |value| value.parse())?;
        let bootstrap = match (
            env::var("NODUS_BOOTSTRAP_EMAIL"),
            env::var("NODUS_BOOTSTRAP_USERNAME"),
            env::var("NODUS_BOOTSTRAP_PASSWORD"),
        ) {
            (Ok(email), Ok(username), Ok(password)) => Some(Bootstrap {
                email,
                username,
                password,
            }),
            (Err(_), Err(_), Err(_)) => None,
            _ => {
                return Err("NODUS_BOOTSTRAP_EMAIL, NODUS_BOOTSTRAP_USERNAME and \
                     NODUS_BOOTSTRAP_PASSWORD must be set together"
                    .into())
            }
        };

        let telemetry = match (
            env::var("NODUS_TELEMETRY_SOCKET").ok(),
            env::var("NODUS_TELEMETRY_BIND").ok(),
        ) {
            (Some(path), None) => Some(nodus_server_transport::parse(&path)?),
            (None, Some(address)) => Some(nodus_server_transport::parse(&address)?),
            (None, None) => None,
            (Some(_), Some(_)) => {
                return Err("set NODUS_TELEMETRY_SOCKET or NODUS_TELEMETRY_BIND, not both".into())
            }
        };

        Ok(Self {
            bind,
            database_url: env::var("NODUS_DATABASE_URL")
                .unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_owned()),
            database_connections,
            instance: InstanceConfig {
                domain,
                base_url,
                title: env::var("NODUS_TITLE").unwrap_or_else(|_| "Nodus".to_owned()),
                description: env::var("NODUS_DESCRIPTION").unwrap_or_default(),
                contact_email: env::var("NODUS_CONTACT_EMAIL").ok(),
                api_version: "4.3.0".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                registrations_open,
            },
            secure_cookies,
            registrations_open,
            migrate_only: env::args().any(|argument| argument == "--migrate-only"),
            roles: Roles::from_args()?,
            bootstrap,
            telemetry,
        })
    }
}

fn app(store: &Store, config: &Config, feed: Router) -> Router {
    let api = nodus_server_api::root_router(AppState::new(store.clone(), config.instance.clone()));
    let auth = nodus_auth::router(nodus_auth::AppState::new(
        PgAuthStore::new(store.pool().clone()),
        nodus_auth::Config {
            domain: config.instance.domain.clone(),
            issuer: config.instance.base_url.clone(),
            secure_cookies: config.secure_cookies,
            registrations_open: config.registrations_open,
        },
    ));
    api.merge(auth).merge(feed)
}

/// The recommendation engine, mounted in this process.
///
/// It is the same router the standalone service serves; the difference is that this
/// process already owns a pool, a listener and the health probes, so a monolith needs
/// no second deployable and no address to discover. An empty router when the role is
/// off keeps `app` a single shape for every role combination.
async fn feed(config: &Config) -> Router {
    if !config.roles.has(Role::Feed) {
        return Router::new();
    }
    match nodus_feeds::mount(
        &config.database_url,
        &config.instance.base_url,
        config.database_connections,
    )
    .await
    {
        Ok(router) => router,
        Err(error) => {
            tracing::error!(
                %error,
                "the recommendation engine could not start, so its routes stay closed"
            );
            Router::new()
        }
    }
}

async fn provision_bootstrap(store: &Store, bootstrap: &Bootstrap) -> Result<(), Box<dyn Error>> {
    use nodus_server_store::accounts;

    let mut tx = store.pool().begin().await?;

    let account = match accounts::local_by_username(&mut *tx, &bootstrap.username).await? {
        Some(account) => account,
        None => {
            accounts::insert(
                &mut *tx,
                &accounts::NewAccount {
                    username: &bootstrap.username,
                    display_name: &bootstrap.username,
                    note: "",
                    bot: false,
                    locked: false,
                },
            )
            .await?
        }
    };

    if PgAuthStore::has_credential_for_account_with(&mut *tx, &account.id).await? {
        accounts::set_admin(&mut *tx, &account.id, true).await?;
        tx.commit().await?;
        tracing::info!(username = %account.username, "bootstrap user already has a login");
        return Ok(());
    }

    if PgAuthStore::has_credential_with(&mut *tx, &bootstrap.email).await? {
        return Err(std::io::Error::other(format!(
            "bootstrap email {} is already bound to another account",
            bootstrap.email
        ))
        .into());
    }

    accounts::set_admin(&mut *tx, &account.id, true).await?;
    let password_hash = nodus_auth::hash_password(&bootstrap.password)
        .map_err(|error| std::io::Error::other(format!("password hash failed: {error}")))?;
    PgAuthStore::create_credential_with(&mut *tx, &account.id, &bootstrap.email, &password_hash)
        .await?;
    tx.commit().await?;
    tracing::info!(username = %account.username, "bootstrap user created as administrator");
    Ok(())
}

fn media_dir() -> PathBuf {
    std::env::var_os("NODUS_MEDIA_DIR").map_or_else(|| PathBuf::from("./media"), PathBuf::from)
}

fn variants_dir() -> PathBuf {
    std::env::var_os("NODUS_MEDIA_VARIANTS_DIR")
        .map_or_else(|| media_dir().join("variants"), PathBuf::from)
}

async fn remove_unreferenced_variants(
    pool: &sqlx::PgPool,
    variants_root: &std::path::Path,
    digests: Vec<String>,
) {
    for digest in digests {
        if !media::variant_digest_referenced(pool, &digest)
            .await
            .unwrap_or(true)
        {
            let _ = tokio::fs::remove_file(variants_root.join(&digest)).await;
        }
    }
}

async fn remove_unreferenced_originals(
    pool: &sqlx::PgPool,
    media_root: &std::path::Path,
    digests: Vec<String>,
) {
    for digest in digests {
        if !media::original_digest_referenced(pool, &digest)
            .await
            .unwrap_or(true)
        {
            let _ = tokio::fs::remove_file(media_root.join(&digest)).await;
        }
    }
}

async fn prune_media(store: &Store) {
    prune_media_in(store, &media_dir(), &variants_dir()).await;
}

async fn prune_media_in(
    store: &Store,
    media_root: &std::path::Path,
    variants_root: &std::path::Path,
) {
    let pool = store.pool();
    match media::delete_expired_variants(pool).await {
        Ok(digests) => remove_unreferenced_variants(pool, variants_root, digests).await,
        Err(error) => tracing::warn!(%error, "could not prune media variants"),
    }
    match media::expired_originals(pool).await {
        Ok(digests) => remove_unreferenced_originals(pool, media_root, digests).await,
        Err(error) => tracing::warn!(%error, "could not prune media originals"),
    }
    match media::delete_expired_unattached(pool).await {
        Ok(pruned) => {
            remove_unreferenced_variants(pool, variants_root, pruned.variant_digests).await;
            remove_unreferenced_originals(pool, media_root, pruned.original_digests).await;
        }
        Err(error) => tracing::warn!(%error, "could not prune unattached media"),
    }

    let auth = PgAuthStore::new(pool.clone());
    if let Err(error) = auth.delete_expired_sessions().await {
        tracing::warn!(%error, "could not prune expired auth sessions");
    }
    if let Err(error) = auth.delete_expired_codes().await {
        tracing::warn!(%error, "could not prune expired oauth codes");
    }
    if let Err(error) = nodus_server_store::miauth::delete_expired(pool).await {
        tracing::warn!(%error, "could not prune expired miauth sessions");
    }
}

async fn shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
    tracing::info!("shutting down");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let agent = Agent::new(Node {
        name: env::var("NODUS_NODE_NAME").unwrap_or_else(|_| "api".to_owned()),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    });
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(TelemetryLayer::new(agent.ring(), agent.live()))
        .init();

    let config = Config::from_env()?;
    if let Some(address) = config.telemetry.clone() {
        let serving = std::sync::Arc::clone(&agent);
        tokio::spawn(async move {
            tracing::info!(listen = %address, "telemetry listening");
            let stopped =
                nodus_server_telemetry::serve(serving, &address, std::future::pending()).await;
            if let Err(error) = stopped {
                tracing::error!(%error, "the telemetry service stopped");
            }
        });
    }
    let store = Store::connect(&config.database_url, config.database_connections).await?;

    if config.migrate_only {
        store.migrate().await?;
        if config.roles.has(Role::Feed) {
            nodus_feeds::prepare(&config.database_url, config.database_connections).await?;
        }
        tracing::info!("migrations applied");
        return Ok(());
    }

    store.migrate().await?;
    let feed = feed(&config).await;
    if let Some(bootstrap) = &config.bootstrap {
        provision_bootstrap(&store, bootstrap).await?;
    }
    tracing::info!(roles = %config.roles.names(), "nodus server starting");
    if config.roles.has(Role::Scan) {
        scanning::spawn(store.clone(), config.instance.base_url.clone());
    }
    if config.roles.has(Role::Prune) {
        let store = store.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(3600));
            loop {
                ticker.tick().await;
                prune_media(&store).await;
            }
        });
    }
    if !config.roles.has(Role::Api) {
        tracing::info!(roles = %config.roles.names(), "no listener in this process");
        shutdown().await;
        return Ok(());
    }
    // Queued posts publish and outbound activities leave from the process that also
    // serves requests: one pool, one set of signing keys, and no second deployable to
    // keep in step with this one.
    {
        let state = nodus_server_api::AppState::new(store.clone(), config.instance.clone());
        tokio::spawn(nodus_server_api::schedules::run(state.clone()));
        tokio::spawn(nodus_server_api::outbox::run(state));
    }
    tracing::info!(
        address = %config.bind,
        domain = %config.instance.domain,
        "nodus server listening"
    );
    nodus_server_transport::serve_http(&config.bind, app(&store, &config, feed), shutdown()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;

    fn config() -> Config {
        Config {
            bind: nodus_server_transport::parse("127.0.0.1:0").expect("bind"),
            database_url: "postgres://nodus:nodus@127.0.0.1:1/nodus".to_owned(),
            database_connections: 1,
            instance: InstanceConfig {
                domain: "social.test".to_owned(),
                base_url: "https://social.test".to_owned(),
                title: "Nodus test".to_owned(),
                description: String::new(),
                contact_email: None,
                api_version: "4.3.0".to_owned(),
                version: "0.1.0".to_owned(),
                registrations_open: false,
            },
            secure_cookies: true,
            registrations_open: false,
            migrate_only: false,
            roles: Roles::parse(DEFAULT_ROLES).expect("default roles"),
            telemetry: None,
            bootstrap: None,
        }
    }

    /// The mount as the process builds it, without a database to reach: these tests are
    /// about which router answers which path, not about what the engine stores.
    fn feeds(store: &Store, config: &Config) -> Router {
        nodus_feeds::core_router(nodus_feeds::in_process(
            store.pool().clone(),
            &config.instance.base_url,
            1,
        ))
    }

    #[tokio::test]
    async fn the_monolith_router_serves_health_and_auth_metadata() {
        let store = Store::connect_lazy(&config().database_url, 1);
        let config = config();
        let app = app(&store, &config, feeds(&store, &config));

        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(health.status(), StatusCode::OK);

        let metadata = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-authorization-server")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(metadata.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn the_monolith_router_answers_the_feeds_surface() {
        let store = Store::connect_lazy(&config().database_url, 1);
        let config = config();
        let app = app(&store, &config, feeds(&store, &config));

        // Without a database the handler can only fail, and that is the point: a 404
        // would mean the router was never mounted, while any other status proves the
        // request reached the recommendation engine.
        let meta = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/meta")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_ne!(meta.status(), StatusCode::NOT_FOUND);

        let feed = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/feed/accounts?limit=1")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_ne!(feed.status(), StatusCode::NOT_FOUND);
    }

    async fn connect_isolated_store() -> Option<(Store, Store, String)> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let admin = Store::connect(&url, 1).await.expect("connect to postgres");
        let schema = format!("pgtest_{}", nodus_server_core::Id::new());
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(admin.pool())
            .await
            .expect("create isolated test schema");

        let sep = if url.contains('?') { '&' } else { '?' };
        let schema_url = format!("{url}{sep}options=-csearch_path%3D{schema}%2Cpublic");
        let store = Store::connect(&schema_url, 5)
            .await
            .expect("connect isolated store");
        store.migrate().await.expect("run migrations");
        Some((admin, store, schema))
    }

    async fn run_db_test<F, Fut>(body: F)
    where
        F: FnOnce(Store) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let Some((admin, store, schema)) = connect_isolated_store().await else {
            return;
        };
        let handle = tokio::spawn(async move { body(store).await });
        let outcome = handle.await;

        let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .execute(admin.pool())
            .await;

        if let Err(err) = outcome {
            std::panic::resume_unwind(err.into_panic());
        }
    }

    async fn insert_media_with_preview(
        pool: &sqlx::PgPool,
        account_id: &str,
        status_id: Option<&str>,
        orig_digest: &str,
        var_digest: &str,
        lossless: bool,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> String {
        use nodus_server_core::Id;
        use nodus_server_store::media::{MediaRow, VariantRow};

        let media_id = Id::new().to_string();
        media::insert(
            pool,
            &MediaRow {
                id: media_id.clone(),
                account_id: account_id.to_owned(),
                status_id: status_id.map(str::to_owned),
                digest: orig_digest.to_owned(),
                content_type: "image/png".to_owned(),
                size: 10,
                width: Some(10),
                height: Some(10),
                blurhash: None,
                description: String::new(),
                sensitive: false,
                lossless,
                processing_state: "ready".to_owned(),
                processing_progress: 100,
                processing_error: None,
                original_pruned: false,
                created_at,
            },
        )
        .await
        .expect("insert media");
        media::replace_variants(
            pool,
            &media_id,
            &[VariantRow {
                media_id: media_id.clone(),
                layer: "preview".to_owned(),
                max_edge: 400,
                object_key: format!("media/{media_id}/preview"),
                content_type: "image/webp".to_owned(),
                digest: var_digest.to_owned(),
                size: 10,
                width: None,
                height: None,
                expires_at: None,
                created_at,
            }],
        )
        .await
        .expect("insert variant");
        media_id
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn prune_media_deletes_expired_unattached_uploads_and_preserves_shared_blobs() {
        run_db_test(|store| async move {
            use chrono::{Duration, Utc};
            use nodus_server_core::Id;
            use nodus_server_store::accounts::{self, NewAccount};
            use nodus_server_store::statuses;

            let pool = store.pool();
            let dir = std::env::temp_dir().join(format!("nodus-server-prune-test-{}", Id::new()));
            let variants_root = dir.join("variants");
            tokio::fs::create_dir_all(&variants_root)
                .await
                .expect("create media dirs");

            let account = accounts::insert(
                pool,
                &NewAccount {
                    username: &format!("pruner_{}", Id::new()),
                    display_name: "Pruner",
                    note: "",
                    bot: false,
                    locked: false,
                },
            )
            .await
            .expect("insert account");

            let status_id = Id::new().to_string();
            let status = statuses::create(
                pool,
                &statuses::NewStatus {
                    id: &status_id,
                    account_id: &account.id,
                    content: "attached status",
                    content_html: "<p>attached status</p>",
                    content_source: None,
                    content_format: "html",
                    spoiler_text: "",
                    visibility: "public",
                    sensitive: false,
                    in_reply_to_id: None,
                    in_reply_to_account_id: None,
                    reblog_of_id: None,
                    language: None,
                },
                &[],
                &[],
                &[],
            )
            .await
            .expect("create status");

            let now = Utc::now();
            let old = now - Duration::hours(25);
            let recent = now - Duration::hours(1);

            let old_orig_digest = format!("orig-old-{}", Id::new());
            let old_var_digest = format!("var-old-{}", Id::new());
            tokio::fs::write(dir.join(&old_orig_digest), b"old-orig")
                .await
                .unwrap();
            tokio::fs::write(variants_root.join(&old_var_digest), b"old-var")
                .await
                .unwrap();
            let old_unattached_id = insert_media_with_preview(
                pool,
                &account.id,
                None,
                &old_orig_digest,
                &old_var_digest,
                false,
                old,
            )
            .await;

            let recent_orig_digest = format!("orig-recent-{}", Id::new());
            let recent_var_digest = format!("var-recent-{}", Id::new());
            tokio::fs::write(dir.join(&recent_orig_digest), b"recent-orig")
                .await
                .unwrap();
            tokio::fs::write(variants_root.join(&recent_var_digest), b"recent-var")
                .await
                .unwrap();
            let recent_unattached_id = insert_media_with_preview(
                pool,
                &account.id,
                None,
                &recent_orig_digest,
                &recent_var_digest,
                false,
                recent,
            )
            .await;

            let shared_orig_digest = format!("orig-shared-{}", Id::new());
            let shared_var_digest = format!("var-shared-{}", Id::new());
            tokio::fs::write(dir.join(&shared_orig_digest), b"shared-orig")
                .await
                .unwrap();
            tokio::fs::write(variants_root.join(&shared_var_digest), b"shared-var")
                .await
                .unwrap();
            let attached_id = insert_media_with_preview(
                pool,
                &account.id,
                Some(&status.id),
                &shared_orig_digest,
                &shared_var_digest,
                true,
                old,
            )
            .await;
            let old_shared_unattached_id = insert_media_with_preview(
                pool,
                &account.id,
                None,
                &shared_orig_digest,
                &shared_var_digest,
                false,
                old,
            )
            .await;

            prune_media_in(&store, &dir, &variants_root).await;

            assert!(media::by_id(pool, &old_unattached_id)
                .await
                .unwrap()
                .is_none());
            assert!(media::variants(pool, &old_unattached_id)
                .await
                .unwrap()
                .is_empty());
            assert!(!dir.join(&old_orig_digest).exists());
            assert!(!variants_root.join(&old_var_digest).exists());

            assert!(media::by_id(pool, &recent_unattached_id)
                .await
                .unwrap()
                .is_some());
            assert_eq!(
                media::variants(pool, &recent_unattached_id)
                    .await
                    .unwrap()
                    .len(),
                1
            );
            assert!(dir.join(&recent_orig_digest).exists());
            assert!(variants_root.join(&recent_var_digest).exists());

            assert!(media::by_id(pool, &old_shared_unattached_id)
                .await
                .unwrap()
                .is_none());
            assert!(media::by_id(pool, &attached_id).await.unwrap().is_some());
            assert!(dir.join(&shared_orig_digest).exists());
            assert!(variants_root.join(&shared_var_digest).exists());

            let _ = tokio::fs::remove_dir_all(&dir).await;
        })
        .await;
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn prune_media_deletes_expired_sessions_and_codes() {
        run_db_test(|store| async move {
            use chrono::{Duration, Utc};
            use nodus_auth::store::{AuthStore as _, PgAuthStore};
            use nodus_server_core::Id;
            use nodus_server_store::accounts::{self, NewAccount};
            use nodus_server_store::{apps, miauth};

            let pool = store.pool();
            let dir = std::env::temp_dir().join(format!("nodus-server-prune-auth-{}", Id::new()));
            let variants_root = dir.join("variants");
            tokio::fs::create_dir_all(&variants_root).await.unwrap();

            let account = accounts::insert(
                pool,
                &NewAccount {
                    username: &format!("sess_pruner_{}", Id::new()),
                    display_name: "Session Pruner",
                    note: "",
                    bot: false,
                    locked: false,
                },
            )
            .await
            .expect("insert account");

            let now = Utc::now();
            let auth = PgAuthStore::new(pool.clone());
            let expired_sess_hash = format!("expired-sess-{}", Id::new());
            let active_sess_hash = format!("active-sess-{}", Id::new());
            auth.create_session(&expired_sess_hash, &account.id, now - Duration::hours(1))
                .await
                .unwrap();
            auth.create_session(&active_sess_hash, &account.id, now + Duration::hours(1))
                .await
                .unwrap();

            let app_id = Id::new().to_string();
            apps::register(
                pool,
                &app_id,
                &format!("cid-{app_id}"),
                "secret",
                "TestApp",
                None,
                &["urn:ietf:wg:oauth:2.0:oob".to_owned()],
                &["read".to_owned()],
            )
            .await
            .unwrap();

            let expired_code_hash = format!("expired-code-{}", Id::new());
            let active_code_hash = format!("active-code-{}", Id::new());
            auth.create_code(
                &expired_code_hash,
                &app_id,
                &account.id,
                "urn:ietf:wg:oauth:2.0:oob",
                &["read".to_owned()],
                "challenge",
                now - Duration::hours(1),
            )
            .await
            .unwrap();
            auth.create_code(
                &active_code_hash,
                &app_id,
                &account.id,
                "urn:ietf:wg:oauth:2.0:oob",
                &["read".to_owned()],
                "challenge",
                now + Duration::hours(1),
            )
            .await
            .unwrap();

            let expired_miauth_id = Id::new().to_string();
            let active_miauth_id = Id::new().to_string();
            assert!(miauth::create_session(
                pool,
                &expired_miauth_id,
                "ExpiredApp",
                None,
                &["read".to_owned()]
            )
            .await
            .unwrap());
            sqlx::query("UPDATE miauth_session SET expires_at = $2 WHERE id = $1")
                .bind(&expired_miauth_id)
                .bind(now - Duration::hours(1))
                .execute(pool)
                .await
                .unwrap();
            assert!(miauth::create_session(
                pool,
                &active_miauth_id,
                "ActiveApp",
                None,
                &["read".to_owned()]
            )
            .await
            .unwrap());

            prune_media_in(&store, &dir, &variants_root).await;

            let expired_sess_count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM auth_session WHERE token_hash = $1")
                    .bind(&expired_sess_hash)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            let active_sess_count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM auth_session WHERE token_hash = $1")
                    .bind(&active_sess_hash)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert_eq!(expired_sess_count, 0);
            assert_eq!(active_sess_count, 1);

            let expired_code_count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM oauth_code WHERE code_hash = $1")
                    .bind(&expired_code_hash)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            let active_code_count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM oauth_code WHERE code_hash = $1")
                    .bind(&active_code_hash)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert_eq!(expired_code_count, 0);
            assert_eq!(active_code_count, 1);

            let expired_miauth_count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM miauth_session WHERE id = $1")
                    .bind(&expired_miauth_id)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            let active_miauth_count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM miauth_session WHERE id = $1")
                    .bind(&active_miauth_id)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert_eq!(expired_miauth_count, 0);
            assert_eq!(active_miauth_count, 1);

            let _ = tokio::fs::remove_dir_all(&dir).await;
        })
        .await;
    }

    #[tokio::test]
    async fn provision_bootstrap_is_transactional_when_email_belongs_to_another_account() {
        run_db_test(|store| async move {
            use nodus_server_store::accounts::{self, NewAccount};

            let pool = store.pool();
            let owner = accounts::insert(
                pool,
                &NewAccount {
                    username: "email_owner",
                    display_name: "Owner",
                    note: "",
                    bot: false,
                    locked: false,
                },
            )
            .await
            .expect("insert owner");
            let auth = PgAuthStore::new(pool.clone());
            auth.create_credential(&owner.id, "taken@social.test", "hash")
                .await
                .expect("create owner credential");

            // Existing non-admin user without credentials must NOT be promoted on failure.
            let target = accounts::insert(
                pool,
                &NewAccount {
                    username: "target_user",
                    display_name: "Target",
                    note: "",
                    bot: false,
                    locked: false,
                },
            )
            .await
            .expect("insert target");
            assert!(!target.admin);

            let is_err = provision_bootstrap(
                &store,
                &Bootstrap {
                    email: "taken@social.test".to_owned(),
                    username: "target_user".to_owned(),
                    password: "bootstrap-password-123".to_owned(),
                },
            )
            .await
            .is_err();
            assert!(is_err, "duplicate email bootstrap must fail");

            let refreshed_target = accounts::local_by_username(pool, "target_user")
                .await
                .unwrap()
                .expect("target still exists");
            assert!(
                !refreshed_target.admin,
                "failed bootstrap must not leave existing account promoted to admin"
            );

            // Non-existent user with conflicting email must NOT leave an orphaned admin account.
            let is_err = provision_bootstrap(
                &store,
                &Bootstrap {
                    email: "taken@social.test".to_owned(),
                    username: "ghost_admin".to_owned(),
                    password: "bootstrap-password-123".to_owned(),
                },
            )
            .await
            .is_err();
            assert!(is_err, "duplicate email bootstrap must fail");
            assert!(
                accounts::local_by_username(pool, "ghost_admin")
                    .await
                    .unwrap()
                    .is_none(),
                "failed bootstrap must roll back newly inserted account"
            );

            // Valid bootstrap succeeds atomically and is idempotent on restart.
            let bootstrap = Bootstrap {
                email: "fresh@social.test".to_owned(),
                username: "fresh_admin".to_owned(),
                password: "bootstrap-password-123".to_owned(),
            };
            provision_bootstrap(&store, &bootstrap)
                .await
                .expect("valid bootstrap should succeed");
            let created = accounts::local_by_username(pool, "fresh_admin")
                .await
                .unwrap()
                .expect("admin created");
            assert!(created.admin);
            assert!(auth.has_credential_for_account(&created.id).await.unwrap());

            provision_bootstrap(&store, &bootstrap)
                .await
                .expect("repeated bootstrap should be idempotent");
        })
        .await;
    }

    #[test]
    fn default_roles_run_every_loop() {
        let roles = Roles::parse(DEFAULT_ROLES).expect("default roles parse");
        for role in Role::all() {
            assert!(roles.has(role), "{} must run by default", role.name());
        }
        assert_eq!(roles.names(), "api,feed,scan,prune");
    }

    #[test]
    fn a_narrow_role_list_runs_only_what_it_names() {
        let roles = Roles::parse("scan").expect("scan parses");
        assert!(roles.has(Role::Scan));
        assert!(!roles.has(Role::Api));
        assert!(!roles.has(Role::Prune));
    }

    #[test]
    fn roles_are_deduplicated_and_trimmed() {
        let roles = Roles::parse(" api , api,scan ").expect("padded roles parse");
        assert_eq!(roles.names(), "api,scan");
    }

    #[test]
    fn an_unknown_or_empty_role_list_is_refused() {
        assert!(Roles::parse("api,frontend").is_err());
        assert!(Roles::parse("").is_err());
        assert!(Roles::parse(" , ").is_err());
    }
}

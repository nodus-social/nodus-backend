use std::sync::Once;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::limits::{IMAGE_SIZE_LIMIT, VIDEO_SIZE_LIMIT};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::{apps, Store};

static MEDIA_ENV_INIT: Once = Once::new();

fn init_test_media_dirs() {
    MEDIA_ENV_INIT.call_once(|| {
        let base = std::env::temp_dir().join(format!("nodus-api-issue21-{}", Id::new()));
        let variants = base.join("variants");
        std::fs::create_dir_all(&variants).expect("create temp media dirs");
        std::env::set_var("NODUS_MEDIA_DIR", &base);
        std::env::set_var("NODUS_MEDIA_VARIANTS_DIR", &variants);
    });
}

fn instance_config() -> InstanceConfig {
    InstanceConfig {
        domain: "social.test".to_owned(),
        base_url: "https://social.test".to_owned(),
        title: "Nodus test".to_owned(),
        description: "A test instance".to_owned(),
        contact_email: None,
        api_version: "4.3.0".to_owned(),
        version: "0.1.0".to_owned(),
    }
}

async fn connect_isolated_store() -> Option<(Store, Store, String)> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let admin = Store::connect(&url, 1).await.expect("connect to postgres");
    let schema = format!("pgtest_{}", Id::new());
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
    F: FnOnce(Store, AppState) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some((admin, store, schema)) = connect_isolated_store().await else {
        return;
    };
    let state = AppState::new(store.clone(), instance_config());
    let handle = tokio::spawn(async move { body(store, state).await });
    let outcome = handle.await;

    let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(admin.pool())
        .await;

    if let Err(err) = outcome {
        std::panic::resume_unwind(err.into_panic());
    }
}

async fn create_account(pool: &PgPool, label: &str) -> String {
    let username = format!("pgtest_{label}_{}", Id::new());
    accounts::insert(
        pool,
        &NewAccount {
            username: &username,
            display_name: &username,
            note: "",
            bot: false,
            locked: false,
        },
    )
    .await
    .expect("insert account")
    .id
}

async fn create_token(pool: &PgPool, account_id: &str) -> String {
    let app_id = Id::new().to_string();
    let client_id = format!("pgtest-client-{app_id}");
    apps::register(
        pool,
        &app_id,
        &client_id,
        "unused",
        "pgtest",
        None,
        &["urn:ietf:wg:oauth:2.0:oob".to_owned()],
        &["read".to_owned(), "write".to_owned()],
    )
    .await
    .expect("register app");

    let token = format!("pgtest-token-{}", Id::new());
    let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
    sqlx::query(
        "INSERT INTO oauth_token (id, app_id, account_id, token_hash, scopes) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Id::new().to_string())
    .bind(&app_id)
    .bind(account_id)
    .bind(&digest)
    .bind(&["read".to_owned(), "write".to_owned()][..])
    .execute(pool)
    .await
    .expect("insert oauth token");

    token
}

fn multipart_upload_request(
    uri: &str,
    token: &str,
    filename: &str,
    content_type: &str,
    payload: &[u8],
) -> Request<Body> {
    let boundary = "----nodus-issue-21-boundary";
    let mut body = Vec::with_capacity(payload.len() + 256);
    body.extend_from_slice(
        format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n\
             Content-Type: {content_type}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(payload);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("multipart request")
}

#[tokio::test]
async fn media_upload_enforces_image_size_limit_but_allows_larger_videos() {
    init_test_media_dirs();

    run_db_test(|store, state| async move {
        let account_id = create_account(store.pool(), "media_limit").await;
        let token = create_token(store.pool(), &account_id).await;
        let app = root_router(state);

        let over_image_limit = usize::try_from(IMAGE_SIZE_LIMIT).expect("fits usize") + 1;
        assert!(u64::try_from(over_image_limit).unwrap() < VIDEO_SIZE_LIMIT);

        // Still image exceeding 10 MiB must be rejected with 413 Payload Too Large.
        let big_png = vec![0x89_u8; over_image_limit];
        let resp = app
            .clone()
            .oneshot(multipart_upload_request(
                "/api/v1/media",
                &token,
                "huge.png",
                "image/png",
                &big_png,
            ))
            .await
            .expect("image upload response");
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "still images over IMAGE_SIZE_LIMIT must return 413"
        );

        // Animated image (GIF) exceeding 10 MiB must also be rejected with 413.
        let resp = app
            .clone()
            .oneshot(multipart_upload_request(
                "/api/v2/media",
                &token,
                "huge.gif",
                "image/gif",
                &big_png,
            ))
            .await
            .expect("gif upload response");
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "animated images over IMAGE_SIZE_LIMIT must return 413"
        );

        // Image right at IMAGE_SIZE_LIMIT (10 MiB) must be accepted.
        let exact_image_limit = usize::try_from(IMAGE_SIZE_LIMIT).expect("fits usize");
        let ok_png = vec![0x89_u8; exact_image_limit];
        let resp = app
            .clone()
            .oneshot(multipart_upload_request(
                "/api/v1/media",
                &token,
                "exact.png",
                "image/png",
                &ok_png,
            ))
            .await
            .expect("exact limit image response");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "images at IMAGE_SIZE_LIMIT must be accepted"
        );

        // Video exceeding 10 MiB but within 40 MiB (VIDEO_SIZE_LIMIT) must be accepted.
        let ok_video = vec![0x00_u8; over_image_limit];
        let resp = app
            .oneshot(multipart_upload_request(
                "/api/v1/media",
                &token,
                "clip.mp4",
                "video/mp4",
                &ok_video,
            ))
            .await
            .expect("video upload response");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "videos between IMAGE_SIZE_LIMIT and VIDEO_SIZE_LIMIT must be accepted"
        );
    })
    .await;
}

//! Integration tests for the self-service registration flow.
//!
//! These drive the real router against a real Postgres, because the parts that can break
//! are the ones a unit test cannot see: the CSRF cookie round trip, the unique indexes
//! behind "that username is taken", and the session cookie issued on the way out. The
//! render tests in the crate cover the markup; these cover the contract with the browser.
//!
//! Each test gets its own schema so they can run in parallel, and the whole file is
//! skipped when `DATABASE_URL` is unset — the same convention as the API tests.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use nodus_auth::store::PgAuthStore;
use nodus_auth::{AppState, Config};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tower::ServiceExt;

fn config(registrations_open: bool) -> Config {
    Config {
        domain: "social.test".to_owned(),
        issuer: "https://social.test".to_owned(),
        secure_cookies: false,
        registrations_open,
    }
}

/// Creates a private schema, migrates it, and returns a pool pointed at it.
async fn isolated_pool() -> Option<(PgPool, String)> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect to postgres");
    // Lower case: `search_path` folds unquoted identifiers, so a Crockford base32
    // name with capitals would silently resolve to nothing and land in `public`.
    let schema = format!("pgtest_auth_{}", ulid::Ulid::new()).to_lowercase();
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&admin)
        .await
        .expect("create isolated test schema");

    let separator = if url.contains('?') { '&' } else { '?' };
    let schema_url = format!("{url}{separator}options=-csearch_path%3D{schema}%2Cpublic");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&schema_url)
        .await
        .expect("connect isolated pool");
    sqlx::migrate!("../store/migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    Some((pool, schema))
}

async fn run_db_test<F, Fut>(body: F)
where
    F: FnOnce(PgPool, axum::Router) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some((pool, schema)) = isolated_pool().await else {
        return;
    };
    let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config(true)));
    let cleanup = pool.clone();
    let handle = tokio::spawn(async move { body(pool, app).await });
    let outcome = handle.await;

    let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(&cleanup)
        .await;

    if let Err(error) = outcome {
        std::panic::resume_unwind(error.into_panic());
    }
}

/// Everything a browser would keep after one response.
#[derive(Default, Clone)]
struct Browser {
    cookies: Vec<(String, String)>,
}

impl Browser {
    fn absorb(&mut self, response: &axum::http::Response<Body>) {
        for value in response.headers().get_all(header::SET_COOKIE) {
            let raw = value.to_str().expect("set-cookie is ascii");
            let pair = raw.split(';').next().unwrap_or_default();
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            self.cookies.retain(|(kept, _)| kept != name);
            self.cookies.push((name.to_owned(), value.to_owned()));
        }
    }

    fn header(&self) -> String {
        self.cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.cookies
            .iter()
            .find(|(kept, _)| kept == name)
            .map(|(_, value)| value.as_str())
    }

    async fn get_page(&mut self, app: &axum::Router, uri: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .uri(uri)
            .header(header::COOKIE, self.header())
            .body(Body::empty())
            .expect("build request");
        let response = app.clone().oneshot(request).await.expect("send request");
        self.absorb(&response);
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("read body")
            .to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    async fn post_form(
        &mut self,
        app: &axum::Router,
        uri: &str,
        body: &str,
    ) -> (StatusCode, Option<String>, String) {
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::COOKIE, self.header())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body.to_owned()))
            .expect("build request");
        let response = app.clone().oneshot(request).await.expect("send request");
        self.absorb(&response);
        let status = response.status();
        let location = response
            .headers()
            .get(header::LOCATION)
            .map(|value| value.to_str().expect("location is ascii").to_owned());
        let body = response
            .into_body()
            .collect()
            .await
            .expect("read body")
            .to_bytes();
        (
            status,
            location,
            String::from_utf8_lossy(&body).into_owned(),
        )
    }
}

/// Pulls the value of a hidden input out of the rendered form.
fn hidden(html: &str, name: &str) -> String {
    let needle = format!("name=\"{name}\"");
    let start = html
        .find(&needle)
        .unwrap_or_else(|| panic!("form has no {name} field: {html}"))
        + needle.len();
    let rest = &html[start..];
    let after_value = rest
        .find("value=")
        .unwrap_or_else(|| panic!("{name} field has no value: {html}"))
        + "value=".len();
    let rest = &rest[after_value..];
    let rest = rest.strip_prefix('"').unwrap_or(rest);
    let end = rest.find(['"', ' ']).unwrap_or(rest.len());
    rest[..end].to_owned()
}

fn form(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(name, value)| {
            format!(
                "{name}={}",
                url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

#[tokio::test]
async fn signing_up_creates_the_account_and_signs_the_reader_in() {
    run_db_test(|pool, app| async move {
        let mut browser = Browser::default();
        let (status, page) = browser.get_page(&app, "/auth/register").await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("Create account"), "{page}");
        let csrf = hidden(&page, "csrf_token");
        assert!(browser.get("nodus_csrf").is_some(), "csrf cookie is set");

        let body = form(&[
            ("csrf_token", &csrf),
            ("username", "Ada_Lovelace"),
            ("email", "Ada@Example.test"),
            ("password", "correct horse battery"),
            ("password_confirmation", "correct horse battery"),
        ]);
        let (status, location, body_text) = browser.post_form(&app, "/auth/register", &body).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body_text}");
        assert_eq!(location.as_deref(), Some("/"));
        let session = browser.get("nodus_auth").expect("session cookie").to_owned();
        assert_ne!(session, "", "the session cookie carries a token");

        // The reader is signed in without typing the password again.
        let (status, session_page) = browser.get_page(&app, "/auth/session").await;
        assert_eq!(status, StatusCode::OK, "{session_page}");
        let json: serde_json::Value = serde_json::from_str(&session_page).expect("session json");
        assert_eq!(json["username"], "ada_lovelace");
        assert_eq!(json["display_name"], "ada_lovelace");
        assert!(json["account_id"].is_string());

        // The row is a normal local account, not an administrator by accident.
        let (local, admin, email): (bool, bool, String) = sqlx::query_as(
            "SELECT account.local, account.admin, credential.email::text \
             FROM account JOIN account_credential AS credential ON credential.account_id = account.id \
             WHERE account.username = $1",
        )
        .bind("ada_lovelace")
        .fetch_one(&pool)
        .await
        .expect("account row");
        assert!(local);
        assert!(!admin);
        // citext keeps the typed case; comparisons are case-insensitive.
        assert_eq!(email.to_ascii_lowercase(), "ada@example.test");

        // The stored password is a hash the login path can verify.
        // Joined by account id on purpose: comparing a `citext` column to a text bind
        // resolves to `text = text`, so a mixed-case address would not match.
        let hash: String = sqlx::query_scalar(
            "SELECT credential.password_hash \
             FROM account JOIN account_credential AS credential ON credential.account_id = account.id \
             WHERE account.username = $1",
        )
        .bind("ada_lovelace")
        .fetch_one(&pool)
        .await
        .expect("credential row");
        assert!(hash.starts_with("$argon2"), "{hash}");
    })
    .await;
}

#[tokio::test]
async fn the_new_account_can_then_sign_in_with_its_password() {
    run_db_test(|_pool, app| async move {
        let mut browser = Browser::default();
        let (_, page) = browser.get_page(&app, "/auth/register").await;
        let csrf = hidden(&page, "csrf_token");
        let body = form(&[
            ("csrf_token", &csrf),
            ("username", "grace"),
            ("email", "grace@example.test"),
            ("password", "hopper-1906"),
            ("password_confirmation", "hopper-1906"),
        ]);
        let (status, _, text) = browser.post_form(&app, "/auth/register", &body).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{text}");

        // A fresh browser with no session: the password must be enough.
        let mut anonymous = Browser::default();
        let (_, page) = anonymous.get_page(&app, "/auth/login").await;
        let csrf = hidden(&page, "csrf_token");
        let body = form(&[
            ("csrf_token", &csrf),
            ("email", "grace@example.test"),
            ("password", "hopper-1906"),
        ]);
        let (status, location, text) = anonymous.post_form(&app, "/auth/login", &body).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{text}");
        assert_eq!(location.as_deref(), Some("/"));

        let (status, session_page) = anonymous.get_page(&app, "/auth/session").await;
        assert_eq!(status, StatusCode::OK, "{session_page}");
        let json: serde_json::Value = serde_json::from_str(&session_page).expect("session json");
        assert_eq!(json["username"], "grace");
    })
    .await;
}

#[tokio::test]
async fn a_taken_username_re_renders_the_form_with_the_reason() {
    run_db_test(|pool, app| async move {
        let mut first = Browser::default();
        let (_, page) = first.get_page(&app, "/auth/register").await;
        let csrf = hidden(&page, "csrf_token");
        let body = form(&[
            ("csrf_token", &csrf),
            ("username", "taken_name"),
            ("email", "first@example.test"),
            ("password", "long-enough-password"),
            ("password_confirmation", "long-enough-password"),
        ]);
        let (status, _, text) = first.post_form(&app, "/auth/register", &body).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{text}");

        let mut second = Browser::default();
        let (_, page) = second.get_page(&app, "/auth/register").await;
        let csrf = hidden(&page, "csrf_token");
        let body = form(&[
            ("csrf_token", &csrf),
            ("username", "TAKEN_NAME"),
            ("email", "second@example.test"),
            ("password", "another-good-password"),
            ("password_confirmation", "another-good-password"),
        ]);
        let (status, location, text) = second.post_form(&app, "/auth/register", &body).await;
        assert_eq!(status, StatusCode::OK, "{text}");
        assert!(location.is_none(), "no redirect on a refused sign-up");
        assert!(text.contains("That username is already taken."), "{text}");
        assert!(second.get("nodus_auth").is_none(), "nobody is signed in");
        // The typed values survive the round trip; the password does not.
        assert!(text.contains("value=\"TAKEN_NAME\""), "{text}");
        assert!(text.contains("value=\"second@example.test\""), "{text}");
        assert!(!text.contains("another-good-password"), "{text}");

        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM account")
            .fetch_one(&pool)
            .await
            .expect("count accounts");
        assert_eq!(count, 1);
    })
    .await;
}

#[tokio::test]
async fn a_taken_email_re_renders_the_form_with_the_reason() {
    run_db_test(|_pool, app| async move {
        let mut first = Browser::default();
        let (_, page) = first.get_page(&app, "/auth/register").await;
        let csrf = hidden(&page, "csrf_token");
        let body = form(&[
            ("csrf_token", &csrf),
            ("username", "first_one"),
            ("email", "shared@example.test"),
            ("password", "long-enough-password"),
            ("password_confirmation", "long-enough-password"),
        ]);
        let (status, _, text) = first.post_form(&app, "/auth/register", &body).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{text}");

        let mut second = Browser::default();
        let (_, page) = second.get_page(&app, "/auth/register").await;
        let csrf = hidden(&page, "csrf_token");
        let body = form(&[
            ("csrf_token", &csrf),
            ("username", "second_one"),
            ("email", "SHARED@example.test"),
            ("password", "another-good-password"),
            ("password_confirmation", "another-good-password"),
        ]);
        let (status, _, text) = second.post_form(&app, "/auth/register", &body).await;
        assert_eq!(status, StatusCode::OK, "{text}");
        assert!(
            text.contains("That email address already has a login."),
            "{text}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_closed_instance_answers_403_and_keeps_the_form_hidden() {
    let Some((pool, schema)) = isolated_pool().await else {
        return;
    };
    let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config(false)));
    let mut browser = Browser::default();

    let (status, page) = browser.get_page(&app, "/auth/register").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Registration is closed"), "{page}");
    assert!(!page.contains("name=\"password\""), "{page}");

    let body = form(&[
        ("csrf_token", "irrelevant"),
        ("username", "sneaky"),
        ("email", "sneaky@example.test"),
        ("password", "long-enough-password"),
        ("password_confirmation", "long-enough-password"),
    ]);
    let (status, _, text) = browser.post_form(&app, "/auth/register", &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(text, "registration is closed on this instance");

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM account")
        .fetch_one(&pool)
        .await
        .expect("count accounts");
    assert_eq!(count, 0);

    let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn a_wrong_csrf_token_is_refused_and_nothing_is_created() {
    run_db_test(|pool, app| async move {
        let mut browser = Browser::default();
        let (_status, _page) = browser.get_page(&app, "/auth/register").await;
        let body = form(&[
            ("csrf_token", "not-the-token"),
            ("username", "csrf_victim"),
            ("email", "victim@example.test"),
            ("password", "long-enough-password"),
            ("password_confirmation", "long-enough-password"),
        ]);
        let (status, _, text) = browser.post_form(&app, "/auth/register", &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
        assert_eq!(text, "invalid CSRF token");

        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM account")
            .fetch_one(&pool)
            .await
            .expect("count accounts");
        assert_eq!(count, 0);
        assert!(browser.get("nodus_auth").is_none());
    })
    .await;
}

#[tokio::test]
async fn validation_failures_are_reported_before_anything_is_stored() {
    run_db_test(|pool, app| async move {
        let mut browser = Browser::default();
        let (_, page) = browser.get_page(&app, "/auth/register").await;
        let csrf = hidden(&page, "csrf_token");

        let cases = [
            (
                "short password",
                "A password is at least 8 characters.",
                [
                    ("username", "valid_name"),
                    ("email", "valid@example.test"),
                    ("password", "short"),
                    ("password_confirmation", "short"),
                ],
            ),
            (
                "mismatched confirmation",
                "The two passwords do not match.",
                [
                    ("username", "valid_name"),
                    ("email", "valid@example.test"),
                    ("password", "long-enough-password"),
                    ("password_confirmation", "long-enough-password2"),
                ],
            ),
            (
                "reserved name",
                "That username is reserved on this instance.",
                [
                    ("username", "admin"),
                    ("email", "valid@example.test"),
                    ("password", "long-enough-password"),
                    ("password_confirmation", "long-enough-password"),
                ],
            ),
            (
                "spaces in the name",
                "Use only letters, numbers and underscores in the username.",
                [
                    ("username", "two words"),
                    ("email", "valid@example.test"),
                    ("password", "long-enough-password"),
                    ("password_confirmation", "long-enough-password"),
                ],
            ),
            (
                "email without a dot",
                "That does not look like an email address.",
                [
                    ("username", "valid_name"),
                    ("email", "valid@example"),
                    ("password", "long-enough-password"),
                    ("password_confirmation", "long-enough-password"),
                ],
            ),
            (
                "name too short",
                "A username is 3 to 30 characters.",
                [
                    ("username", "ab"),
                    ("email", "valid@example.test"),
                    ("password", "long-enough-password"),
                    ("password_confirmation", "long-enough-password"),
                ],
            ),
        ];

        for (label, message, fields) in cases {
            let mut all = vec![("csrf_token", csrf.as_str())];
            all.extend(fields.iter().copied());
            let (status, location, text) =
                browser.post_form(&app, "/auth/register", &form(&all)).await;
            assert_eq!(status, StatusCode::OK, "{label}: {text}");
            assert!(location.is_none(), "{label} redirected");
            assert!(
                text.contains("role=\"alert\"") && text.contains(message),
                "{label} showed the wrong message: {text}"
            );
        }

        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM account")
            .fetch_one(&pool)
            .await
            .expect("count accounts");
        assert_eq!(count, 0);
    })
    .await;
}

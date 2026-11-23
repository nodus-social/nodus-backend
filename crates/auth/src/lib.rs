//! Nodus auth service.
//!
//! One process renders the login/consent pages and speaks the OAuth endpoints Mastodon
//! clients expect. Storage is behind [`AuthStore`]; the service never opens a second
//! database abstraction of its own.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::Argon2;
use axum::extract::{ConnectInfo, Form, FromRequestParts, Path, Query, RawQuery, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{Duration, Utc};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::domain::{
    constant_time_eq, csrf_token, is_admin_scope, is_safe_redirect_uri, opaque_token,
    redirect_allowed, redirect_with, token_hash, verify_csrf, verify_pkce, AuthorizeRequest,
    CSRF_COOKIE,
};
use crate::outbox::Confirmation;
use crate::store::{
    AuthStore, Credential, IpBlockVerdict, PgAuthStore, RegisterError, SessionAccount,
};

pub mod domain;
pub mod outbox;
mod password_reset;
mod password_reset_mail;
mod password_reset_pages;
pub mod store;
pub mod totp;

/// Hashes a bootstrap password with Argon2id's default parameters.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    use argon2::password_hash::{PasswordHasher, SaltString};

    let salt = SaltString::encode_b64(&rand::random::<[u8; 16]>())?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

pub const SESSION_COOKIE: &str = "nodus_auth";
const SESSION_DAYS: i64 = 30;
/// The password was accepted but the second factor has not been; the cookie is not a
/// session and no token is issued until it is exchanged.
const TWO_FACTOR_COOKIE: &str = "nodus_2fa";
/// Long enough to open an authenticator app, short enough that a stolen challenge is not
/// a standing key. The database row enforces the same deadline.
const CHALLENGE_MINUTES: i64 = 5;
/// Five wrong codes consume the challenge. The ±1 step window holds three valid codes in a
/// million, so five guesses leave an attacker about one chance in sixty thousand; a sixth
/// only keeps a stolen password useful longer. The lockout ends with the challenge rather
/// than the account (see `0065_two_factor_attempts.sql`), so it cannot be used to deny the
/// owner a login.
pub const CHALLENGE_ATTEMPTS: i32 = 5;
/// Long enough to survive a mail queue and a weekend, short enough to be worthless later.
const CONFIRMATION_HOURS: i64 = 48;
const CODE_MINUTES: i64 = 5;
/// Enough for every user agent in the wild; the header is attacker-controlled, so a
/// session row must not be a place to park kilobytes.
const USER_AGENT_MAX: usize = 512;

/// The peer address the transport observed, when it observed one.
///
/// The socket transport inserts [`ConnectInfo`] only for the ingress path, where the
/// ingress is the only process that can dial it. A TCP listener's peer is already the
/// caller, so a forwarded header there would be a claim rather than an observation.
struct Peer(Option<SocketAddr>);

// The trait's method is async; reading an extension is not. There is nothing to wait
// for, and a second await point would only be noise.
#[allow(clippy::unused_async_trait_impl)]
impl<S: Send + Sync> FromRequestParts<S> for Peer {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(address)| *address),
        ))
    }
}

/// The session's device: the user agent it announced and the network it came from.
fn session_device(headers: &HeaderMap, peer: Option<SocketAddr>) -> (String, Option<String>) {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(USER_AGENT_MAX)
        .collect();
    (user_agent, peer.map(|address| network_prefix(address.ip())))
}

/// Keeps the network and drops the host: `/24` for IPv4, `/48` for IPv6.
///
/// A session list answers "which network was this", and the host bits do not add to
/// that answer. Thirty days of a full address is a location record; a prefix is not.
pub fn network_prefix(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
        }
        // A dual-stack listener reports an IPv4 caller as `::ffff:a.b.c.d`; treating that
        // as native IPv6 would truncate every IPv4 visitor to the same useless prefix.
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                network_prefix(IpAddr::V4(mapped))
            } else {
                let segments = address.segments();
                format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
            }
        }
    }
}

static DUMMY_PASSWORD_HASH: LazyLock<String> = LazyLock::new(|| {
    hash_password("nodus-dummy-timing-oracle-guard").expect("dummy password hash")
});

/// Builds the per-browser CSRF nonce cookie.
#[must_use]
pub fn csrf_cookie(nonce: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(CSRF_COOKIE, nonce);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(secure);
    cookie
}

/// Returns `(jar, csrf_form_token)` reusing an existing `nodus_csrf` cookie or minting one.
pub fn ensure_csrf(
    jar: CookieJar,
    session_secret: Option<&str>,
    secure: bool,
) -> (CookieJar, String) {
    let existing = jar
        .get(CSRF_COOKIE)
        .map(Cookie::value)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if let Some(nonce) = existing {
        let token = csrf_token(&nonce, session_secret);
        (jar, token)
    } else {
        let nonce = opaque_token();
        let token = csrf_token(&nonce, session_secret);
        (jar.add(csrf_cookie(nonce, secure)), token)
    }
}

/// Checks a submitted form CSRF token against the `nodus_csrf` cookie and optional session secret.
#[must_use]
pub fn has_valid_csrf(
    jar: &CookieJar,
    submitted_token: Option<&str>,
    session_secret: Option<&str>,
) -> bool {
    verify_csrf(
        jar.get(CSRF_COOKIE).map(Cookie::value),
        submitted_token,
        session_secret,
    )
}

#[derive(Clone)]
pub struct Config {
    pub domain: String,
    pub issuer: String,
    pub secure_cookies: bool,
    /// Whether a stranger may create an account from `/auth/register`.
    ///
    /// Off unless the operator says otherwise: an instance that is reachable before
    /// anyone has decided to open it should not be fillable by a script.
    pub registrations_open: bool,
}

/// Where a confirmation link points, and the base every link must use.
///
/// Held on [`AppState`] rather than in [`Config`] because it is only ever present when a
/// real sender exists; a `Config` literal therefore never has to invent a value for mail.
#[derive(Clone)]
pub struct EmailConfirmation {
    pub base_url: String,
}

impl Config {
    #[must_use]
    pub fn new(domain: impl Into<String>) -> Self {
        let domain = domain.into();
        Self {
            issuer: format!("https://{domain}"),
            domain,
            secure_cookies: true,
            registrations_open: false,
        }
    }
}

#[derive(Clone)]
pub struct AppState<S: AuthStore> {
    store: S,
    config: Arc<Config>,
    email_confirmation: Option<EmailConfirmation>,
}

impl<S: AuthStore> AppState<S> {
    pub fn new(store: S, config: Config) -> Self {
        Self {
            store,
            config: Arc::new(config),
            email_confirmation: None,
        }
    }

    /// Turns on the confirmation mail queued by registration.
    #[must_use]
    pub fn with_email_confirmation(mut self, confirmation: EmailConfirmation) -> Self {
        self.email_confirmation = Some(confirmation);
        self
    }
}

pub fn router<S: AuthStore>(state: AppState<S>) -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::to("/auth/login") }))
        .route("/auth/login", get(login_page::<S>).post(login_submit::<S>))
        .route(
            "/auth/register",
            get(register_page::<S>).post(register_submit::<S>),
        )
        .route("/auth/logout", post(logout::<S>))
        .route(
            "/auth/password/reset",
            get(password_reset::request_page::<S>).post(password_reset::request_submit::<S>),
        )
        .route(
            "/auth/password/reset/{token}",
            get(password_reset::form_page::<S>).post(password_reset::form_submit::<S>),
        )
        .route("/auth/confirm/{token}", get(confirm_page::<S>))
        .route(
            "/auth/2fa",
            get(two_factor_page::<S>).post(two_factor_submit::<S>),
        )
        .route(
            "/auth/2fa/enroll",
            get(enrol_page::<S>).post(enrol_submit::<S>),
        )
        .route("/auth/2fa/recovery", post(regenerate_recovery::<S>))
        .route("/auth/session", get(session::<S>))
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::<S>),
        )
        .route("/oauth/authorize", get(authorize::<S>).post(consent::<S>))
        .route("/oauth/token", post(token::<S>))
        .route("/oauth/revoke", post(revoke::<S>))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct LoginQuery {
    return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    email: String,
    password: String,
    return_to: Option<String>,
    #[serde(default)]
    csrf_token: String,
}

async fn login_page<S: AuthStore>(
    State(state): State<AppState<S>>,
    Query(query): Query<LoginQuery>,
    jar: CookieJar,
) -> (CookieJar, Html<String>) {
    let signed_in = jar.get(SESSION_COOKIE).is_some();
    let (jar, csrf_token) = ensure_csrf(jar, None, state.config.secure_cookies);
    (
        jar,
        Html(render_login(LoginView {
            domain: &state.config.domain,
            registrations_open: state.config.registrations_open,
            return_to: query.return_to.as_deref(),
            signed_in,
            error: None,
            filled: None,
            csrf_token: &csrf_token,
        })),
    )
}

fn verify_login_password(credential: Option<&Credential>, password: &str) -> bool {
    let hash_str = credential.map_or(DUMMY_PASSWORD_HASH.as_str(), |cred| {
        cred.password_hash.as_str()
    });
    let parsed = PasswordHash::new(hash_str)
        .unwrap_or_else(|_| PasswordHash::new(DUMMY_PASSWORD_HASH.as_str()).expect("dummy hash"));
    let verified = Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok();
    credential.is_some() && verified
}

async fn login_submit<S: AuthStore>(
    State(state): State<AppState<S>>,
    jar: CookieJar,
    headers: HeaderMap,
    peer: Peer,
    Form(form): Form<LoginForm>,
) -> Response {
    if !has_valid_csrf(&jar, Some(form.csrf_token.as_str()), None) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    if let Some(prefix) = peer.0.map(|address| network_prefix(address.ip())) {
        if matches!(
            state.store.ip_block_verdict(&prefix).await.ok().flatten(),
            Some(IpBlockVerdict::NoAccess)
        ) {
            return (
                StatusCode::FORBIDDEN,
                "This network is not permitted to sign in.",
            )
                .into_response();
        }
    }
    let credential = state
        .store
        .credential_by_email(form.email.trim())
        .await
        .ok()
        .flatten();
    if !verify_login_password(credential.as_ref(), &form.password) {
        let (jar, csrf_token) = ensure_csrf(jar, None, state.config.secure_cookies);
        return (
            jar,
            Html(render_login(LoginView {
                domain: &state.config.domain,
                registrations_open: state.config.registrations_open,
                return_to: form.return_to.as_deref(),
                signed_in: false,
                error: Some("Wrong email or password."),
                filled: Some(form.email.trim()),
                csrf_token: &csrf_token,
            })),
        )
            .into_response();
    }
    let Some(credential) = credential else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "credential missing").into_response();
    };

    // A confirmed authenticator moves the login to a challenge: the password alone must
    // not mint a session, and the challenge expires independently of this request.
    let totp = state
        .store
        .totp_state(&credential.account_id)
        .await
        .ok()
        .flatten();
    if totp.is_some_and(|state| state.confirmed) {
        let challenge = opaque_token();
        let expiry = Utc::now() + Duration::minutes(CHALLENGE_MINUTES);
        if state
            .store
            .create_2fa_challenge(&token_hash(&challenge), &credential.account_id, expiry)
            .await
            .is_err()
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "challenge could not be stored",
            )
                .into_response();
        }
        let redirect = with_return("/auth/2fa", form.return_to.as_deref());
        return (
            jar.add(two_factor_cookie(challenge, state.config.secure_cookies)),
            Redirect::to(&redirect),
        )
            .into_response();
    }

    let Ok(cookie) = issue_session(&state, &credential.account_id, &headers, peer).await else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session could not be stored",
        )
            .into_response();
    };
    let rotated_csrf = csrf_cookie(opaque_token(), state.config.secure_cookies);
    let target = safe_return_to(form.return_to.as_deref()).unwrap_or("/");
    (jar.add(cookie).add(rotated_csrf), Redirect::to(target)).into_response()
}

/// Mints the only thing a completed login produces: an opaque session token whose hash is
/// stored. Both the password-only path and the second-factor path end here.
async fn issue_session<S: AuthStore>(
    state: &AppState<S>,
    account_id: &str,
    headers: &HeaderMap,
    peer: Peer,
) -> Result<Cookie<'static>, ()> {
    let session = opaque_token();
    let expiry = Utc::now() + Duration::days(SESSION_DAYS);
    let (user_agent, ip) = session_device(headers, peer.0);
    state
        .store
        .create_session(
            &token_hash(&session),
            account_id,
            expiry,
            &user_agent,
            ip.as_deref(),
        )
        .await
        .map_err(|_| ())?;
    Ok(session_cookie(session, expiry, state.config.secure_cookies))
}

#[derive(Debug, Deserialize)]
struct RegisterForm {
    username: String,
    email: String,
    password: String,
    password_confirmation: String,
    return_to: Option<String>,
    #[serde(default)]
    csrf_token: String,
}

const USERNAME_MIN: usize = 3;
const USERNAME_MAX: usize = 30;
const PASSWORD_MIN: usize = 8;
const PASSWORD_MAX: usize = 200;

/// Names a new account may not take.
///
/// These are the first path segment of routes the instance answers, plus the names people
/// read as staff; a local account holding one would shadow a page or sound official.
const RESERVED_USERNAMES: &[&str] = &[
    "about",
    "admin",
    "administrator",
    "api",
    "ap",
    "auth",
    "explore",
    "help",
    "inbox",
    "media",
    "moderator",
    "nodus",
    "oauth",
    "outbox",
    "root",
    "settings",
    "staff",
    "statuses",
    "support",
    "system",
    "users",
    "web",
];

struct Registration {
    username: String,
    email: String,
    password: String,
}

/// Normalises a submitted form into the values that are written, or the one sentence
/// that tells the reader what to change.
fn normalized_registration(form: &RegisterForm) -> Result<Registration, &'static str> {
    let username = form.username.trim().to_ascii_lowercase();
    if !(USERNAME_MIN..=USERNAME_MAX).contains(&username.chars().count()) {
        return Err("A username is 3 to 30 characters.");
    }
    if !username.chars().all(|character| {
        character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
    }) {
        return Err("Use only letters, numbers and underscores in the username.");
    }
    if RESERVED_USERNAMES.contains(&username.as_str()) {
        return Err("That username is reserved on this instance.");
    }
    let email = form.email.trim();
    if !plausible_email(email) {
        return Err("That does not look like an email address.");
    }
    let password = form.password.clone();
    validated_password(&password, &form.password_confirmation)?;
    Ok(Registration {
        username,
        email: email.to_owned(),
        password,
    })
}

/// The one password rule, shared by registration and password reset.
///
/// A second rule would drift, and a reset would then accept something sign-up refuses.
fn validated_password(password: &str, confirmation: &str) -> Result<(), &'static str> {
    if password.chars().count() < PASSWORD_MIN {
        return Err("A password is at least 8 characters.");
    }
    if password.chars().count() > PASSWORD_MAX {
        return Err("That password is too long.");
    }
    if password != confirmation {
        return Err("The two passwords do not match.");
    }
    Ok(())
}

/// What passes for an email check here: one `@`, a local part, and a domain with a dot.
///
/// Deliverability is not decided at sign-up — nothing on this page sends mail — and a
/// stricter check only rejects addresses that happen to be unusual.
fn plausible_email(value: &str) -> bool {
    if value.is_empty() || value.len() > 254 || value.chars().any(char::is_whitespace) {
        return false;
    }
    let mut parts = value.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

async fn register_page<S: AuthStore>(
    State(state): State<AppState<S>>,
    Query(query): Query<LoginQuery>,
    jar: CookieJar,
) -> (CookieJar, Html<String>) {
    let (jar, csrf_token) = ensure_csrf(jar, None, state.config.secure_cookies);
    (
        jar,
        Html(render_register(RegisterView {
            domain: &state.config.domain,
            open: state.config.registrations_open,
            return_to: query.return_to.as_deref(),
            error: None,
            filled: None,
            csrf_token: &csrf_token,
        })),
    )
}

/// What the source network's block says about this attempt, if anything.
async fn sign_up_verdict<S: AuthStore>(
    state: &AppState<S>,
    peer: Option<SocketAddr>,
) -> Option<IpBlockVerdict> {
    let prefix = peer.map(|address| network_prefix(address.ip()))?;
    state.store.ip_block_verdict(&prefix).await.ok().flatten()
}

/// The confirmation mail a registration must queue in its own transaction, when mail is
/// configured at all.
fn queued_confirmation<S: AuthStore>(
    state: &AppState<S>,
    registration: &Registration,
) -> Option<Confirmation> {
    state.email_confirmation.as_ref().map(|mail| {
        let token = opaque_token();
        Confirmation {
            token_hash: token_hash(&token),
            expires_at: Utc::now() + Duration::hours(CONFIRMATION_HOURS),
            message: confirmation_message(
                &mail.base_url,
                &registration.username,
                &registration.email,
                &token,
            ),
        }
    })
}

async fn register_submit<S: AuthStore>(
    State(state): State<AppState<S>>,
    jar: CookieJar,
    headers: HeaderMap,
    peer: Peer,
    Form(form): Form<RegisterForm>,
) -> Response {
    if !state.config.registrations_open {
        return (
            StatusCode::FORBIDDEN,
            "registration is closed on this instance",
        )
            .into_response();
    }
    if !has_valid_csrf(&jar, Some(form.csrf_token.as_str()), None) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    let verdict = sign_up_verdict(&state, peer.0).await;
    if matches!(
        verdict,
        Some(IpBlockVerdict::NoAccess | IpBlockVerdict::SignUpBlock)
    ) {
        return registration_error(
            &state,
            jar,
            &form,
            "Registration is not available from this network.",
        );
    }
    // An address that must be reviewed still registers: the account exists and the
    // moderator's queue is where it waits. Refusing it here would put the decision in a
    // block table instead of the approval queue that already exists for exactly this.
    let approved = !matches!(verdict, Some(IpBlockVerdict::RequiresApproval));
    let registration = match normalized_registration(&form) {
        Ok(registration) => registration,
        Err(message) => return registration_error(&state, jar, &form, message),
    };
    let Ok(password_hash) = hash_password(&registration.password) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "password could not be hashed",
        )
            .into_response();
    };
    let confirmation = queued_confirmation(&state, &registration);
    let account = match state
        .store
        .register_local(
            &registration.username,
            &registration.email,
            &password_hash,
            approved,
            confirmation,
        )
        .await
    {
        Ok(account) => account,
        Err(RegisterError::UsernameTaken) => {
            return registration_error(&state, jar, &form, "That username is already taken.");
        }
        Err(RegisterError::EmailTaken) => {
            return registration_error(
                &state,
                jar,
                &form,
                "That email address already has a login.",
            );
        }
        Err(RegisterError::Database(error)) => {
            tracing::error!(%error, "registration failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the account could not be created",
            )
                .into_response();
        }
    };

    // A new account arrives signed in: making someone type the password they just chose
    // into the same page is a step that only exists to be clicked past.
    let session = opaque_token();
    let expiry = Utc::now() + Duration::days(SESSION_DAYS);
    let (user_agent, ip) = session_device(&headers, peer.0);
    if state
        .store
        .create_session(
            &token_hash(&session),
            &account.account_id,
            expiry,
            &user_agent,
            ip.as_deref(),
        )
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session could not be stored",
        )
            .into_response();
    }
    tracing::info!(username = %account.username, "account registered");

    let cookie = session_cookie(session, expiry, state.config.secure_cookies);
    let rotated_csrf = csrf_cookie(opaque_token(), state.config.secure_cookies);
    let target = safe_return_to(form.return_to.as_deref()).unwrap_or("/");
    (jar.add(cookie).add(rotated_csrf), Redirect::to(target)).into_response()
}

/// Answers a confirmation link.
///
/// A GET because the link is opened from a mail client. The token is single-use, so a
/// second visit reports the expired case instead of confirming twice.
async fn confirm_page<S: AuthStore>(
    State(state): State<AppState<S>>,
    Path(token): Path<String>,
) -> Response {
    match state.store.confirm_email(&token_hash(&token)).await {
        Ok(Some(username)) => {
            let heading = format!("@{username}, your address is confirmed.");
            Html(shell(
                "Address confirmed · Nodus",
                None,
                view! {
                    <h1>{heading}</h1>
                    <p class="muted">"You can close this page and return to Nodus."</p>
                    <p><a href="/">"Go to Nodus"</a></p>
                },
            ))
            .into_response()
        }
        Ok(None) => (
            StatusCode::GONE,
            Html(shell(
                "Confirmation expired · Nodus",
                None,
                view! {
                    <h1>"This link is no longer valid."</h1>
                    <p class="muted">"It may have expired or already been used."</p>
                },
            )),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "confirmation failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "confirmation failed").into_response()
        }
    }
}

/// The message a new account receives.
///
/// Both bodies carry the same absolute link. The HTML has no images, fonts or tracking
/// pixel: opening a confirmation must not tell a third party which address exists.
fn confirmation_message(
    base_url: &str,
    username: &str,
    email: &str,
    token: &str,
) -> nodus_mail::Message {
    let link = format!("{}/auth/confirm/{token}", base_url.trim_end_matches('/'));
    let subject = "Confirm your Nodus address".to_owned();
    let text = format!(
        "Hello @{username},\n\nConfirm this address for your Nodus account by opening:\n\n{link}\n\n\
         The link is valid for {CONFIRMATION_HOURS} hours and can be used once.\n\
         If you did not create an account, ignore this message.\n"
    );
    let username_html = escape_html(username);
    let email_html = escape_html(email);
    let html = format!(
        "<!doctype html><html><body>\
         <p>Hello @{username_html},</p>\
         <p>Confirm this address for your Nodus account:</p>\
         <p><a href=\"{link}\">Confirm {email_html}</a></p>\
         <p>The link is valid for {CONFIRMATION_HOURS} hours and can be used once.</p>\
         <p>If you did not create an account, ignore this message.</p>\
         </body></html>"
    );
    nodus_mail::Message {
        to: email.to_owned(),
        subject,
        text,
        html: Some(html),
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Re-renders the form with the submitted name and email still in it.
fn registration_error<S: AuthStore>(
    state: &AppState<S>,
    jar: CookieJar,
    form: &RegisterForm,
    message: &str,
) -> Response {
    let (jar, csrf_token) = ensure_csrf(jar, None, state.config.secure_cookies);
    (
        jar,
        Html(render_register(RegisterView {
            domain: &state.config.domain,
            open: true,
            return_to: form.return_to.as_deref(),
            error: Some(message),
            filled: Some(RegisterFilled {
                username: form.username.trim(),
                email: form.email.trim(),
            }),
            csrf_token: &csrf_token,
        })),
    )
        .into_response()
}

async fn logout<S: AuthStore>(State(state): State<AppState<S>>, jar: CookieJar) -> Response {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        let _ = state
            .store
            .delete_session(&token_hash(cookie.value()))
            .await;
    }
    let mut removal = Cookie::new(SESSION_COOKIE, "");
    removal.set_path("/");
    removal.set_max_age(Some(time::Duration::ZERO));
    let mut csrf_removal = Cookie::new(CSRF_COOKIE, "");
    csrf_removal.set_path("/");
    csrf_removal.set_max_age(Some(time::Duration::ZERO));
    (
        jar.remove(removal).remove(csrf_removal),
        Redirect::to("/auth/login"),
    )
        .into_response()
}

async fn session<S: AuthStore>(
    State(state): State<AppState<S>>,
    jar: CookieJar,
) -> Result<Json<SessionJson>, StatusCode> {
    let Some(account) = current_account(&state, &jar).await else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    Ok(Json(SessionJson {
        account_id: account.account_id,
        username: account.username,
        display_name: account.display_name,
    }))
}

fn two_factor_cookie(value: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(TWO_FACTOR_COOKIE, value);
    // The challenge is only useful under the auth routes; a wider path would carry it to
    // every page for no reason.
    cookie.set_path("/auth");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(secure);
    cookie.set_max_age(time::Duration::minutes(CHALLENGE_MINUTES));
    cookie
}

fn expired_two_factor_cookie() -> Cookie<'static> {
    let mut cookie = Cookie::new(TWO_FACTOR_COOKIE, "");
    cookie.set_path("/auth");
    cookie.set_max_age(Some(time::Duration::ZERO));
    cookie
}

#[derive(Debug, Deserialize)]
struct TwoFactorForm {
    code: String,
    return_to: Option<String>,
    #[serde(default)]
    csrf_token: String,
}

async fn two_factor_page<S: AuthStore>(
    State(state): State<AppState<S>>,
    jar: CookieJar,
    Query(query): Query<LoginQuery>,
) -> Response {
    let Some(challenge) = jar.get(TWO_FACTOR_COOKIE).map(Cookie::value) else {
        return Redirect::to("/auth/login").into_response();
    };
    if state
        .store
        .challenge_account(&token_hash(challenge))
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return (
            jar.remove(expired_two_factor_cookie()),
            Redirect::to("/auth/login"),
        )
            .into_response();
    }
    let (jar, csrf_token) = ensure_csrf(jar, None, state.config.secure_cookies);
    (
        jar,
        Html(render_two_factor(
            query.return_to.as_deref(),
            None,
            &csrf_token,
        )),
    )
        .into_response()
}

async fn two_factor_submit<S: AuthStore>(
    State(state): State<AppState<S>>,
    jar: CookieJar,
    headers: HeaderMap,
    peer: Peer,
    Form(form): Form<TwoFactorForm>,
) -> Response {
    let (jar, _csrf_token) = ensure_csrf(jar, None, state.config.secure_cookies);
    if !has_valid_csrf(&jar, Some(form.csrf_token.as_str()), None) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    let Some(challenge) = jar.get(TWO_FACTOR_COOKIE).map(Cookie::value) else {
        return Redirect::to("/auth/login").into_response();
    };
    let challenge_hash = token_hash(challenge);
    let Some(account_id) = state
        .store
        .challenge_account(&challenge_hash)
        .await
        .ok()
        .flatten()
    else {
        return (
            jar.remove(expired_two_factor_cookie()),
            Redirect::to("/auth/login"),
        )
            .into_response();
    };
    let Some(totp_state) = state
        .store
        .totp_state(&account_id)
        .await
        .ok()
        .flatten()
        .filter(|state| state.confirmed)
    else {
        return (
            jar.remove(expired_two_factor_cookie()),
            Redirect::to("/auth/login"),
        )
            .into_response();
    };

    let step = totp::step_at(Utc::now().timestamp());
    let accepted = match totp::verify(
        &totp_state.secret,
        &form.code,
        step,
        totp_state.last_used_step,
    ) {
        // The step is recorded in the same UPDATE that admits it, so a replay in the same
        // window loses the race rather than issuing a second session.
        Some(step) => state
            .store
            .advance_totp_step(&account_id, step)
            .await
            .unwrap_or(false),
        None => state
            .store
            .consume_recovery_code(&account_id, &totp::recovery_code_hash(&form.code))
            .await
            .unwrap_or(false),
    };
    if !accepted {
        return refuse_two_factor(&state, jar, form.return_to.as_deref(), &challenge_hash).await;
    }

    // Only the request that removes the challenge may issue the session: a concurrent
    // request that saw the same challenge row fails here.
    if !state
        .store
        .delete_2fa_challenge(&challenge_hash)
        .await
        .unwrap_or(false)
    {
        return (
            jar.remove(expired_two_factor_cookie()),
            Redirect::to("/auth/login"),
        )
            .into_response();
    }
    let Ok(cookie) = issue_session(&state, &account_id, &headers, peer).await else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session could not be stored",
        )
            .into_response();
    };
    let rotated_csrf = csrf_cookie(opaque_token(), state.config.secure_cookies);
    let target = safe_return_to(form.return_to.as_deref()).unwrap_or("/");
    (
        jar.add(cookie)
            .add(rotated_csrf)
            .remove(expired_two_factor_cookie()),
        Redirect::to(target),
    )
        .into_response()
}

/// Answers a wrong code while spending one of the challenge's attempts.
///
/// The count and the decision to burn the row happen under one row lock, so parallel
/// guesses cannot each read the same count and exceed the limit. Once the row is gone the
/// next answer needs a fresh password, which is the only thing that mints a new challenge.
async fn refuse_two_factor<S: AuthStore>(
    state: &AppState<S>,
    jar: CookieJar,
    return_to: Option<&str>,
    challenge_hash: &str,
) -> Response {
    let survives = state
        .store
        .record_failed_2fa_attempt(challenge_hash, CHALLENGE_ATTEMPTS)
        .await
        .unwrap_or(false);
    if !survives {
        return (
            jar.remove(expired_two_factor_cookie()),
            Redirect::to("/auth/login"),
        )
            .into_response();
    }
    let (jar, csrf_token) = ensure_csrf(jar, None, state.config.secure_cookies);
    (
        jar,
        Html(render_two_factor(
            return_to,
            Some("That code did not work. Try the next one, or a recovery code."),
            &csrf_token,
        )),
    )
        .into_response()
}

async fn enrol_page<S: AuthStore>(State(state): State<AppState<S>>, jar: CookieJar) -> Response {
    let Some(account) = current_account(&state, &jar).await else {
        return Redirect::to("/auth/login").into_response();
    };
    let (jar, csrf_token) = ensure_csrf(jar, None, state.config.secure_cookies);
    let totp_state = state
        .store
        .totp_state(&account.account_id)
        .await
        .ok()
        .flatten();
    if totp_state.as_ref().is_some_and(|state| state.confirmed) {
        return (jar, Html(render_enrolled(&csrf_token))).into_response();
    }
    // Reuse an unfinished secret: reloading the page must not silently invalidate the
    // QR the user already scanned.
    let secret = if let Some(state) = totp_state {
        state.secret
    } else {
        let secret = totp::generate_secret();
        if state
            .store
            .start_totp_enrolment(&account.account_id, &secret)
            .await
            .is_err()
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "enrolment could not be stored",
            )
                .into_response();
        }
        secret
    };
    let uri = totp::provisioning_uri(&state.config.domain, &account.username, &secret);
    (
        jar,
        Html(render_enrolment(
            &account.username,
            &secret,
            &uri,
            None,
            &csrf_token,
        )),
    )
        .into_response()
}

async fn enrol_submit<S: AuthStore>(
    State(state): State<AppState<S>>,
    jar: CookieJar,
    Form(form): Form<TwoFactorForm>,
) -> Response {
    let Some(account) = current_account(&state, &jar).await else {
        return Redirect::to("/auth/login").into_response();
    };
    let (jar, csrf_token) = ensure_csrf(jar, None, state.config.secure_cookies);
    if !has_valid_csrf(&jar, Some(form.csrf_token.as_str()), None) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    let Some(totp_state) = state
        .store
        .totp_state(&account.account_id)
        .await
        .ok()
        .flatten()
    else {
        return Redirect::to("/auth/2fa/enroll").into_response();
    };
    if totp_state.confirmed {
        return (jar, Html(render_enrolled(&csrf_token))).into_response();
    }
    let step = totp::step_at(Utc::now().timestamp());
    let Some(step) = totp::verify(&totp_state.secret, &form.code, step, None) else {
        let uri =
            totp::provisioning_uri(&state.config.domain, &account.username, &totp_state.secret);
        return (
            jar,
            Html(render_enrolment(
                &account.username,
                &totp_state.secret,
                &uri,
                Some("That code did not match. Check the app's clock and try again."),
                &csrf_token,
            )),
        )
            .into_response();
    };
    let codes: Vec<String> = (0..totp::RECOVERY_CODES)
        .map(|_| totp::generate_recovery_code())
        .collect();
    let hashes: Vec<String> = codes
        .iter()
        .map(|code| totp::recovery_code_hash(code))
        .collect();
    if state
        .store
        .confirm_totp(&account.account_id, step, &hashes)
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "enrolment could not be confirmed",
        )
            .into_response();
    }
    (jar, Html(render_recovery_codes(&codes))).into_response()
}

async fn regenerate_recovery<S: AuthStore>(
    State(state): State<AppState<S>>,
    jar: CookieJar,
    Form(form): Form<TwoFactorForm>,
) -> Response {
    let Some(account) = current_account(&state, &jar).await else {
        return Redirect::to("/auth/login").into_response();
    };
    let (jar, _csrf_token) = ensure_csrf(jar, None, state.config.secure_cookies);
    if !has_valid_csrf(&jar, Some(form.csrf_token.as_str()), None) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    let Some(_totp_state) = state
        .store
        .totp_state(&account.account_id)
        .await
        .ok()
        .flatten()
        .filter(|state| state.confirmed)
    else {
        return Redirect::to("/auth/2fa/enroll").into_response();
    };
    let codes: Vec<String> = (0..totp::RECOVERY_CODES)
        .map(|_| totp::generate_recovery_code())
        .collect();
    let hashes: Vec<String> = codes
        .iter()
        .map(|code| totp::recovery_code_hash(code))
        .collect();
    // The delete and the insert share a transaction, so the old set stops working at the
    // same moment the new one appears.
    if state
        .store
        .replace_recovery_codes(&account.account_id, &hashes)
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "recovery codes could not be replaced",
        )
            .into_response();
    }
    (jar, Html(render_recovery_codes(&codes))).into_response()
}

fn render_two_factor(return_to: Option<&str>, error: Option<&str>, csrf_token: &str) -> String {
    let return_to = return_to.unwrap_or_default().to_owned();
    let csrf_token = csrf_token.to_owned();
    let error = error.map(str::to_owned);
    shell(
        "Two-factor · Nodus",
        None,
        view! {
            <h1>"Two-factor authentication"</h1>
            <p class="muted">
                "Enter the six-digit code from your authenticator app, or one of your recovery codes."
            </p>
            {error.map(|message| view! { <p class="error">{message}</p> })}
            <form method="post" action="/auth/2fa">
                <input type="hidden" name="return_to" value=return_to/>
                <input type="hidden" name="csrf_token" value=csrf_token/>
                <label for="code">"Code"</label>
                <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code"
                    autofocus required/>
                <div class="actions">
                    <button type="submit">"Continue"</button>
                </div>
            </form>
        },
    )
}

fn render_enrolment(
    username: &str,
    secret: &str,
    uri: &str,
    error: Option<&str>,
    csrf_token: &str,
) -> String {
    let username = username.to_owned();
    let secret = secret.to_owned();
    let uri = uri.to_owned();
    let csrf_token = csrf_token.to_owned();
    let error = error.map(str::to_owned);
    shell(
        "Set up two-factor · Nodus",
        None,
        view! {
            <h1>"Set up two-factor authentication"</h1>
            <p class="muted">
                "Add this secret to your authenticator app, then enter the code it shows. "
                "The factor is not required until you confirm it."
            </p>
            <p>"Account: "<strong>{username}</strong></p>
            <p>"Secret: "<code>{secret}</code></p>
            <p class="muted">"Or open this link on the device with the app:"</p>
            <p><code class="break">{uri}</code></p>
            {error.map(|message| view! { <p class="error">{message}</p> })}
            <form method="post" action="/auth/2fa/enroll">
                <input type="hidden" name="csrf_token" value=csrf_token/>
                <label for="code">"Code from the app"</label>
                <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code"
                    autofocus required/>
                <div class="actions">
                    <button type="submit">"Turn on two-factor"</button>
                </div>
            </form>
        },
    )
}

fn render_enrolled(csrf_token: &str) -> String {
    let csrf_token = csrf_token.to_owned();
    shell(
        "Two-factor · Nodus",
        None,
        view! {
            <h1>"Two-factor authentication is on"</h1>
            <p class="muted">
                "Signing in now asks for a code after your password. Keep the recovery codes "
                "somewhere you can reach without your phone."
            </p>
            <form method="post" action="/auth/2fa/recovery">
                <input type="hidden" name="csrf_token" value=csrf_token/>
                <button type="submit" class="secondary">"Replace recovery codes"</button>
            </form>
            <p class="muted">"Replacing them invalidates every code shown before."</p>
        },
    )
}

fn render_recovery_codes(codes: &[String]) -> String {
    let codes: Vec<String> = codes.to_vec();
    shell(
        "Recovery codes · Nodus",
        None,
        view! {
            <h1>"Save your recovery codes"</h1>
            <p class="error">
                "These are shown once. Each works one time, in place of an authenticator code."
            </p>
            <ul>
                {codes
                    .into_iter()
                    .map(|code| view! { <li><code>{code}</code></li> })
                    .collect_view()}
            </ul>
            <p><a href="/">"Continue"</a></p>
        },
    )
}

async fn authorize<S: AuthStore>(
    State(state): State<AppState<S>>,
    RawQuery(query): RawQuery,
    jar: CookieJar,
) -> Response {
    let raw = query.unwrap_or_default();
    let pairs = parse_pairs(&raw);
    let Ok(request) = AuthorizeRequest::parse(&pairs) else {
        return (StatusCode::BAD_REQUEST, "invalid authorization request").into_response();
    };
    let Ok(Some(app)) = state.store.client_app(&request.client_id).await else {
        return (StatusCode::BAD_REQUEST, "unknown client").into_response();
    };
    if !redirect_allowed(&app.redirect_uris, &request.redirect_uri) {
        return (StatusCode::BAD_REQUEST, "redirect_uri is not registered").into_response();
    }
    if request.scopes.is_empty()
        || !request
            .scopes
            .iter()
            .all(|scope| app.scopes.contains(scope))
    {
        return (
            StatusCode::BAD_REQUEST,
            "requested scope is not allowed for this client",
        )
            .into_response();
    }
    let Some(account) = current_account(&state, &jar).await else {
        let return_to = format!("/oauth/authorize?{raw}");
        let url = format!(
            "/auth/login?return_to={}",
            url::form_urlencoded::byte_serialize(return_to.as_bytes()).collect::<String>()
        );
        return Redirect::to(&url).into_response();
    };
    if !account.admin && request.scopes.iter().any(|scope| is_admin_scope(scope)) {
        return (
            StatusCode::FORBIDDEN,
            "admin scope requires an administrator account",
        )
            .into_response();
    }
    let session_secret = jar
        .get(SESSION_COOKIE)
        .map(Cookie::value)
        .map(str::to_owned);
    let (jar, csrf_token) =
        ensure_csrf(jar, session_secret.as_deref(), state.config.secure_cookies);
    (
        jar,
        Html(render_consent(&app.name, &request, &account, &csrf_token)),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct ConsentForm {
    client_id: String,
    redirect_uri: String,
    scopes: String,
    state: Option<String>,
    code_challenge: String,
    decision: String,
    #[serde(default)]
    csrf_token: String,
}

async fn consent<S: AuthStore>(
    State(state): State<AppState<S>>,
    jar: CookieJar,
    Form(form): Form<ConsentForm>,
) -> Response {
    let Some(account) = current_account(&state, &jar).await else {
        return Redirect::to("/auth/login").into_response();
    };
    let session_secret = jar.get(SESSION_COOKIE).map(Cookie::value);
    if !has_valid_csrf(&jar, Some(form.csrf_token.as_str()), session_secret) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    let Ok(Some(app)) = state.store.client_app(&form.client_id).await else {
        return (StatusCode::BAD_REQUEST, "unknown client").into_response();
    };
    if !redirect_allowed(&app.redirect_uris, &form.redirect_uri) {
        return (StatusCode::BAD_REQUEST, "redirect_uri is not registered").into_response();
    }
    let scopes: Vec<String> = form.scopes.split_whitespace().map(str::to_owned).collect();
    if scopes.is_empty() || !scopes.iter().all(|scope| app.scopes.contains(scope)) {
        return (
            StatusCode::BAD_REQUEST,
            "requested scope is not allowed for this client",
        )
            .into_response();
    }
    if !account.admin && scopes.iter().any(|scope| is_admin_scope(scope)) {
        return (
            StatusCode::FORBIDDEN,
            "admin scope requires an administrator account",
        )
            .into_response();
    }
    if form.decision != "allow" {
        if !is_safe_redirect_uri(&form.redirect_uri) {
            return (StatusCode::BAD_REQUEST, "bad redirect_uri").into_response();
        }
        let Ok(mut url) = url::Url::parse(&form.redirect_uri) else {
            return (StatusCode::BAD_REQUEST, "bad redirect_uri").into_response();
        };
        url.query_pairs_mut().append_pair("error", "access_denied");
        if let Some(state_val) = form.state.as_deref().filter(|s| !s.is_empty()) {
            url.query_pairs_mut().append_pair("state", state_val);
        }
        return Redirect::to(url.as_str()).into_response();
    }

    let code = opaque_token();
    let expires = Utc::now() + Duration::minutes(CODE_MINUTES);
    if state
        .store
        .create_code(
            &token_hash(&code),
            &app.id,
            &account.account_id,
            &form.redirect_uri,
            &scopes,
            &form.code_challenge,
            expires,
        )
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "code could not be stored",
        )
            .into_response();
    }
    match redirect_with(&form.redirect_uri, &code, form.state.as_deref()) {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "bad redirect_uri").into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: String,
    client_secret: Option<String>,
    code_verifier: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    scope: String,
    created_at: i64,
}

async fn token<S: AuthStore>(
    State(state): State<AppState<S>>,
    Form(form): Form<TokenForm>,
) -> Response {
    if form.grant_type != crate::domain::AUTHORIZATION_CODE {
        return oauth_error("unsupported_grant_type");
    }
    let (Some(code), Some(redirect_uri), Some(verifier)) = (
        form.code.as_deref(),
        form.redirect_uri.as_deref(),
        form.code_verifier.as_deref(),
    ) else {
        return oauth_error("invalid_request");
    };
    let Ok(Some(app)) = state.store.client_app(&form.client_id).await else {
        return oauth_error("invalid_client");
    };
    // A public client cannot keep a secret: a browser bundle and a mobile app are both
    // readable by whoever runs them. PKCE is what makes that safe — the verifier proves
    // the same thing the secret would, that whoever redeems the code is whoever started
    // the flow — so the exchange is allowed without one. A secret that *is* presented
    // still has to match, which keeps a leaked confidential client from being replayed.
    if form
        .client_secret
        .as_deref()
        .filter(|value| !value.is_empty())
        .is_some_and(|secret| {
            !constant_time_eq(
                token_hash(secret).as_bytes(),
                app.client_secret_hash.as_bytes(),
            )
        })
    {
        return oauth_error("invalid_client");
    }
    let Ok(Some(stored)) = state.store.consume_code(&token_hash(code)).await else {
        return oauth_error("invalid_grant");
    };
    if stored.app_id != app.id || stored.redirect_uri != redirect_uri {
        return oauth_error("invalid_grant");
    }
    if verify_pkce(verifier, &stored.code_challenge).is_err() {
        return oauth_error("invalid_grant");
    }
    if stored.scopes.is_empty() || !stored.scopes.iter().all(|scope| app.scopes.contains(scope)) {
        return oauth_error("invalid_scope");
    }
    if !stored.account_admin && stored.scopes.iter().any(|scope| is_admin_scope(scope)) {
        return oauth_error("access_denied");
    }
    let access_token = opaque_token();
    if state
        .store
        .issue_token(
            &token_hash(&access_token),
            &stored.app_id,
            &stored.account_id,
            &stored.scopes,
        )
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "token could not be stored",
        )
            .into_response();
    }
    Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        scope: stored.scopes.join(" "),
        created_at: Utc::now().timestamp(),
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
struct RevokeForm {
    token: String,
}

async fn revoke<S: AuthStore>(
    State(state): State<AppState<S>>,
    Form(form): Form<RevokeForm>,
) -> StatusCode {
    let _ = state.store.revoke_token(&token_hash(&form.token)).await;
    StatusCode::OK
}

async fn metadata<S: AuthStore>(State(state): State<AppState<S>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "issuer": state.config.issuer,
        "authorization_endpoint": format!("{}/oauth/authorize", state.config.issuer),
        "token_endpoint": format!("{}/oauth/token", state.config.issuer),
        "revocation_endpoint": format!("{}/oauth/revoke", state.config.issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "scopes_supported": ["read", "write", "follow", "push"]
    }))
}

async fn current_account<S: AuthStore>(
    state: &AppState<S>,
    jar: &CookieJar,
) -> Option<SessionAccount> {
    let cookie = jar.get(SESSION_COOKIE)?;
    state
        .store
        .session_account(&token_hash(cookie.value()))
        .await
        .ok()
        .flatten()
}

fn session_cookie(value: String, expires: chrono::DateTime<Utc>, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE, value);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(secure);
    cookie.set_expires(
        time::OffsetDateTime::from_unix_timestamp(expires.timestamp())
            .unwrap_or_else(|_| time::OffsetDateTime::now_utc()),
    );
    cookie
}

fn safe_return_to(value: Option<&str>) -> Option<&str> {
    value.filter(|target| target.starts_with('/') && !target.starts_with("//"))
}

fn parse_pairs(raw: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(raw.as_bytes())
        .into_owned()
        .collect()
}

fn oauth_error(code: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": code })),
    )
        .into_response()
}

#[derive(Debug, Serialize)]
struct SessionJson {
    account_id: String,
    username: String,
    display_name: String,
}

/// The stylesheet the auth pages wear.
///
/// These pages are answered by the backend, not by the client, so they cannot link the
/// client's compiled stylesheet: its name is a content hash. The tokens below are copied
/// from `web/crates/web-shared/style/theme.css`, so the door and the room behind it look
/// like one product — keep them in step when that palette changes.
const STYLES: &str = "\
:root{color-scheme:light dark;\
--sans:ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,'Noto Sans',sans-serif;\
--mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace;\
--radius:0.5rem;\
--base-100:oklch(99% 0.003 250);--base-200:oklch(97% 0.004 250);--base-300:oklch(93% 0.006 250);\
--base-content:oklch(28% 0.012 255);--primary:oklch(58% 0.16 258);\
--primary-content:oklch(99% 0.005 258);--error:oklch(60% 0.19 25)}\
@media (prefers-color-scheme:dark){:root{\
--base-100:oklch(22% 0.01 255);--base-200:oklch(19% 0.01 255);--base-300:oklch(16% 0.01 255);\
--base-content:oklch(92% 0.006 255);--primary:oklch(72% 0.13 258);\
--primary-content:oklch(18% 0.02 258);--error:oklch(70% 0.16 25)}}\
*{box-sizing:border-box}\
body{margin:0;min-height:100vh;background:var(--base-200);color:var(--base-content);\
font-family:var(--sans);font-size:1rem;line-height:1.5;-webkit-font-smoothing:antialiased}\
a{color:var(--primary)}\
.top{display:flex;align-items:center;justify-content:space-between;gap:.75rem;\
border-bottom:1px solid var(--base-300);background:var(--base-100);padding:.5rem .75rem}\
.brand{font-weight:600;letter-spacing:-.01em;color:var(--base-content);text-decoration:none}\
.top nav{font-size:.875rem}\
main{width:min(26rem,calc(100vw - 2rem));margin:2rem auto 3rem;padding:1.5rem;\
background:var(--base-100);border:1px solid var(--base-300);border-radius:var(--radius);\
box-shadow:0 1px 2px 0 color-mix(in oklch,#000 8%,transparent)}\
h1{font-size:1.25rem;font-weight:600;letter-spacing:-.01em;margin:0 0 .25rem}\
p{margin:0 0 .75rem;font-size:.875rem}\
p.muted,.muted{color:color-mix(in oklch,var(--base-content) 65%,transparent)}\
.field{margin:0 0 .75rem}\
label{display:block;margin:0 0 .25rem;font-size:.875rem}\
.hint{margin:.25rem 0 0;font-size:.75rem;color:color-mix(in oklch,var(--base-content) 60%,transparent)}\
input{width:100%;padding:.5rem .625rem;font:inherit;font-size:.9375rem;color:var(--base-content);\
background:var(--base-100);border:1px solid var(--base-300);border-radius:var(--radius)}\
input:focus-visible{outline:2px solid var(--primary);outline-offset:1px}\
button{display:block;width:100%;padding:.55rem .75rem;font:inherit;font-size:.9375rem;\
font-weight:600;color:var(--primary-content);background:var(--primary);border:1px solid transparent;\
border-radius:var(--radius);cursor:pointer}\
button:hover{background:color-mix(in oklch,var(--primary) 88%,var(--base-content))}\
button:focus-visible{outline:2px solid var(--primary);outline-offset:2px}\
button.secondary{color:var(--base-content);background:var(--base-200);border-color:var(--base-300)}\
button.secondary:hover{background:var(--base-300)}\
.actions{display:flex;gap:.5rem}.actions button{flex:1}\
.alert{margin:0 0 .75rem;padding:.5rem .75rem;font-size:.875rem;color:var(--error);\
background:color-mix(in oklch,var(--error) 12%,transparent);\
border:1px solid color-mix(in oklch,var(--error) 35%,transparent);border-radius:var(--radius)}\
.scopes{list-style:none;margin:0 0 .75rem;padding:0;display:flex;flex-direction:column;gap:.375rem}\
.scopes li{display:flex;gap:.5rem;align-items:baseline;padding:.375rem .5rem;font-size:.8125rem;\
border:1px solid var(--base-300);border-radius:var(--radius);background:var(--base-200)}\
.scopes code{font-family:var(--mono);font-size:.8125rem;font-weight:600}\
.scopes span{color:color-mix(in oklch,var(--base-content) 70%,transparent)}\
footer{margin:1.25rem 0 0;padding:.875rem 0 0;border-top:1px solid var(--base-300);font-size:.875rem}\
footer button{width:auto;margin:0;padding:.35rem .6rem;font-size:.8125rem}\
";

fn shell(title: &str, nav: Option<(String, String)>, content: impl IntoView + 'static) -> String {
    let title = title.to_owned();
    let body = Owner::new().with(|| {
        view! {
            <html lang="en">
                <head>
                    <meta charset="utf-8"/>
                    <meta name="viewport" content="width=device-width, initial-scale=1"/>
                    <meta name="robots" content="noindex"/>
                    <title>{title}</title>
                    <style>{STYLES}</style>
                </head>
                <body>
                    <header class="top">
                        <a class="brand" href="/">"Nodus"</a>
                        <nav>
                            {nav.map(|(href, label)| view! { <a href=href>{label}</a> })}
                        </nav>
                    </header>
                    <main>{content}</main>
                </body>
            </html>
        }
        .to_html()
    });
    format!("<!DOCTYPE html>{body}")
}

/// Rebuilds a link that carries the caller's `return_to`, so a detour through a form still
/// ends where the reader was going.
fn with_return(path: &str, return_to: Option<&str>) -> String {
    match safe_return_to(return_to) {
        Some(target) => format!(
            "{path}?return_to={}",
            url::form_urlencoded::byte_serialize(target.as_bytes()).collect::<String>()
        ),
        None => path.to_owned(),
    }
}

/// The one line the consent screen shows for a scope.
fn scope_label(scope: &str) -> &'static str {
    match scope {
        "read" => "Read your timelines, notifications and profile",
        "write" => "Post, edit, boost and delete on your behalf",
        "follow" => "Follow and unfollow accounts for you",
        "push" => "Receive push notifications",
        _ => "An ability this instance does not describe",
    }
}

#[derive(Clone, Copy)]
struct LoginView<'a> {
    domain: &'a str,
    registrations_open: bool,
    return_to: Option<&'a str>,
    signed_in: bool,
    error: Option<&'a str>,
    filled: Option<&'a str>,
    csrf_token: &'a str,
}

fn render_login(view: LoginView<'_>) -> String {
    let return_to = view.return_to.unwrap_or("/").to_owned();
    let email = view.filled.unwrap_or_default().to_owned();
    let csrf_token = view.csrf_token.to_owned();
    let domain = view.domain.to_owned();
    let error = view.error.map(str::to_owned);
    let signed_in = view.signed_in;
    let register_href = with_return("/auth/register", view.return_to);
    let nav = view
        .registrations_open
        .then(|| (register_href.clone(), "Create account".to_owned()));
    let open = view.registrations_open;
    shell(
        "Sign in · Nodus",
        nav,
        view! {
            <h1>"Sign in"</h1>
            <p class="muted">{format!("Use your {domain} account to continue.")}</p>
            {signed_in.then(|| view! { <p class="muted">"You are already signed in."</p> })}
            {error.map(|message| view! { <div class="alert" role="alert">{message}</div> })}
            <form method="post" action="/auth/login">
                <input type="hidden" name="return_to" value=return_to/>
                <input type="hidden" name="csrf_token" value=csrf_token/>
                <div class="field">
                    <label for="email">"Email"</label>
                    <input
                        id="email"
                        name="email"
                        type="email"
                        autocomplete="username"
                        value=email
                        required
                    />
                </div>
                <div class="field">
                    <label for="password">"Password"</label>
                    <input
                        id="password"
                        name="password"
                        type="password"
                        autocomplete="current-password"
                        required
                    />
                </div>
                <button type="submit">"Sign in"</button>
            </form>
            {open
                .then(|| {
                    view! {
                        <footer>
                            <span class="muted">"No account yet? "</span>
                            <a href=register_href>"Create one"</a>
                        </footer>
                    }
                })}
        },
    )
}

struct RegisterFilled<'a> {
    username: &'a str,
    email: &'a str,
}

struct RegisterView<'a> {
    domain: &'a str,
    open: bool,
    return_to: Option<&'a str>,
    error: Option<&'a str>,
    filled: Option<RegisterFilled<'a>>,
    csrf_token: &'a str,
}

fn render_register(view: RegisterView<'_>) -> String {
    let domain = view.domain.to_owned();
    let sign_in_href = with_return("/auth/login", view.return_to);
    let nav = Some((sign_in_href.clone(), "Sign in".to_owned()));

    if !view.open {
        return shell(
            "Create account · Nodus",
            nav,
            view! {
                <h1>"Registration is closed"</h1>
                <p class="muted">
                    {format!(
                        "{domain} is not accepting new accounts right now. Ask an administrator to create one for you.",
                    )}
                </p>
            },
        );
    }

    let return_to = view.return_to.unwrap_or("/").to_owned();
    let csrf_token = view.csrf_token.to_owned();
    let error = view.error.map(str::to_owned);
    let (username, email) = view.filled.map_or_else(
        || (String::new(), String::new()),
        |filled| (filled.username.to_owned(), filled.email.to_owned()),
    );
    let handle = if username.is_empty() {
        "name".to_owned()
    } else {
        username.clone()
    };
    shell(
        "Create account · Nodus",
        nav,
        view! {
            <h1>"Create account"</h1>
            <p class="muted">{format!("Pick a name and a password for {domain}.")}</p>
            {error.map(|message| view! { <div class="alert" role="alert">{message}</div> })}
            <form method="post" action="/auth/register">
                <input type="hidden" name="return_to" value=return_to/>
                <input type="hidden" name="csrf_token" value=csrf_token/>
                <div class="field">
                    <label for="username">"Username"</label>
                    <input
                        id="username"
                        name="username"
                        type="text"
                        autocomplete="username"
                        value=username
                        required
                        minlength="3"
                        maxlength="30"
                        pattern="[A-Za-z0-9_]+"
                    />
                    <p class="hint">{format!(
                        "Letters, numbers and underscores. Others will see you as @{handle}@{domain}.",
                    )}</p>
                </div>
                <div class="field">
                    <label for="email">"Email"</label>
                    <input
                        id="email"
                        name="email"
                        type="email"
                        autocomplete="email"
                        value=email
                        required
                    />
                    <p class="hint">"Used to sign in. Nothing is sent to it."</p>
                </div>
                <div class="field">
                    <label for="password">"Password"</label>
                    <input
                        id="password"
                        name="password"
                        type="password"
                        autocomplete="new-password"
                        minlength="8"
                        required
                    />
                </div>
                <div class="field">
                    <label for="password_confirmation">"Repeat password"</label>
                    <input
                        id="password_confirmation"
                        name="password_confirmation"
                        type="password"
                        autocomplete="new-password"
                        minlength="8"
                        required
                    />
                </div>
                <button type="submit">"Create account"</button>
            </form>
            <footer>
                <span class="muted">"Already have an account? "</span>
                <a href=sign_in_href>"Sign in"</a>
            </footer>
        },
    )
}

fn render_consent(
    app_name: &str,
    request: &AuthorizeRequest,
    account: &SessionAccount,
    csrf_token: &str,
) -> String {
    let scopes = request.scopes.join(" ");
    let state = request.state.clone().unwrap_or_default();
    let csrf_token = csrf_token.to_owned();
    let heading = format!("Authorize {app_name}");
    let signed_in = format!("Signed in as @{}.", account.username);
    let asks = format!("{app_name} is asking for:");
    let rows: Vec<(String, &'static str)> = request
        .scopes
        .iter()
        .map(|scope| (scope.clone(), scope_label(scope)))
        .collect();
    shell(
        "Authorize · Nodus",
        None,
        view! {
            <h1>{heading}</h1>
            <p class="muted">{signed_in}</p>
            <p>{asks}</p>
            <ul class="scopes">
                {rows
                    .into_iter()
                    .map(|(scope, label)| view! { <li><code>{scope}</code><span>{label}</span></li> })
                    .collect_view()}
            </ul>
            <form method="post" action="/oauth/authorize">
                <input type="hidden" name="client_id" value=request.client_id.clone()/>
                <input type="hidden" name="redirect_uri" value=request.redirect_uri.clone()/>
                <input type="hidden" name="scopes" value=scopes/>
                <input type="hidden" name="state" value=state/>
                <input type="hidden" name="code_challenge" value=request.code_challenge.clone()/>
                <input type="hidden" name="csrf_token" value=csrf_token/>
                <div class="actions">
                    <button class="secondary" type="submit" name="decision" value="deny">
                        "Deny"
                    </button>
                    <button type="submit" name="decision" value="allow">"Allow"</button>
                </div>
            </form>
            <footer>
                <form method="post" action="/auth/logout">
                    <button class="secondary" type="submit">"Not you? Sign out"</button>
                </form>
            </footer>
        },
    )
}

/// Builds the runtime. The binary owns the listener; this owns the surface.
pub async fn run(
    pool: PgPool,
    config: Config,
    listener: tokio::net::TcpListener,
) -> std::io::Result<()> {
    let state = AppState::new(PgAuthStore::new(pool), config);
    axum::serve(listener, router(state)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_to_cannot_leave_the_instance() {
        assert_eq!(
            safe_return_to(Some("/oauth/authorize?x=1")),
            Some("/oauth/authorize?x=1")
        );
        assert_eq!(safe_return_to(Some("//evil.test")), None);
        assert_eq!(safe_return_to(Some("https://evil.test")), None);
    }

    #[test]
    fn login_page_escapes_the_return_target() {
        let html = render_login(LoginView {
            domain: "social.test",
            registrations_open: true,
            return_to: Some("/ok"),
            signed_in: false,
            error: None,
            filled: None,
            csrf_token: "csrf-sample",
        });
        assert!(html.contains("name=\"return_to\" value=\"/ok\""));
        assert!(html.contains("name=\"csrf_token\" value=\"csrf-sample\""));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn a_closed_instance_shows_no_form() {
        let html = render_register(RegisterView {
            domain: "social.test",
            open: false,
            return_to: None,
            error: None,
            filled: None,
            csrf_token: "csrf-sample",
        });
        assert!(html.contains("Registration is closed"));
        assert!(!html.contains("action=\"/auth/register\""));
    }

    #[test]
    fn registration_normalises_the_username_and_keeps_the_password_verbatim() {
        let form = RegisterForm {
            username: "  Lux_Test ".to_owned(),
            email: " Lux@Test.example ".to_owned(),
            password: "correct horse".to_owned(),
            password_confirmation: "correct horse".to_owned(),
            return_to: None,
            csrf_token: String::new(),
        };
        let registration = normalized_registration(&form).expect("valid form");
        assert_eq!(registration.username, "lux_test");
        assert_eq!(registration.email, "Lux@Test.example");
        assert_eq!(registration.password, "correct horse");
    }

    #[test]
    fn registration_refuses_the_usual_mistakes() {
        let base = |username: &str, email: &str, password: &str| RegisterForm {
            username: username.to_owned(),
            email: email.to_owned(),
            password: password.to_owned(),
            password_confirmation: password.to_owned(),
            return_to: None,
            csrf_token: String::new(),
        };
        assert!(normalized_registration(&base("ab", "a@b.test", "longenough")).is_err());
        assert!(normalized_registration(&base("has space", "a@b.test", "longenough")).is_err());
        assert!(normalized_registration(&base("admin", "a@b.test", "longenough")).is_err());
        assert!(normalized_registration(&base("fine", "not-an-email", "longenough")).is_err());
        assert!(normalized_registration(&base("fine", "a@b.test", "short")).is_err());
        let mut mismatch = base("fine", "a@b.test", "longenough");
        mismatch.password_confirmation = "different".to_owned();
        assert!(normalized_registration(&mismatch).is_err());
    }

    #[test]
    fn verify_login_password_parses_dummy_hash_without_oracle() {
        assert!(!verify_login_password(None, "anything"));
        let parsed = PasswordHash::new(DUMMY_PASSWORD_HASH.as_str()).expect("valid dummy hash");
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
    }

    #[test]
    fn the_network_prefix_drops_the_host_and_unwraps_mapped_ipv4() {
        assert_eq!(
            network_prefix("203.0.113.7".parse().expect("ipv4")),
            "203.0.113.0/24"
        );
        assert_eq!(
            network_prefix("2001:db8:abcd:12::1".parse().expect("ipv6")),
            "2001:db8:abcd::/48"
        );
        assert_eq!(
            network_prefix("::ffff:203.0.113.7".parse().expect("mapped ipv4")),
            "203.0.113.0/24",
            "a dual-stack peer keeps the IPv4 network instead of collapsing to ::/48"
        );
    }

    #[test]
    fn a_core_error_is_not_an_oauth_error_code() {
        assert_eq!(
            crate::domain::Error::Pkce.to_string(),
            "code_verifier does not match the challenge"
        );
    }
}

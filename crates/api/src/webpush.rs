//! Sending the notifications slice 1 stored: RFC 8291 `aes128gcm` encryption and VAPID.
//!
//! A push message is encrypted to the browser's own key (`p256dh`), authenticated with its
//! `auth` secret, and signed for the push service with the instance's VAPID key. Nothing
//! here reads a table the API may write; the queue lives in [`nodus_server_store::push`].
//!
//! The sender is a loop in this process, like the mail outbox. One dead endpoint is never
//! allowed to hold back the batch: each subscription is tried, its failure counted, and
//! the next one starts.

use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use base64::Engine;
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use p256::{EncodedPoint, PublicKey};
use sha2::Sha256;
use sqlx::PgPool;

use nodus_server_runtime::Vapid;
use nodus_server_store::push;

/// How many failed deliveries retire a subscription. Ten transient errors — a laptop
/// asleep for ten send windows — is long enough that a working browser is not dropped,
/// and short enough that a removed profile stops costing a request per notification.
pub const MAX_FAILURES: i32 = 10;

/// Seconds a push service may keep a message for a device that is offline.
const TTL_SECONDS: u32 = 3600;
/// The largest record this sender emits. One record holds the whole payload.
const RECORD_SIZE: u32 = 4096;
/// How often the queue is read when it is empty.
const POLL: Duration = Duration::from_secs(5);
/// How many queue rows one pass takes.
const BATCH: i64 = 20;
/// How long one push service is given before it counts as failed.
const TIMEOUT: Duration = Duration::from_secs(10);

/// What one pass did, for the log line and the tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeliveryReport {
    pub sent: usize,
    pub failed: usize,
    pub removed: usize,
}

/// Encrypts `payload` for one browser subscription, exactly as RFC 8291 section 3.3.
///
/// # Errors
///
/// Fails when either key is not base64url, when `p256dh` is not a P-256 point, or when the
/// AES-GCM primitive refuses the inputs. A malformed stored row fails only its own send.
pub fn encrypt(p256dh: &str, auth: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
    let ua_bytes = decode(p256dh).map_err(|error| format!("p256dh: {error}"))?;
    let ua_public = PublicKey::from_sec1_bytes(&ua_bytes)
        .map_err(|error| format!("p256dh is not a P-256 point: {error}"))?;
    let auth_secret = decode(auth).map_err(|error| format!("auth: {error}"))?;

    let ephemeral = EphemeralSecret::random(&mut OsRng);
    let as_public = EncodedPoint::from(ephemeral.public_key());
    let shared = ephemeral.diffie_hellman(&ua_public);

    // RFC 8291 section 3.4: the auth secret salts the ECDH output, and the two public
    // keys are the info that binds the result to this subscription and this sender.
    let mut auth_info = Vec::with_capacity(14 + ua_bytes.len() + as_public.len());
    auth_info.extend_from_slice(b"WebPush: info\x00");
    auth_info.extend_from_slice(&ua_bytes);
    auth_info.extend_from_slice(as_public.as_bytes());
    let ikm_hkdf = Hkdf::<Sha256>::new(Some(&auth_secret), shared.raw_secret_bytes());
    let mut ikm = [0u8; 32];
    ikm_hkdf
        .expand(&auth_info, &mut ikm)
        .map_err(|error| format!("key derivation failed: {error}"))?;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut cek = [0u8; 16];
    hkdf.expand(b"Content-Encoding: aes128gcm\x00", &mut cek)
        .map_err(|error| format!("content key derivation failed: {error}"))?;
    let mut nonce = [0u8; 12];
    hkdf.expand(b"Content-Encoding: nonce\x00", &mut nonce)
        .map_err(|error| format!("nonce derivation failed: {error}"))?;

    let mut header = Vec::with_capacity(16 + 4 + 1 + as_public.len());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    header.push(u8::try_from(as_public.len()).map_err(|_| "sender key is too long")?);
    header.extend_from_slice(as_public.as_bytes());

    // 0x02 is the last-record delimiter: no padding follows this payload.
    let mut plaintext = payload.to_vec();
    plaintext.push(0x02);
    let cipher = Aes128Gcm::new_from_slice(&cek).map_err(|error| error.to_string())?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|error| format!("payload could not be encrypted: {error}"))?;

    let mut body = header;
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

/// Sends every queued notification that is still owed.
///
/// A row is marked sent even when every subscription for it failed: the queue is a list of
/// notifications, not of endpoints, and a retry would repeat the same dead delivery. The
/// subscription's own failure counter is what remembers a bad endpoint.
///
/// # Errors
///
/// Fails only when the queue itself cannot be read or written. Per-endpoint errors are
/// counted on the subscription row.
pub async fn deliver_due(
    pool: &PgPool,
    vapid: &Vapid,
    limit: i64,
) -> Result<DeliveryReport, sqlx::Error> {
    let rows = push::due(pool, limit).await?;
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(|error| sqlx::Error::Protocol(format!("push client: {error}")))?;
    let mut report = DeliveryReport::default();

    for job in rows {
        let Some(notice) = push::notice(pool, &job.account_id, &job.notification_id).await? else {
            // The notification was deleted before it could be sent; there is nothing to
            // say and no reason to keep the row.
            push::mark_sent(pool, &job.id).await?;
            continue;
        };
        let payload = payload_for(&job.kind, &notice);
        let body = serde_json::to_vec(&payload).unwrap_or_default();

        let subscriptions = push::list(pool, &job.account_id).await?;
        for subscription in subscriptions {
            if !alert_enabled(&subscription.alerts, &job.kind) {
                continue;
            }
            match send_one(&client, vapid, &subscription, &body).await {
                Ok(()) => {
                    push::record_success(pool, &subscription.account_id, &subscription.endpoint)
                        .await?;
                    report.sent += 1;
                }
                Err(SendFailure::Gone) => {
                    push::delete(pool, &subscription.account_id, &subscription.endpoint).await?;
                    report.removed += 1;
                }
                Err(SendFailure::Failed(error)) => {
                    tracing::warn!(
                        endpoint = %subscription.endpoint,
                        %error,
                        "push delivery failed"
                    );
                    if let Some(row) =
                        push::record_failure(pool, &subscription.account_id, &subscription.endpoint)
                            .await?
                    {
                        if row.failure_count >= MAX_FAILURES {
                            push::delete(pool, &row.account_id, &row.endpoint).await?;
                            report.removed += 1;
                        }
                    }
                    report.failed += 1;
                }
            }
        }
        push::mark_sent(pool, &job.id).await?;
    }
    Ok(report)
}

/// The queue's delivery loop. The first pass runs immediately so a restart drains what was
/// queued while the previous process was exiting.
pub async fn run(pool: PgPool, vapid: Vapid) {
    let mut ticker = tokio::time::interval(POLL);
    loop {
        ticker.tick().await;
        match deliver_due(&pool, &vapid, BATCH).await {
            Ok(report) if report != DeliveryReport::default() => {
                tracing::info!(
                    sent = report.sent,
                    failed = report.failed,
                    removed = report.removed,
                    "push delivered"
                );
            }
            Ok(_) => {}
            Err(error) => tracing::error!(%error, "push queue could not be read"),
        }
    }
}

/// The JSON a service worker shows. `access_token` is omitted: a push subscription has no
/// per-device token, and inventing one would make a client present a credential this
/// instance never issued.
///
/// `tag` exists so a browser coalesces replacements instead of stacking them: two
/// notifications about the same thing share a tag and the second REPLACES the first; two
/// notifications about different things never share one, because a shared tag would
/// silently swallow the older notification. The target is the status for status kinds and
/// the actor's account for follow kinds; a kind with no target id in this row (an appeal,
/// a moderation notice, an admin report) uses the notification's own id, which can never
/// collide with another notification.
///
/// `renotify` makes a replacement alert again. Chrome replaces a same-tag notification
/// silently unless the new one sets it, so without it only the first favourite of a post
/// is ever heard. It is set for the kinds where a replacement is a new event and omitted
/// for the kinds where it is a duplicate of one fact. See [`renotify`].
fn payload_for(kind: &str, notice: &push::NoticeRow) -> serde_json::Value {
    let body = notice
        .note
        .as_deref()
        .or(notice.status_text.as_deref())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map_or_else(|| sentence(kind).to_owned(), str::to_owned);
    let mut payload = serde_json::json!({
        "title": notice.actor.as_deref().unwrap_or("Nodus"),
        "body": body,
        "tag": tag(kind, notice),
        "data": { "url": target_url(kind, notice) },
        "icon": crate::assets::ICON_PATH,
    });
    if renotify(kind) {
        payload["renotify"] = serde_json::Value::Bool(true);
    }
    payload
}

/// Whether a same-tag replacement should alert again.
///
/// `mention`: another reply is a different person's words — news.
/// `favourite`: another favouriter is a different person — news.
/// `reblog`: another booster is a different person — news.
/// `follow`: two notices about the same follower repeat one fact — not news, stay silent.
/// Every other kind keeps the conservative answer, alert: inheriting silence would drop a
/// notification the reader never saw, which is worse than one extra buzz.
fn renotify(kind: &str) -> bool {
    match kind {
        // A second notice about the same follower repeats one fact.
        "follow" => false,
        // Mention, favourite and reblog (and any kind added later): a replacement is a
        // new event from a different person, and silence would drop it.
        _ => true,
    }
}

/// The replacement key. Two notifications with the same key are about the same target and
/// the newer one wins in the browser; keys for different targets must not meet.
fn tag(kind: &str, notice: &push::NoticeRow) -> String {
    match kind {
        "mention" | "favourite" | "reblog" | "poll" | "status" | "update" => notice
            .status_id
            .as_deref()
            .map_or_else(|| notification_tag(notice), |id| format!("{kind}:{id}")),
        "follow" | "follow_request" | "admin.sign_up" => {
            format!("{kind}:{}", notice.from_account_id)
        }
        // An appeal, a moderation notice and an admin report carry no target id in this
        // row; the notification id is unique, so these never coalesce with anything.
        _ => notification_tag(notice),
    }
}

fn notification_tag(notice: &push::NoticeRow) -> String {
    format!("notification:{}", notice.id)
}

/// The path a click opens. A status notification opens the status's permalink (whichever
/// account wrote it), a follow opens the actor's profile, and a notice with no target page
/// opens the notification list. The path is relative because no base URL is known here;
/// the web client resolves it against its own origin.
fn target_url(kind: &str, notice: &push::NoticeRow) -> String {
    match kind {
        "mention" | "favourite" | "reblog" | "poll" | "status" | "update" => {
            match (notice.status_author.as_deref(), notice.status_id.as_deref()) {
                (Some(author), Some(id)) => format!("/@{author}/{id}"),
                _ => "/notifications".to_owned(),
            }
        }
        "follow" | "follow_request" => notice
            .actor_username
            .as_deref()
            .map_or_else(|| "/notifications".to_owned(), |name| format!("/@{name}")),
        _ => "/notifications".to_owned(),
    }
}

fn sentence(kind: &str) -> &'static str {
    match kind {
        "mention" => "You were mentioned",
        "reblog" => "Someone boosted your post",
        "follow" => "You have a new follower",
        "follow_request" => "You have a new follow request",
        "favourite" => "Someone favourited your post",
        "poll" => "A poll you voted in has ended",
        "status" => "Someone you follow posted",
        "update" => "A post you interacted with was edited",
        "admin.sign_up" => "A new account signed up",
        "admin.report" => "A new report needs moderation",
        _ => "You have a new notification",
    }
}

fn alert_enabled(alerts: &serde_json::Value, kind: &str) -> bool {
    alerts
        .get(kind)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

enum SendFailure {
    /// The push service says the subscription no longer exists.
    Gone,
    /// A transport or server error worth counting.
    Failed(String),
}

async fn send_one(
    client: &reqwest::Client,
    vapid: &Vapid,
    subscription: &push::SubscriptionRow,
    body: &[u8],
) -> Result<(), SendFailure> {
    let authorization = vapid
        .authorization(&subscription.endpoint)
        .map_err(SendFailure::Failed)?;
    let encrypted =
        encrypt(&subscription.p256dh, &subscription.auth, body).map_err(SendFailure::Failed)?;
    let response = client
        .post(&subscription.endpoint)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header(reqwest::header::CONTENT_ENCODING, "aes128gcm")
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .header("TTL", TTL_SECONDS.to_string())
        .body(encrypted)
        .send()
        .await
        .map_err(|error| SendFailure::Failed(error.to_string()))?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
        return Err(SendFailure::Gone);
    }
    Err(SendFailure::Failed(format!(
        "push service answered {status}"
    )))
}

fn decode(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare_notice() -> push::NoticeRow {
        push::NoticeRow {
            id: "notification:1".to_owned(),
            from_account_id: "actor".to_owned(),
            status_id: None,
            note: None,
            actor: None,
            actor_username: None,
            status_text: None,
            status_author: None,
        }
    }

    /// A kind the match has never seen must alert, not inherit the silent replacement a
    /// missing `renotify` gives.
    #[test]
    fn an_unknown_kind_alerts_rather_than_replacing_silently() {
        let payload = payload_for("kind.added.later", &bare_notice());
        assert_eq!(
            payload.get("renotify"),
            Some(&serde_json::Value::Bool(true))
        );
    }
}

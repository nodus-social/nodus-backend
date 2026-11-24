//! What a service is told when it starts.

use std::env;
use std::error::Error;

use nodus_server_core::instance::InstanceConfig;
use nodus_server_transport::Address;

/// The address a service takes when its unit says nothing. Every unit does say
/// something: this default exists so a developer can run a binary with no environment.
pub const DEFAULT_BIND: &str = "0.0.0.0:3000";
pub const DEFAULT_DATABASE_URL: &str = "postgres://nodus:nodus@localhost/nodus";

/// How long a deleted account stays recoverable before its profile is erased. Thirty days
/// balances a mistaken deletion against keeping a leaver's data longer than they asked.
pub const DEFAULT_ACCOUNT_DELETE_GRACE_DAYS: i64 = 30;

/// The software video encoder behind every `WebM` rendition (`NODUS_MEDIA_VIDEO_CODEC`).
///
/// VP8 is the default because this host has no hardware encoder: VP8 encodes several
/// times faster in software than VP9, and at the renditions we publish the quality and
/// size difference is small. VP9 is the opt-in for a host that can spend the time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    Vp8,
    Vp9,
}

/// The codec used when `NODUS_MEDIA_VIDEO_CODEC` says nothing.
pub const DEFAULT_VIDEO_CODEC: VideoCodec = VideoCodec::Vp8;

impl VideoCodec {
    /// Parse one `NODUS_MEDIA_VIDEO_CODEC` value.
    ///
    /// The error names both accepted values and the default: a typo must stop the
    /// process, not quietly pick a codec the operator did not ask for.
    ///
    /// # Errors
    ///
    /// Fails for anything but `vp8` or `vp9`, case-insensitively.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "vp8" => Ok(Self::Vp8),
            "vp9" => Ok(Self::Vp9),
            other => Err(format!(
                "NODUS_MEDIA_VIDEO_CODEC must be vp8 or vp9 (default vp8), not {other:?}"
            )),
        }
    }

    /// Read `NODUS_MEDIA_VIDEO_CODEC`, falling back to [`DEFAULT_VIDEO_CODEC`].
    ///
    /// # Errors
    ///
    /// Fails when the variable is set to a value [`Self::parse`] refuses.
    pub fn from_env() -> Result<Self, String> {
        match env::var("NODUS_MEDIA_VIDEO_CODEC") {
            Ok(value) => Self::parse(&value),
            Err(_) => Ok(DEFAULT_VIDEO_CODEC),
        }
    }

    /// Stable spelling, used in logs and in the error message.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vp8 => "vp8",
            Self::Vp9 => "vp9",
        }
    }
}

/// The VAPID identity every Web Push delivery is signed with.
///
/// The three variables are read once at startup. A key that is not a P-256 key is a
/// deployment mistake that can never deliver anything, so it stops the process here
/// rather than at the first notification; an instance with no key at all keeps running
/// and answers the subscription verbs `501`, because refusing mail-like optional
/// features must not take the whole API down.
#[derive(Clone)]
pub struct Vapid {
    public_key: String,
    subject: String,
    signing_key: p256::ecdsa::SigningKey,
}

impl std::fmt::Debug for Vapid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Vapid")
            .field("public_key", &self.public_key)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

/// The subject a VAPID JWT carries when `NODUS_VAPID_SUBJECT` says nothing.
const DEFAULT_VAPID_SUBJECT_DOMAIN: &str = "localhost";

impl Vapid {
    /// Reads `NODUS_VAPID_PUBLIC_KEY`, `NODUS_VAPID_PRIVATE_KEY` and
    /// `NODUS_VAPID_SUBJECT` (the last optional).
    ///
    /// # Errors
    ///
    /// Fails when only one of the two keys is set, or when either is not the base64url
    /// form of a matching P-256 key pair. The message names the variable.
    pub fn from_env(domain: &str) -> Result<Option<Self>, String> {
        let public = env::var("NODUS_VAPID_PUBLIC_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let private = env::var("NODUS_VAPID_PRIVATE_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let subject = env::var("NODUS_VAPID_SUBJECT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                let domain = if domain.trim().is_empty() {
                    DEFAULT_VAPID_SUBJECT_DOMAIN
                } else {
                    domain
                };
                format!("mailto:admin@{domain}")
            });
        match (public, private) {
            (None, None) => Ok(None),
            (Some(public), Some(private)) => Self::parse(&public, &private, &subject).map(Some),
            (None, Some(_)) => Err(
                "NODUS_VAPID_PUBLIC_KEY is not set but NODUS_VAPID_PRIVATE_KEY is; \
                 set both or neither"
                    .to_owned(),
            ),
            (Some(_), None) => Err(
                "NODUS_VAPID_PRIVATE_KEY is not set but NODUS_VAPID_PUBLIC_KEY is; \
                 set both or neither"
                    .to_owned(),
            ),
        }
    }

    /// Parses and validates one key pair. The two keys must belong together: a JWT signs
    /// with the private half while the header publishes the public half, so a mismatched
    /// pair would be rejected by every push service with no useful error here.
    ///
    /// # Errors
    ///
    /// Names the offending variable and what was wrong with it.
    pub fn parse(public: &str, private: &str, subject: &str) -> Result<Self, String> {
        let public_bytes = decode_key(public)
            .map_err(|error| format!("NODUS_VAPID_PUBLIC_KEY is not base64url: {error}"))?;
        p256::PublicKey::from_sec1_bytes(&public_bytes)
            .map_err(|error| format!("NODUS_VAPID_PUBLIC_KEY is not a P-256 point: {error}"))?;
        let private_bytes = decode_key(private)
            .map_err(|error| format!("NODUS_VAPID_PRIVATE_KEY is not base64url: {error}"))?;
        let secret = p256::SecretKey::from_slice(&private_bytes)
            .map_err(|error| format!("NODUS_VAPID_PRIVATE_KEY is not a P-256 scalar: {error}"))?;
        let signing_key = p256::ecdsa::SigningKey::from(secret);
        if signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            != public_bytes
        {
            return Err("NODUS_VAPID_PUBLIC_KEY does not match NODUS_VAPID_PRIVATE_KEY".to_owned());
        }
        Ok(Self {
            public_key: public.trim().to_owned(),
            subject: subject.to_owned(),
            signing_key,
        })
    }

    /// The value `GET /api/v1/push/subscription` returns as `server_key`.
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// The `Authorization` header value for one push service endpoint.
    ///
    /// # Errors
    ///
    /// Fails when the endpoint has no `scheme://host` origin to name as the audience.
    pub fn authorization(&self, endpoint: &str) -> Result<String, String> {
        let audience = origin_of(endpoint)
            .ok_or_else(|| format!("push endpoint is not an absolute URL: {endpoint}"))?;
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| format!("system clock is before the epoch: {error}"))?
            .as_secs()
            + 12 * 60 * 60;
        let header = serde_json::json!({"typ": "JWT", "alg": "ES256"});
        let claims = serde_json::json!({
            "aud": audience,
            "exp": expires,
            "sub": self.subject,
        });
        let signing_input = format!(
            "{}.{}",
            base64_url(&serde_json::to_vec(&header).map_err(|error| error.to_string())?),
            base64_url(&serde_json::to_vec(&claims).map_err(|error| error.to_string())?)
        );
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = self.signing_key.sign(signing_input.as_bytes());
        let token = format!("{signing_input}.{}", base64_url(&signature.to_bytes()));
        Ok(format!("vapid t={token},k={}", self.public_key))
    }
}

fn decode_key(value: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let value = value.trim();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .map_err(|error| error.to_string())
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// `scheme://host[:port]`, which is what a VAPID JWT names as its audience.
fn origin_of(endpoint: &str) -> Option<String> {
    let (scheme, rest) = endpoint.split_once("://")?;
    if scheme.is_empty() || rest.is_empty() {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "each switch is an independent deployment decision, not a state"
)]
pub struct Config {
    /// Where this service accepts requests. A socket or a port; the binaries do not care.
    pub bind: Address,
    pub database_url: String,
    pub database_connections: u32,
    pub instance: InstanceConfig,
    pub secure_cookies: bool,
    /// Whether `/auth/register` accepts new accounts. Off unless the operator opts in.
    pub registrations_open: bool,
    /// Whether `ActivityPub` reads require an HTTP signature (`NODUS_AUTHORIZED_FETCH`).
    /// Off unless the operator opts in, and read once so peers see one stable mode.
    pub authorized_fetch: bool,
    /// Whether an unconfirmed address may post or follow
    /// (`NODUS_REQUIRE_EMAIL_CONFIRMATION`). Off by default: turning it on without a
    /// sender would lock every new account out of a working instance.
    pub require_email_confirmation: bool,
    /// Days between an account deletion request and the purge of its profile and keys
    /// (`NODUS_ACCOUNT_DELETE_GRACE_DAYS`, default 30).
    pub account_delete_grace_days: i64,
    /// Encoder for `WebM` renditions (`NODUS_MEDIA_VIDEO_CODEC`, default VP8). Read once
    /// here so a typo fails startup instead of the first uploaded video.
    pub video_codec: VideoCodec,
    /// The Web Push signing identity (`NODUS_VAPID_*`). `None` means this instance
    /// cannot deliver push: the subscription verbs refuse rather than store a row that
    /// will never be sent.
    pub vapid: Option<Vapid>,
    pub migrate_only: bool,
    /// `TOKEN_ENC_KEY`, the base64 32-byte key that seals stored instance tokens.
    ///
    /// Left undecoded here because only the feed and calc processes use it; each parses
    /// it at boot so an unusable value stops that process, not every role. Absent means
    /// background sync cannot work, which the feed says out loud at startup.
    pub token_enc_key: Option<String>,
    pub bootstrap: Option<Bootstrap>,
    /// Where this process answers questions about itself, if anywhere.
    pub telemetry: Option<Address>,
}

#[derive(Debug, Clone)]
pub struct Bootstrap {
    pub email: String,
    pub username: String,
    pub password: String,
}

/// Read the process-wide settings, and the instance identity that every service needs
/// to build an absolute URL.
///
/// # Errors
///
/// Fails on an address that does not parse, a number that is not a number, or a
/// half-given bootstrap login — each of which is a deployment mistake that would
/// otherwise show up much later as a wrong link or a forgotten password.
pub fn read() -> Result<Config, Box<dyn Error>> {
    let bind = nodus_server_transport::parse(
        &env::var("NODUS_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_owned()),
    )?;
    read_with_bind(bind)
}

/// Read the process-wide settings with an explicit listen address.
///
/// The `aio` role runs two listeners in one process, so the rest of the environment is
/// read once per role but the address comes from `NODUS_BIND` for the API and
/// `NODUS_MEDIA_BIND` for media. Everything else is the environment a standalone service
/// reads.
///
/// # Errors
///
/// The same deployment mistakes [`read`] refuses: a number that is not a number, a
/// half-given bootstrap login, or two telemetry addresses at once.
pub fn read_with_bind(bind: Address) -> Result<Config, Box<dyn Error>> {
    let domain = env::var("NODUS_DOMAIN").unwrap_or_else(|_| "localhost".to_owned());
    let base_url = env::var("NODUS_BASE_URL")
        .unwrap_or_else(|_| format!("https://{domain}"))
        .trim_end_matches('/')
        .to_owned();
    let database_connections = env::var("NODUS_DATABASE_CONNECTIONS")
        .ok()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(10);
    let secure_cookies =
        env::var("NODUS_AUTH_SECURE_COOKIES").map_or(Ok(true), |value| value.parse())?;
    let registrations_open =
        env::var("NODUS_REGISTRATIONS_OPEN").map_or(Ok(false), |value| value.parse())?;
    let authorized_fetch =
        env::var("NODUS_AUTHORIZED_FETCH").map_or(Ok(false), |value| value.parse())?;
    let require_email_confirmation =
        env::var("NODUS_REQUIRE_EMAIL_CONFIRMATION").map_or(Ok(false), |value| value.parse())?;
    let account_delete_grace_days = env::var("NODUS_ACCOUNT_DELETE_GRACE_DAYS")
        .ok()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(DEFAULT_ACCOUNT_DELETE_GRACE_DAYS);
    let video_codec = VideoCodec::from_env()?;
    let vapid = Vapid::from_env(&domain)?;
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

    Ok(Config {
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
        authorized_fetch,
        require_email_confirmation,
        account_delete_grace_days,
        video_codec,
        vapid,
        migrate_only: env::args().any(|argument| argument == "--migrate-only"),
        token_enc_key: env::var("TOKEN_ENC_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        bootstrap,
        telemetry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_video_codec_names_every_accepted_value_and_the_default() {
        let error = VideoCodec::parse("vp10").expect_err("a typo must be refused");
        assert_eq!(
            error,
            "NODUS_MEDIA_VIDEO_CODEC must be vp8 or vp9 (default vp8), not \"vp10\""
        );
    }

    #[test]
    fn the_video_codec_parser_accepts_both_names_case_insensitively() {
        assert_eq!(VideoCodec::parse("VP8"), Ok(VideoCodec::Vp8));
        assert_eq!(VideoCodec::parse("vp9\n"), Ok(VideoCodec::Vp9));
    }
}

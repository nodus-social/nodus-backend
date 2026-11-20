//! The scanner contract.
//!
//! A scanner is **headless**: it reports what it sees and says nothing about policy. It
//! never decides that content is a violation, never picks a severity and never removes
//! anything. An administrator decides, once per label, how sure the scanner must be
//! before a label means something and how bad that something is. That split is what keeps
//! a scanner swapping-safe: upgrading a model, or replacing a hash matcher with a
//! classifier, changes the signals an instance receives but not the rules it applied to
//! them.
//!
//! The contract is deliberately small, because a scanner is often a stranger's model:
//!
//! ```text
//! GET  <endpoint>/v1/manifest
//! 200  {"contract":1,"name":"nsfw-1","version":"1.2.0","kind":"image",
//!       "labels":[{"name":"nsfw","description":"adult imagery","severity":"sensitive"}],
//!       "models":["mobilenet_v2"],"config":{}}
//!
//! POST <endpoint>/v1/scan        Authorization: Bearer <secret>   (when configured)
//! {"contract":1,"id":"…","kind":"image","url":"…","text":null,"mime":"image/png",
//!  "alt":"…","metadata":{}}
//!
//! 200  {"labels":[{"name":"nsfw","score":0.93},{"name":"is-art","score":0.71}],"detail":{}}
//! ```
//!
//! A label may be written as a bare string when the scanner has no confidence to report
//! (a hash match either happens or it does not); that scores as `1.0`. `detail` is opaque
//! and stored for the moderator, never interpreted.
//!
//! A scanner that cannot answer must answer with a non-2xx status, not an empty body.
//!
//! The crate also holds the process around that contract — [`run`], the sweep that applies
//! scanner answers, and the control listener — so `nodus-scan` and `nodus scan` start the
//! same service rather than two copies of it. The contract itself knows nothing about
//! storage; the part that does lives beside it.

mod sweep;

pub mod run;

pub use run::run;

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// The largest answer worth reading. A scanner that needs more than this is not answering
/// a yes/no question, and the sweep will not hold the connection open for it.
const MAX_ANSWER_BYTES: usize = 64 * 1024;

/// The contract version. A scanner refuses a caller it does not understand, and the
/// instance refuses a manifest it does not understand, so the two can be upgraded
/// independently.
pub const CONTRACT: u32 = 1;

/// What the instance asks about.
#[derive(Debug, Clone, Serialize)]
pub struct Request<'a> {
    pub contract: u32,
    /// The scan id: lets a scanner log, deduplicate or rate-limit per request.
    pub id: &'a str,
    pub kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt: Option<&'a str>,
    pub metadata: Value,
}

impl<'a> Request<'a> {
    #[must_use]
    pub fn new(id: &'a str, kind: &'a str) -> Self {
        Self {
            contract: CONTRACT,
            id,
            kind,
            url: None,
            text: None,
            mime: None,
            alt: None,
            metadata: Value::Null,
        }
    }

    #[must_use]
    pub fn url(mut self, url: &'a str) -> Self {
        self.url = Some(url);
        self
    }

    #[must_use]
    pub fn text(mut self, text: &'a str) -> Self {
        self.text = Some(text);
        self
    }

    #[must_use]
    pub fn mime(mut self, mime: &'a str) -> Self {
        self.mime = Some(mime);
        self
    }

    #[must_use]
    pub fn alt(mut self, alt: &'a str) -> Self {
        self.alt = Some(alt);
        self
    }
}

/// One thing a scanner thinks it saw, and how sure it is.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum Signal {
    Scored { name: String, score: f32 },
    Bare(String),
}

impl Signal {
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Scored { name, .. } | Self::Bare(name) => name,
        }
    }

    #[must_use]
    pub fn score(&self) -> f32 {
        match self {
            Self::Scored { score, .. } => *score,
            Self::Bare(_) => 1.0,
        }
    }
}

/// What a scanner reported. No verdict, no severity: those are the instance's to decide.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Response {
    #[serde(default)]
    pub labels: Vec<Signal>,
    #[serde(default)]
    pub detail: Value,
}

/// A label a scanner can emit, as advertised in its manifest.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Label {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// What the scanner's author thinks this label usually means. A starting point for the
    /// administrator's rules, never a policy of its own.
    #[serde(default)]
    pub severity: Option<Severity>,
}

/// The strongest thing a label justifies, as configured by an administrator.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Record the signal and do nothing: the label is noise on this instance.
    #[default]
    Ignore,
    /// Worth a moderator's attention; the content stays up.
    Flag,
    /// The content stays up but is marked adult.
    Sensitive,
    /// The content does not stay up.
    Block,
}

impl Severity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ignore => "ignore",
            Self::Flag => "flag",
            Self::Sensitive => "sensitive",
            Self::Block => "block",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value {
            "ignore" | "none" => Self::Ignore,
            "sensitive" => Self::Sensitive,
            "block" => Self::Block,
            _ => Self::Flag,
        }
    }

    /// The more severe of two. Rules for different labels can both match one piece of
    /// content; the strictest answer wins, because under-reacting is the expensive mistake.
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        if other > self {
            other
        } else {
            self
        }
    }
}

/// What a scanner says it can do. Read when a scanner is registered, and again whenever
/// an administrator asks for a refresh, so a changed label vocabulary is visible instead
/// of silently altering results.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    #[serde(default = "contract_version")]
    pub contract: u32,
    pub name: String,
    #[serde(default)]
    pub version: String,
    /// `image`, `video` or `text`; must match the kind the instance registered it as.
    pub kind: String,
    #[serde(default)]
    pub labels: Vec<Label>,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub config: Value,
}

fn contract_version() -> u32 {
    CONTRACT
}

impl Manifest {
    pub fn check(&self, kind: &str) -> Result<(), Error> {
        if self.contract != CONTRACT {
            return Err(Error::Invalid(format!(
                "the scanner speaks contract {}, this instance speaks {CONTRACT}",
                self.contract
            )));
        }
        if self.kind != kind {
            return Err(Error::Invalid(format!(
                "the scanner scans {} content, it was registered for {kind}",
                self.kind
            )));
        }
        if self.labels.is_empty() {
            return Err(Error::Invalid(
                "the scanner's manifest lists no labels, so no rule could ever match".to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn label_names(&self) -> Vec<String> {
        self.labels.iter().map(|label| label.name.clone()).collect()
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Transport(String),
    #[error("{0}")]
    Status(String),
    #[error("{0}")]
    Invalid(String),
}

/// How the instance talks to scanners.
///
/// One variant today. A gRPC arm slots in beside `Http` without touching the sweep, the
/// rules or the review queue: everything above this enum is transport-agnostic on
/// purpose, because the scanners are first-party services and the wire format is an
/// implementation detail of how they are deployed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Transport {
    Http(Http),
}

impl Transport {
    pub fn new() -> Result<Self, Error> {
        Ok(Self::Http(Http::new()?))
    }

    pub async fn ask(
        &self,
        endpoint: &str,
        secret: Option<&str>,
        timeout: Duration,
        request: &Request<'_>,
    ) -> Result<Response, Error> {
        match self {
            Self::Http(http) => http.ask(endpoint, secret, timeout, request).await,
        }
    }

    pub async fn manifest(
        &self,
        endpoint: &str,
        secret: Option<&str>,
        timeout: Duration,
    ) -> Result<Manifest, Error> {
        match self {
            Self::Http(http) => http.manifest(endpoint, secret, timeout).await,
        }
    }
}

/// One reusable HTTP client. Reusing it keeps TLS handshakes out of the sweep's latency.
#[derive(Debug, Clone)]
pub struct Http {
    http: reqwest::Client,
}

impl Http {
    pub fn new() -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("nodus-scan/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::Transport(format!("could not build an HTTP client: {e}")))?;
        Ok(Self { http })
    }

    /// Asks one scanner. The timeout is the scanner row's own: a slow local model and a
    /// remote service deserve different patience.
    pub async fn ask(
        &self,
        endpoint: &str,
        secret: Option<&str>,
        timeout: Duration,
        request: &Request<'_>,
    ) -> Result<Response, Error> {
        let url = scan_url(endpoint);
        let body = self
            .call(self.http.post(&url).timeout(timeout).json(request), secret)
            .await?;
        serde_json::from_str::<Response>(&body).map_err(|e| {
            Error::Invalid(format!(
                "{url} answered something that is not a scan result: {e}"
            ))
        })
    }

    pub async fn manifest(
        &self,
        endpoint: &str,
        secret: Option<&str>,
        timeout: Duration,
    ) -> Result<Manifest, Error> {
        let url = manifest_url(endpoint);
        let body = self
            .call(self.http.get(&url).timeout(timeout), secret)
            .await?;
        serde_json::from_str::<Manifest>(&body)
            .map_err(|e| Error::Invalid(format!("{url} is not a scanner manifest: {e}")))
    }

    async fn call(
        &self,
        call: reqwest::RequestBuilder,
        secret: Option<&str>,
    ) -> Result<String, Error> {
        let call = match secret {
            Some(secret) => call.bearer_auth(secret),
            None => call,
        };
        let response = call
            .send()
            .await
            .map_err(|e| Error::Transport(describe(&e)))?;
        let status = response.status();
        let url = response.url().clone();
        let body = read_capped(response).await?;
        if !status.is_success() {
            let reason = body.trim();
            return Err(Error::Status(if reason.is_empty() {
                format!("{url} answered {status}")
            } else {
                format!("{url} answered {status}: {}", truncate(reason, 200))
            }));
        }
        Ok(body)
    }
}

/// A registered endpoint is the service root; the routes are the contract's, not the
/// administrator's, so they are appended rather than typed into the settings form.
fn scan_url(endpoint: &str) -> String {
    format!("{}/v1/scan", endpoint.trim_end_matches('/'))
}

fn manifest_url(endpoint: &str) -> String {
    format!("{}/v1/manifest", endpoint.trim_end_matches('/'))
}

async fn read_capped(mut response: reqwest::Response) -> Result<String, Error> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Error::Transport(describe(&e)))?
    {
        if body.len() + chunk.len() > MAX_ANSWER_BYTES {
            return Err(Error::Invalid(
                "the scanner's answer was too large to read".to_owned(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body)
        .map_err(|_| Error::Invalid("the scanner's answer was not text".to_owned()))
}

/// `reqwest`'s error display hides the useful part (a connect timeout prints as "error
/// sending request"); the source chain is where "connection refused" lives.
fn describe(error: &reqwest::Error) -> String {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    truncate(&message, 300)
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let kept: String = text.chars().take(max).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_label_scores_as_certain() {
        let response: Response =
            serde_json::from_str(r#"{"labels":["known-hash"]}"#).expect("parses");
        assert_eq!(response.labels[0].name(), "known-hash");
        assert!((response.labels[0].score() - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn a_scored_label_keeps_its_confidence() {
        let response: Response =
            serde_json::from_str(r#"{"labels":[{"name":"nsfw","score":0.93}]}"#).expect("parses");
        assert_eq!(response.labels[0].name(), "nsfw");
        assert!((response.labels[0].score() - 0.93).abs() < 0.001);
    }

    #[test]
    fn an_empty_answer_reports_nothing_rather_than_clearing_content() {
        let response: Response = serde_json::from_str("{}").expect("an empty object parses");
        assert!(
            response.labels.is_empty(),
            "an empty answer carries no labels"
        );
    }

    #[test]
    fn the_stricter_of_two_rules_wins() {
        assert_eq!(Severity::Flag.or(Severity::Block), Severity::Block);
        assert_eq!(Severity::Block.or(Severity::Flag), Severity::Block);
        assert_eq!(Severity::Sensitive.or(Severity::Flag), Severity::Sensitive);
        assert_eq!(Severity::Ignore.or(Severity::Ignore), Severity::Ignore);
        assert_eq!(Severity::Ignore.or(Severity::Flag), Severity::Flag);
    }

    #[test]
    fn severity_names_round_trip() {
        for severity in [
            Severity::Ignore,
            Severity::Flag,
            Severity::Sensitive,
            Severity::Block,
        ] {
            assert_eq!(Severity::parse(severity.as_str()), severity);
        }
        assert_eq!(Severity::parse("none"), Severity::Ignore);
        assert_eq!(Severity::parse("senstive"), Severity::Flag);
    }

    #[test]
    fn a_manifest_must_agree_with_its_registration() {
        let manifest = Manifest {
            contract: CONTRACT,
            name: "nsfw".to_owned(),
            version: "1".to_owned(),
            kind: "image".to_owned(),
            labels: vec![Label {
                name: "nsfw".to_owned(),
                description: None,
                severity: Some(Severity::Sensitive),
            }],
            models: Vec::new(),
            config: Value::Null,
        };
        assert!(manifest.check("image").is_ok());
        assert!(manifest.check("text").is_err());

        let wrong = Manifest {
            contract: CONTRACT + 1,
            ..manifest
        };
        assert!(wrong.check("image").is_err());
    }

    #[test]
    fn a_manifest_without_labels_is_refused() {
        let manifest: Manifest =
            serde_json::from_str(r#"{"name":"empty","kind":"text","labels":[]}"#).expect("parses");
        assert!(manifest.check("text").is_err());
    }

    #[test]
    fn routes_are_appended_to_the_registered_root() {
        assert_eq!(
            scan_url("http://127.0.0.1:8080/"),
            "http://127.0.0.1:8080/v1/scan"
        );
        assert_eq!(
            manifest_url("http://127.0.0.1:8080"),
            "http://127.0.0.1:8080/v1/manifest"
        );
    }

    #[test]
    fn a_request_omits_what_it_does_not_have() {
        let request = Request::new("01J", "image");
        let encoded = serde_json::to_string(&request).expect("serialises");
        assert!(!encoded.contains("url"), "{encoded}");
        assert!(encoded.contains(r#""contract":1"#), "{encoded}");
    }
}

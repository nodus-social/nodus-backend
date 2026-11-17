//! What a deployment calls itself.
//!
//! Every service builds absolute links, so the identity of the instance is a value type
//! in the shared crate rather than something the API owns and the other services copy.

/// What this deployment calls itself.
#[derive(Debug, Clone)]
pub struct InstanceConfig {
    /// The domain users see in `@user@domain`, without scheme.
    pub domain: String,
    /// Absolute base URL for generated links, no trailing slash.
    pub base_url: String,
    pub title: String,
    pub description: String,
    pub contact_email: Option<String>,
    /// Version we advertise as the Mastodon API generation (docs/07-decisions.md D11).
    pub api_version: String,
    /// Our own build, reported separately so it never confuses a client.
    pub version: String,
    /// Whether `/auth/register` accepts new accounts, mirrored into the instance
    /// payloads so a client knows whether to offer a sign-up link.
    pub registrations_open: bool,
}

impl InstanceConfig {
    /// The `acct` form of a local username.
    #[must_use]
    pub fn acct(&self, username: &str) -> String {
        format!("{username}@{}", self.domain)
    }

    /// Absolute URL for a path.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }
}

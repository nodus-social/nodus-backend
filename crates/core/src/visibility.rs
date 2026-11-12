//! Who is allowed to see a status.
//!
//! The enum exists so that "does this reach the public timeline" is answered once,
//! here, instead of in each timeline query. The `home`-timeline rule is deliberately
//! *not* "everything except direct": a direct message is visible to its author and
//! to the mentioned accounts, which is a membership test no visibility value can
//! answer on its own.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The four values Mastodon's client API accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// In the author's followers' home timelines, and in public timelines.
    Public,
    /// In followers' home timelines, not in public timelines, but no login required
    /// to read a status page.
    Unlisted,
    /// Followers only.
    Private,
    /// Only the author and the mentioned accounts.
    Direct,
}

impl Visibility {
    /// Every value, in the order Mastodon documents them.
    pub const ALL: [Self; 4] = [Self::Public, Self::Unlisted, Self::Private, Self::Direct];

    /// The wire value used by the client API and by ActivityPub's `to` mapping.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Unlisted => "unlisted",
            Self::Private => "private",
            Self::Direct => "direct",
        }
    }

    /// Appears in `/timelines/public` and `/timelines/tag/:tag`.
    ///
    /// Unlisted is excluded on purpose: that is the entire difference between
    /// unlisted and public.
    #[must_use]
    pub fn in_public_timeline(self) -> bool {
        matches!(self, Self::Public)
    }

    /// Appears in a follower's `/timelines/home`.
    ///
    /// Direct is excluded: it reaches its mentions, not the followers at large.
    #[must_use]
    pub fn in_home_timeline(self) -> bool {
        matches!(self, Self::Public | Self::Unlisted | Self::Private)
    }

    /// Whether an unauthenticated reader may fetch the status page at all.
    #[must_use]
    pub fn readable_without_auth(self) -> bool {
        matches!(self, Self::Public | Self::Unlisted)
    }

    /// Whether the status may be boosted.
    #[must_use]
    pub fn boostable(self) -> bool {
        matches!(self, Self::Public | Self::Unlisted)
    }

    /// Whether federation should include the author's followers collection in `to`.
    #[must_use]
    pub fn addressed_to_followers(self) -> bool {
        matches!(self, Self::Public | Self::Unlisted | Self::Private)
    }
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The value a client sent is not one we accept.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("visibility must be one of public, unlisted, private, direct")]
pub struct UnknownVisibility;

impl FromStr for Visibility {
    type Err = UnknownVisibility;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "public" => Ok(Self::Public),
            "unlisted" => Ok(Self::Unlisted),
            "private" => Ok(Self::Private),
            "direct" => Ok(Self::Direct),
            _ => Err(UnknownVisibility),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_timeline_is_public_only() {
        let seen: Vec<&str> = Visibility::ALL
            .into_iter()
            .filter(|v| v.in_public_timeline())
            .map(Visibility::as_str)
            .collect();
        assert_eq!(seen, vec!["public"]);
    }

    #[test]
    fn a_direct_status_is_neither_public_nor_a_timeline_post() {
        assert!(!Visibility::Direct.in_public_timeline());
        assert!(!Visibility::Direct.in_home_timeline());
        assert!(!Visibility::Direct.readable_without_auth());
        assert!(!Visibility::Direct.addressed_to_followers());
    }

    #[test]
    fn unlisted_is_readable_but_not_boostable_into_oblivion() {
        // An unlisted status must not become public by being boosted: that would let
        // a stranger republish it, which is exactly what the author opted out of.
        assert!(Visibility::Unlisted.readable_without_auth());
        assert!(Visibility::Unlisted.boostable());
        assert!(!Visibility::Unlisted.in_public_timeline());
    }

    #[test]
    fn the_wire_form_round_trips() {
        for value in Visibility::ALL {
            assert_eq!(value.as_str().parse::<Visibility>(), Ok(value));
            assert_eq!(
                serde_json::to_string(&value).expect("serialise"),
                format!("\"{}\"", value.as_str())
            );
        }
        assert_eq!("friends".parse::<Visibility>(), Err(UnknownVisibility));
    }
}

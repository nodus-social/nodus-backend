//! Opaque object ids.
//!
//! A ULID is 128 bits: 48 bits of milliseconds and 80 bits of randomness, rendered
//! as 26 Crockford base32 characters. Two properties matter to us and both are
//! load-bearing:
//!
//! * **Lexicographic order equals creation order**, so `id > $cursor` is a correct
//!   `since_id` query with one index and no second sort key.
//! * **Any replica can mint one** without coordinating, which a sequence cannot.
//!
//! Ids are opaque to clients: nothing outside this module may assume anything about
//! their contents.

use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ulid::Ulid;

/// Monotonicity inside a millisecond needs shared state, so the generator is a
/// process-wide singleton. A `Mutex` is fine here: minting an id is nanoseconds and
/// never happens on a hot path more than once per row.
static GENERATOR: Mutex<Option<ulid::Generator>> = Mutex::new(None);

/// An opaque object id, rendered lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id(Ulid);

impl Id {
    /// Mints a new id, monotonic within the process.
    pub fn new() -> Self {
        let mut guard = GENERATOR
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let generator = guard.get_or_insert_with(ulid::Generator::new);
        generator.generate().map_or_else(|_| Ulid::new(), Ulid::from).into()
    }

    /// The raw 128 bits, for a database that stores ids as `bytea` or `uuid`.
    #[must_use]
    pub fn as_u128(self) -> u128 {
        self.0.0
    }

    /// Milliseconds since the Unix epoch encoded in the id. Used by tests and by
    /// cursors that need a timestamp without a second column.
    #[must_use]
    pub fn timestamp_ms(self) -> u64 {
        self.0.timestamp_ms()
    }
}

impl Default for Id {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Ulid` renders uppercase; the API promises lowercase.
        write!(f, "{}", self.0.to_string().to_ascii_lowercase())
    }
}

impl FromStr for Id {
    type Err = ulid::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ulid::from_str(s).map(Self)
    }
}

impl From<Ulid> for Id {
    fn from(value: Ulid) -> Self {
        Self(value)
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_lowercase_and_26_characters() {
        let id = Id::new();
        let rendered = id.to_string();
        assert_eq!(rendered.len(), 26);
        assert!(rendered.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_eq!(Id::from_str(&rendered).expect("round trip"), id);
    }

    #[test]
    fn ids_minted_in_the_same_millisecond_still_sort() {
        // The monotonic component is the whole reason this test exists: without it
        // two ids in one millisecond can invert, and `max_id` pages backwards.
        let ids: Vec<Id> = (0..1_000).map(|_| Id::new()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn a_cursor_survives_json_as_a_string() {
        let id = Id::new();
        let json = serde_json::to_string(&id).expect("serialise");
        assert_eq!(json, format!("\"{id}\""));
        assert_eq!(serde_json::from_str::<Id>(&json).expect("deserialise"), id);
    }

    #[test]
    fn garbage_is_rejected_rather_than_coerced() {
        assert!(Id::from_str("not-an-id").is_err());
        assert!(Id::from_str("").is_err());
        // 26 characters, but `I` and `L` are excluded from Crockford's alphabet.
        assert!(Id::from_str("01ARZ3NDEKTSV4RRFFQ69G5FAI").is_err());
    }
}

//! The name/value rows a profile publishes beside its name and bio.
//!
//! They are stored in `account.fields`, the jsonb column the client API already returns,
//! in Mastodon's shape: an array of `{ "name", "value", "verified_at" }`. A save replaces
//! the whole array because a reader edits a list, not six independent columns; a row whose
//! pair did not change keeps its `verified_at`, since verification belongs to the link and
//! not to the save that happened to leave it alone.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::{ApiError, ApiResult};

/// The most rows a profile may publish.
///
/// Mastodon stops its editor at four; six is the most a profile card can show without
/// turning the page into a table, and it is the number the API documents.
pub const PROFILE_FIELDS_MAX: usize = 6;

/// Characters allowed in a row's name, and in its value, after trimming.
pub const PROFILE_FIELD_MAX_CHARS: usize = 255;

/// One row as a client sends it.
///
/// Both members default so a row that is only half filled reaches the validator and gets
/// a named error, instead of failing in the deserialiser with a message about JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct ProfileFieldInput {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

/// Validates the rows a client sent and turns them into the stored array.
///
/// `current` is the array already stored for this account: it is read only for the pairs
/// that are still present, so a verified link stays verified when another row changes.
pub fn to_stored(input: &[ProfileFieldInput], current: &Value) -> ApiResult<Value> {
    if input.len() > PROFILE_FIELDS_MAX {
        return Err(ApiError::unprocessable(format!(
            "a profile has at most {PROFILE_FIELDS_MAX} fields; {} were sent",
            input.len()
        )));
    }
    let verified = verified_pairs(current);
    let mut stored = Vec::with_capacity(input.len());
    // The trimmed, lowercased name with the row number that first used it, so a repeat can
    // name both rows instead of only the one that lost.
    let mut seen: Vec<(String, usize)> = Vec::with_capacity(input.len());
    for (index, field) in input.iter().enumerate() {
        let number = index + 1;
        let name = field.name.trim();
        let value = field.value.trim();
        if name.is_empty() && value.is_empty() {
            // An untouched row in the editor form, not a field the reader asked for.
            continue;
        }
        if name.is_empty() {
            return Err(ApiError::unprocessable(format!(
                "profile field {number} needs a name"
            )));
        }
        check_length(number, "name", name)?;
        check_length(number, "value", value)?;
        if has_markup(name) || has_markup(value) {
            return Err(ApiError::unprocessable(format!(
                "profile field {number} must be plain text, without HTML"
            )));
        }
        let key = name.to_lowercase();
        if let Some((_, first)) = seen.iter().find(|(seen, _)| *seen == key) {
            return Err(ApiError::unprocessable(format!(
                "profile fields {first} and {number} are both named \u{201c}{name}\u{201d}"
            )));
        }
        seen.push((key, number));
        let verified_at = verified
            .iter()
            .find(|(verified_name, verified_value, _)| {
                verified_name == name && verified_value == value
            })
            .map_or(Value::Null, |(_, _, at)| at.clone());
        stored.push(json!({ "name": name, "value": value, "verified_at": verified_at }));
    }
    Ok(Value::Array(stored))
}

fn check_length(number: usize, part: &str, text: &str) -> ApiResult<()> {
    if text.chars().count() > PROFILE_FIELD_MAX_CHARS {
        return Err(ApiError::unprocessable(format!(
            "profile field {number}'s {part} must be at most {PROFILE_FIELD_MAX_CHARS} characters"
        )));
    }
    Ok(())
}

/// Whether a value carries markup.
///
/// The rest of the API answers markup by sanitising it, because a post is HTML. A profile
/// row is not: it is a label and a short plain-text value, and a value that carries a tag
/// is a mistake the reader can fix, so it is refused rather than silently rewritten.
fn has_markup(text: &str) -> bool {
    text.contains('<') || text.contains('>')
}

/// The rows of a stored array that carry a verification time, as (name, value, time).
fn verified_pairs(current: &Value) -> Vec<(String, String, Value)> {
    let Some(rows) = current.as_array() else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|row| {
            let at = row.get("verified_at").filter(|at| !at.is_null())?;
            Some((
                row.get("name")?.as_str()?.to_owned(),
                row.get("value")?.as_str()?.to_owned(),
                at.clone(),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(name: &str, value: &str) -> ProfileFieldInput {
        ProfileFieldInput {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }

    #[test]
    fn trims_names_and_values_and_drops_empty_rows() {
        let stored = to_stored(
            &[
                input("  Blog ", " https://example.test "),
                input("  ", "  "),
            ],
            &Value::Null,
        )
        .expect("valid fields");
        assert_eq!(
            stored,
            json!([{ "name": "Blog", "value": "https://example.test", "verified_at": null }])
        );
    }

    #[test]
    fn a_repeated_name_is_refused_by_both_numbers() {
        let error = to_stored(
            &[input("Blog", "a"), input("Site", "b"), input("blog", "c")],
            &Value::Null,
        )
        .expect_err("duplicate name");
        assert!(
            error.message().contains("fields 1 and 3"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn markup_is_refused_in_a_value() {
        let error = to_stored(&[input("Blog", "<b>hi</b>")], &Value::Null).expect_err("markup");
        assert!(
            error.message().contains("plain text"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn a_verified_pair_keeps_its_verification_time() {
        let current = json!([{
            "name": "Blog",
            "value": "https://example.test",
            "verified_at": "2026-01-01T00:00:00Z"
        }]);
        let stored = to_stored(
            &[
                input("Blog", "https://example.test"),
                input("Pronouns", "they/them"),
            ],
            &current,
        )
        .expect("valid fields");
        assert_eq!(stored[0]["verified_at"], json!("2026-01-01T00:00:00Z"));
        assert_eq!(stored[1]["verified_at"], Value::Null);
    }
}

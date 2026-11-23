//! The banner regions an account publishes for other readers.
//!
//! A session style is the owner's arrangement: navigation layout, rail modules and
//! categories are private and stay in `account.client_metadata`, which is served only to
//! that account's own token. What another reader may draw on a profile is narrower: the
//! top, left and right banners, each one's split direction, its ordered pictures, and
//! whether the banner is hidden. That narrower document is what this module stores and
//! serves.
//!
//! One row per account, replaced wholesale by [`publish`]. A picture its owner dropped
//! from the list is therefore absent for every viewer on the next read; merging would keep
//! drawing a banner that was removed.
//!
//! [`StylePublic::cleaned`] is the boundary check. The shell already sanitises what it
//! sends, but the write route accepts any token holding `write:accounts`, so a value the
//! shell would have cleaned must not be stored as though its owner had chosen it.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// The most pictures one banner may publish.
///
/// The editor currently offers fewer; this is the ceiling the boundary enforces, so a
/// layout that adds a slot later does not also need a migration.
pub const MAX_SLOTS_PER_REGION: usize = 6;

/// The longest banner picture description, in characters. Short enough to read under a
/// picture without the banner growing to fit the description.
pub const MAX_ALT_CHARS: usize = 200;

/// The longest media id, in characters. The shell's own id field is capped at this, and a
/// published document is meant to round-trip through its editor.
pub const MAX_MEDIA_ID_CHARS: usize = 48;

/// The total text one published style may carry, in bytes, across every URL, description
/// and media id.
///
/// Addresses are the only text here with no per-field cap: a media host may sign a URL
/// that is a few hundred bytes long. Capping their sum keeps one account from turning a
/// profile into a download while still allowing eighteen long addresses.
pub const MAX_PUBLISHED_TEXT_BYTES: usize = 8 * 1024;

/// How a banner divides its space between its pictures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitDirection {
    /// Pictures sit side by side.
    #[default]
    Horizontal,
    /// Pictures sit one above another.
    Vertical,
}

/// One picture in a banner, with what a reader needs to draw and describe it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slot {
    /// An absolute `http(s)` address or a path on this instance.
    pub url: String,
    /// The description a reader hears instead of the picture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt: Option<String>,
    /// The uploaded media this picture came from, when it did. Kept so the editor can
    /// tell a picture it still holds from one that only survives as an address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_id: Option<String>,
    /// Whether the picture is marked sensitive. A viewer's client decides how to reveal
    /// it; the server only carries the choice.
    #[serde(default)]
    pub sensitive: bool,
}

/// One of the three banners, in the owner's order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Region {
    #[serde(default)]
    pub split: SplitDirection,
    #[serde(default)]
    pub slots: Vec<Slot>,
    /// Whether the owner hid this banner. A hidden banner is still published: the choice
    /// to hide it belongs to the account, and a viewer draws an empty region rather than
    /// a different layout.
    #[serde(default)]
    pub hidden: bool,
}

/// What one account publishes about its style, and nothing more.
///
/// The three field names are the three banner positions the shell knows; there is no key
/// here for navigation layout, modules or categories, and `deny_unknown_fields` refuses a
/// request that tries to add one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StylePublic {
    #[serde(default)]
    pub top: Region,
    #[serde(default)]
    pub left: Region,
    #[serde(default)]
    pub right: Region,
}

impl StylePublic {
    /// Trims, sanitises and checks every picture, returning the document that will be
    /// stored.
    ///
    /// Over-long descriptions and ids are refused rather than cut: a description that
    /// silently lost its ending describes the wrong picture, and a truncated media id
    /// names nothing. Control characters are stripped, as the shell strips them, because
    /// they cannot be drawn and would only make two edits of the same picture differ.
    pub fn cleaned(self) -> Result<Self, String> {
        let mut text_bytes = 0;
        Ok(Self {
            top: clean_region("top", self.top, &mut text_bytes)?,
            left: clean_region("left", self.left, &mut text_bytes)?,
            right: clean_region("right", self.right, &mut text_bytes)?,
        })
    }
}

/// Cleans one banner, charging its text against the document-wide budget.
///
/// The error names the banner and the picture's position (`top.slots[1].alt`) so an editor
/// can point at the field it must fix instead of redrawing the whole style.
fn clean_region(name: &str, region: Region, text_bytes: &mut usize) -> Result<Region, String> {
    if region.slots.len() > MAX_SLOTS_PER_REGION {
        return Err(format!(
            "{name} has {} pictures; at most {MAX_SLOTS_PER_REGION} can be published.",
            region.slots.len()
        ));
    }
    let slots = region
        .slots
        .into_iter()
        .enumerate()
        .map(|(index, slot)| clean_slot(&format!("{name}.slots[{index}]"), slot, text_bytes))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Region {
        split: region.split,
        slots,
        hidden: region.hidden,
    })
}

fn clean_slot(row: &str, slot: Slot, text_bytes: &mut usize) -> Result<Slot, String> {
    let url = slot.url.trim().to_owned();
    if url.is_empty() {
        return Err(format!(
            "{row}.url is empty; a published picture needs an address."
        ));
    }
    if !safe_url(&url) {
        return Err(format!(
            "{row}.url must be an absolute http(s) address or a path on this instance: {}",
            excerpt(&url)
        ));
    }
    let alt = clean_text(row, "alt", slot.alt, MAX_ALT_CHARS)?;
    let media_id = clean_text(row, "media_id", slot.media_id, MAX_MEDIA_ID_CHARS)?;
    *text_bytes +=
        url.len() + alt.as_ref().map_or(0, String::len) + media_id.as_ref().map_or(0, String::len);
    if *text_bytes > MAX_PUBLISHED_TEXT_BYTES {
        return Err(format!(
            "{row} pushes published text to {} bytes; the limit is {MAX_PUBLISHED_TEXT_BYTES}.",
            *text_bytes
        ));
    }
    Ok(Slot {
        url,
        alt,
        media_id,
        sensitive: slot.sensitive,
    })
}

/// Strips control characters, trims, and refuses text longer than `max` characters.
fn clean_text(
    row: &str,
    field: &str,
    value: Option<String>,
    max: usize,
) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let text: String = value.chars().filter(|ch| !ch.is_control()).collect();
    let text = text.trim();
    let length = text.chars().count();
    if length > max {
        return Err(format!(
            "{row}.{field} is {length} characters; the limit is {max}."
        ));
    }
    Ok((!text.is_empty()).then_some(text.to_owned()))
}

/// Whether `url` is a picture address a browser may load on this page.
///
/// The shell refuses `javascript:`, protocol-relative `//host` and the `/\host` spelling
/// that some browsers read as protocol-relative, so the stored copy refuses them too.
fn safe_url(url: &str) -> bool {
    if url.chars().any(char::is_control) {
        return false;
    }
    let lower = url.to_ascii_lowercase();
    lower.starts_with("https://")
        || lower.starts_with("http://")
        || (lower.starts_with('/') && !lower.starts_with("//") && !lower.starts_with("/\\"))
}

/// The start of a refused value, so a `422` names it without echoing a whole document.
fn excerpt(value: &str) -> String {
    let mut excerpt: String = value.chars().take(120).collect();
    if excerpt.chars().count() < value.chars().count() {
        excerpt.push('…');
    }
    excerpt
}

/// Replaces one account's published style with `style`.
///
/// The caller has already run [`StylePublic::cleaned`]; this writes the whole document in
/// one statement, so a viewer never sees a style that is half old and half new.
pub async fn publish(
    pool: &PgPool,
    account_id: &str,
    style: &StylePublic,
) -> Result<(), sqlx::Error> {
    let regions = serde_json::to_value(style)
        .map_err(|error| sqlx::Error::Protocol(format!("style is not JSON: {error}")))?;
    sqlx::query(
        "INSERT INTO account_style_public (account_id, regions) VALUES ($1, $2) \
         ON CONFLICT (account_id) DO UPDATE \
            SET regions = EXCLUDED.regions, updated_at = now()",
    )
    .bind(account_id)
    .bind(regions)
    .execute(pool)
    .await?;
    Ok(())
}

/// One account's published style, or `None` when it has published nothing.
///
/// A missing row is not an empty style: the API answers `404`, because "this account never
/// chose banners" and "this account chose no banners" are different sentences to a reader.
pub async fn load(pool: &PgPool, account_id: &str) -> Result<Option<StylePublic>, sqlx::Error> {
    let regions: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT regions FROM account_style_public WHERE account_id = $1")
            .bind(account_id)
            .fetch_optional(pool)
            .await?;
    regions
        .map(|regions| {
            serde_json::from_value(regions).map_err(|error| {
                sqlx::Error::Protocol(format!("stored style is not the banner shape: {error}"))
            })
        })
        .transpose()
}

impl crate::Store {
    /// The banners one account published, if it has published any.
    pub async fn style_public(&self, account_id: &str) -> Result<Option<StylePublic>, sqlx::Error> {
        load(&self.pool, account_id).await
    }

    /// Replaces one account's published banners.
    pub async fn publish_style_public(
        &self,
        account_id: &str,
        style: &StylePublic,
    ) -> Result<(), sqlx::Error> {
        publish(&self.pool, account_id, style).await
    }
}

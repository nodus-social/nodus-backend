//! Wire shapes.
//!
//! These mirror Mastodon's client API field by field, including the fields we do not
//! fill yet (`card`, `poll`, `moved`), because a client that finds a key missing
//! sometimes crashes and always fails differently than one that finds `null`.

use chrono::{DateTime, Utc};
use serde::Serialize;

use nodus_server_core::limits::{
    IMAGE_SIZE_LIMIT, MEDIA_MAX_ATTACHMENTS, STATUS_MAX_CHARS, URL_RESERVED_CHARS, VIDEO_SIZE_LIMIT,
};
use nodus_server_core::Id;
use nodus_server_store::accounts::AccountRow;
use nodus_server_store::hydrate::{BatchOutcome, PictureSize, ProfilePictures, RowMap};
use nodus_server_store::media::MediaRow;
use nodus_server_store::statuses::{ReactionCount, StatusRow};

use crate::media::ProfileSlot;
use crate::state::InstanceConfig;

/// The page a reader should open for an account, in the place that actually holds it.
///
/// A remote account's page lives on the instance that minted it: printing our own address
/// with its name in it would point at a profile we do not have.
pub(crate) fn account_url(row: &AccountRow, instance: &InstanceConfig) -> String {
    account_url_parts(&row.username, row.domain.as_deref(), instance)
}

/// The same url for an account described only by its parts: a mention carries no row,
/// and building a second spelling of the url is how the two drift apart.
pub(crate) fn account_url_parts(
    username: &str,
    domain: Option<&str>,
    instance: &InstanceConfig,
) -> String {
    match domain {
        Some(domain) => format!("https://{domain}/@{username}"),
        None => instance.url(&format!("/@{username}")),
    }
}

/// The page a reader should open for a status, in the place that actually holds it.
///
/// A remote status keeps its own permalink: its id here is our numbering, so a link built
/// from it would name a post our instance never had.
fn status_url(row: &StatusRow, account: &AccountRow, instance: &InstanceConfig) -> String {
    if !row.local {
        if let Some(uri) = row.uri.as_deref().filter(|uri| uri.starts_with("http")) {
            return uri.to_owned();
        }
    }
    match account.domain.as_deref() {
        Some(domain) => format!("https://{domain}/@{}/{}", account.username, row.id),
        None => instance.url(&format!("/@{}/{}", account.username, row.id)),
    }
}

/// The account a moved profile points at.
///
/// Only the identity is known here: the target is a cached actor, and loading its full
/// profile would turn every status render into another query. A client needs the link and
/// the handle to say where the account went.
fn moved_account(uri: &str) -> serde_json::Value {
    let parsed = url::Url::parse(uri).ok();
    let host = parsed
        .as_ref()
        .and_then(url::Url::host_str)
        .unwrap_or_default();
    let username = parsed
        .as_ref()
        .and_then(url::Url::path_segments)
        .and_then(|segments| {
            segments
                .rev()
                .find(|segment| !segment.is_empty())
                .map(|segment| segment.trim_start_matches('@'))
        })
        .unwrap_or_default();
    serde_json::json!({
        "id": uri,
        "uri": uri,
        "url": uri,
        "username": username,
        "acct": format!("{username}@{host}"),
        "domain": host,
    })
}

/// The staff role Mastodon publishes on an account document.
///
/// Mastodon's `role` is public: every account document carries at least its name, so a
/// profile page can say "Moderator" without a token. The other half is nodus's own
/// spelling (`staff_role`), kept so a nodus client reads one string instead of a nested
/// object; the two are mapped from the stored role in one place below.
#[derive(Debug, Clone, Serialize)]
pub struct AccountRoleDto {
    /// `Admin` or `Moderator`, the names Mastodon's role entity renders.
    pub name: &'static str,
}

/// The shape of one profile picture, in the object Mastodon's media `meta` uses.
///
/// `size` is the `"WxH"` spelling clients compare as a string and `aspect` is width over
/// height, which is what a browser needs before the bytes arrive.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PictureMeta {
    pub width: i32,
    pub height: i32,
    pub size: String,
    pub aspect: f64,
}

impl PictureMeta {
    fn from_size(size: PictureSize) -> Self {
        Self {
            width: size.width,
            height: size.height,
            size: format!("{}x{}", size.width, size.height),
            aspect: f64::from(size.width) / f64::from(size.height.max(1)),
        }
    }
}

/// An account picture's metadata.
///
/// Upstream nests `original` and `small` because it keeps the upload and a thumbnail.
/// This server renders one profile-sized layer per slot, so `original` describes the
/// picture the URL serves and `small` is `null` rather than a duplicate size pretending
/// to be a second rendition.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AccountPictureMeta {
    pub original: PictureMeta,
    pub small: Option<PictureMeta>,
}

impl AccountPictureMeta {
    fn from_size(size: PictureSize) -> Self {
        Self {
            original: PictureMeta::from_size(size),
            small: None,
        }
    }
}

/// The two spellings of a stored staff role: Mastodon's display name and nodus's value.
///
/// `None` for `none`, which is how both a regular account and a read-only public document
/// say "holds no role". One match keeps `role` and `staff_role` from ever disagreeing.
fn staff_role_spellings(role: &str) -> Option<(&'static str, &'static str)> {
    match role {
        "admin" => Some(("Admin", "admin")),
        "moderator" => Some(("Moderator", "moderator")),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountDto {
    pub id: String,
    pub username: String,
    pub acct: String,
    pub display_name: String,
    pub locked: bool,
    pub bot: bool,
    pub discoverable: bool,
    pub group: bool,
    pub created_at: DateTime<Utc>,
    pub note: String,
    pub url: String,
    pub avatar: String,
    pub avatar_static: String,
    pub header: String,
    pub header_static: String,
    /// Rendered avatar shape, `null` when the picture has no variant row yet (a remote
    /// account, the default asset, or a render still in flight).
    pub avatar_meta: Option<AccountPictureMeta>,
    /// Rendered header shape, absent on the same terms as `avatar_meta`.
    pub header_meta: Option<AccountPictureMeta>,
    pub followers_count: i64,
    pub following_count: i64,
    pub statuses_count: i64,
    pub last_status_at: Option<String>,
    pub noindex: bool,
    pub emojis: Vec<serde_json::Value>,
    pub fields: Vec<serde_json::Value>,
    pub moved: Option<serde_json::Value>,
    pub suspended: bool,
    pub limited: bool,
    /// The account's staff role in Mastodon's shape, `null` for a regular account.
    ///
    /// Mastodon makes this public, so it rides on every read of the account, not only the
    /// account's own document; a client showing "Moderator" needs no privileged call.
    pub role: Option<AccountRoleDto>,
    /// The nodus spelling of the same role, `null` unless this is the account's own
    /// document.
    ///
    /// Published only to the subject because it is nodus vocabulary rather than a
    /// Mastodon field: a public read has no reason to teach other clients a second name
    /// for a fact `role` already carries. The export keeps the same spelling.
    pub staff_role: Option<&'static str>,
}

/// The asset every account without a picture points at.
const DEFAULT_AVATAR: &str = "default-avatar.png";

/// The URL a local profile picture is served at.
///
/// `reference` is what the account row stores: a bare media id, the `<id>/<layer>` pair
/// written since profile layers existed, or an asset name such as `default-avatar.png`.
/// Only a bare id gains the layer: naming it is what asks the media service for the size
/// the profile draws, and what gives [`still_url`] a suffix to find the still twin by. A
/// reference that already names its file is published as stored, so an old `{id}/preview`
/// keeps rendering and no reference is given a second layer.
pub(crate) fn profile_picture_url(
    reference: &str,
    slot: ProfileSlot,
    instance: &InstanceConfig,
) -> String {
    if reference.parse::<Id>().is_ok() {
        return instance.url(&format!("/media/{reference}/{}", slot.reference()));
    }
    instance.url(&format!("/media/{reference}"))
}

/// The still twin of an animated profile URL.
///
/// Mastodon's `*_static` fields exist for clients that cannot or must not animate, so
/// returning the animation there defeats them. A remote account's URL or an older
/// `{id}/preview` reference has no still twin: it is returned unchanged and the profile
/// gets one the next time the picture is set.
fn still_url(url: &str) -> String {
    if let Some(base) = url.strip_suffix("/avatar") {
        return format!("{base}/avatar_static");
    }
    if let Some(base) = url.strip_suffix("/header") {
        return format!("{base}/header_static");
    }
    url.to_owned()
}

impl AccountDto {
    #[must_use]
    pub fn from_row(row: &AccountRow, instance: &InstanceConfig) -> Self {
        let acct = match &row.domain {
            Some(domain) => format!("{}@{domain}", row.username),
            None => row.username.clone(),
        };
        let avatar = row.avatar_url.clone().unwrap_or_else(|| {
            profile_picture_url(
                row.avatar_ref.as_deref().unwrap_or(DEFAULT_AVATAR),
                ProfileSlot::Avatar,
                instance,
            )
        });
        let header = row
            .header_url
            .clone()
            .or_else(|| {
                row.header_ref
                    .as_ref()
                    .map(|reference| profile_picture_url(reference, ProfileSlot::Header, instance))
            })
            .unwrap_or_default();
        Self {
            id: row.id.clone(),
            username: row.username.clone(),
            acct,
            display_name: row.display_name.clone(),
            locked: row.locked,
            bot: row.bot,
            discoverable: row.discoverable,
            group: false,
            created_at: row.created_at,
            note: row.note.clone(),
            url: account_url(row, instance),
            avatar: avatar.clone(),
            avatar_static: still_url(&avatar),
            header: header.clone(),
            header_static: still_url(&header),
            avatar_meta: None,
            header_meta: None,
            followers_count: row.followers_count,
            following_count: row.following_count,
            statuses_count: row.statuses_count,
            last_status_at: row
                .last_status_at
                .map(|at| at.format("%Y-%m-%d").to_string()),
            noindex: !row.indexable,
            emojis: Vec::new(),
            fields: row.fields.as_array().cloned().unwrap_or_default(),
            moved: row.moved_to.as_deref().map(moved_account),
            suspended: row.suspended_at.is_some(),
            limited: false,
            role: staff_role_spellings(&row.staff_role).map(|(name, _)| AccountRoleDto { name }),
            staff_role: None,
        }
    }

    /// The same account document with the picture shapes the page's batch read.
    #[must_use]
    pub fn with_pictures(mut self, pictures: Option<&ProfilePictures>) -> Self {
        self.apply_pictures(pictures);
        self
    }

    /// Replaces both picture metas from one account's batch entry. A missing picture
    /// clears both fields, so one DTO shape cannot keep a stale shape from a previous
    /// caller.
    pub fn apply_pictures(&mut self, pictures: Option<&ProfilePictures>) {
        self.avatar_meta = pictures
            .and_then(|pictures| pictures.avatar)
            .map(AccountPictureMeta::from_size);
        self.header_meta = pictures
            .and_then(|pictures| pictures.header)
            .map(AccountPictureMeta::from_size);
    }

    /// The account's own document: the public shape plus its nodus `staff_role`.
    ///
    /// `verify_credentials` and the self-service writes answer with this. The role is a
    /// fact about the token's own subject, so learning it needs no admin scope — which is
    /// what lets the web client draw the Administration door without probing
    /// `/api/v2/admin/accounts`.
    #[must_use]
    pub fn from_own_row(row: &AccountRow, instance: &InstanceConfig) -> Self {
        let mut dto = Self::from_row(row, instance);
        dto.staff_role = staff_role_spellings(&row.staff_role).map(|(_, nodus)| nodus);
        dto
    }
}

/// Account documents for a list, each carrying the picture shapes its page's batch read.
///
/// An endpoint with an avatar on screen calls this rather than mapping
/// [`AccountDto::from_row`] itself: a forgotten `with_pictures` call publishes
/// `avatar_meta: null` for an account whose shape is known, which a client cannot tell
/// from a genuinely unknown picture. Rows keep their order, including any the batch did
/// not answer (whose metas stay `null`).
#[must_use]
pub fn accounts_with_pictures<'a, I>(
    rows: I,
    outcome: &BatchOutcome,
    instance: &InstanceConfig,
) -> Vec<AccountDto>
where
    I: IntoIterator<Item = &'a AccountRow>,
{
    rows.into_iter()
        .map(|row| {
            AccountDto::from_row(row, instance).with_pictures(outcome.profile_pictures.get(&row.id))
        })
        .collect()
}

/// The subject's own document (`staff_role` included) with the same picture shapes.
#[must_use]
pub fn own_account_with_pictures(
    row: &AccountRow,
    outcome: &BatchOutcome,
    instance: &InstanceConfig,
) -> AccountDto {
    AccountDto::from_own_row(row, instance).with_pictures(outcome.profile_pictures.get(&row.id))
}

#[derive(Debug, Serialize)]
pub struct StatusDto {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub in_reply_to_id: Option<String>,
    pub in_reply_to_account_id: Option<String>,
    pub sensitive: bool,
    pub spoiler_text: String,
    pub visibility: String,
    pub language: Option<String>,
    pub uri: String,
    pub url: Option<String>,
    pub replies_count: i64,
    pub reblogs_count: i64,
    pub favourites_count: i64,
    pub edited_at: Option<DateTime<Utc>>,
    pub content: String,
    pub content_format: String,
    pub content_source: Option<String>,
    pub reblog: Option<Box<Self>>,
    pub account: AccountDto,
    pub media_attachments: Vec<MediaAttachmentDto>,
    pub mentions: Vec<serde_json::Value>,
    pub tags: Vec<serde_json::Value>,
    pub emojis: Vec<serde_json::Value>,
    pub card: Option<serde_json::Value>,
    pub poll: Option<serde_json::Value>,
    pub application: Option<ApplicationDto>,
    pub favourited: bool,
    pub reblogged: bool,
    pub muted: bool,
    pub bookmarked: bool,
    /// Reaction chips, filled by the page endpoints from their one batched read. Empty
    /// on every other surface, and omitted rather than serialised as `[]` so those
    /// payloads stay exactly what they were before pages existed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reactions: Vec<ReactionCount>,
}

#[derive(Debug, Serialize)]
pub struct PollDto {
    pub id: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub expired: bool,
    pub multiple: bool,
    /// Omitted while `hide_totals` keeps a non-voter from seeing the tally.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub votes_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voters_count: Option<i64>,
    /// Present only for a signed-in reader: Mastodon omits both this and `own_votes`
    /// otherwise, and a client that sees `false` cannot tell "not voted" from "anonymous".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub own_votes: Option<Vec<usize>>,
    pub options: Vec<PollOptionDto>,
}

#[derive(Debug, Serialize)]
pub struct PollOptionDto {
    pub title: String,
    /// Omitted while `hide_totals` keeps a non-voter from seeing the tally.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub votes_count: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct MediaAttachmentDto {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
    pub preview_url: String,
    pub remote_url: Option<String>,
    pub text_url: Option<String>,
    pub meta: serde_json::Value,
    pub description: Option<String>,
    pub blurhash: Option<String>,
    pub sensitive: bool,
    pub processing_state: String,
    pub processing_progress: i16,
    /// Mastodon's coarse three-value view of `processing_state`, for clients that poll a
    /// `202` upload: the catalogue records the steps, the client wants the verdict.
    pub processing: String,
}

impl MediaAttachmentDto {
    /// The `type` a client understands for a stored content type.
    #[must_use]
    pub fn kind_name(content_type: &str) -> &'static str {
        match content_type {
            "image/gif" => "gifv",
            "video/mp4" | "video/webm" | "video/quicktime" | "video/ogg" => "video",
            "audio/mpeg" | "audio/ogg" | "audio/wav" => "audio",
            content_type if content_type.starts_with("image/") => "image",
            _ => "unknown",
        }
    }

    /// The three-value progress a polling client sees. Anything the pipeline is still
    /// working on (`pending`, `processing`) reads as pending: from the outside the row is
    /// not ready either way.
    #[must_use]
    pub fn processing(state: &str) -> &'static str {
        match state {
            "ready" => "ready",
            "failed" => "failed",
            _ => "pending",
        }
    }

    #[must_use]
    pub fn from_row(row: &MediaRow, instance: &InstanceConfig) -> Self {
        let url = row
            .remote_url
            .clone()
            .unwrap_or_else(|| instance.url(&format!("/media/{}/compressed", row.id)));
        let preview_url = row
            .remote_url
            .clone()
            .unwrap_or_else(|| instance.url(&format!("/media/{}/preview", row.id)));
        let mut original = serde_json::Map::new();
        original.insert(
            "size".to_owned(),
            serde_json::json!(format!(
                "{}x{}",
                row.width.unwrap_or(0),
                row.height.unwrap_or(0)
            )),
        );
        original.insert("width".to_owned(), serde_json::json!(row.width));
        original.insert("height".to_owned(), serde_json::json!(row.height));
        original.insert(
            "aspect".to_owned(),
            serde_json::json!(match (row.width, row.height) {
                (Some(width), Some(height)) if height > 0 => f64::from(width) / f64::from(height),
                _ => 1.0,
            }),
        );
        original.insert("size_bytes".to_owned(), serde_json::json!(row.size));
        Self {
            id: row.id.clone(),
            kind: Self::kind_name(&row.content_type).to_owned(),
            url,
            preview_url,
            remote_url: row.remote_url.clone(),
            text_url: None,
            meta: serde_json::json!({ "original": original }),
            description: (!row.description.is_empty()).then(|| row.description.clone()),
            blurhash: row.blurhash.clone(),
            sensitive: row.sensitive,
            processing_state: row.processing_state.clone(),
            processing_progress: row.processing_progress,
            processing: Self::processing(&row.processing_state).to_owned(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ApplicationDto {
    pub name: String,
    pub website: Option<String>,
}

impl StatusDto {
    /// `uri` falls back to our own URL for local statuses, which is what Mastodon does:
    /// clients use `uri` as the stable identity and `url` as the human page.
    #[must_use]
    pub fn from_row(row: &StatusRow, account: &AccountRow, instance: &InstanceConfig) -> Self {
        Self::from_row_with_media(row, account, instance, &[])
    }

    /// Applies the page's picture shapes to this status's author and its boost's author.
    ///
    /// The map is keyed by account id, so a reblog that names a different account gets
    /// that account's shape rather than its booster's.
    pub fn apply_account_pictures(&mut self, pictures: &RowMap<ProfilePictures>) {
        self.account.apply_pictures(pictures.get(&self.account.id));
        if let Some(reblog) = self.reblog.as_mut() {
            reblog.apply_account_pictures(pictures);
        }
    }

    /// Builds a status with its already-loaded attachments.
    #[must_use]
    pub fn from_row_with_media(
        row: &StatusRow,
        account: &AccountRow,
        instance: &InstanceConfig,
        media: &[MediaRow],
    ) -> Self {
        let url = status_url(row, account, instance);
        Self {
            id: row.id.clone(),
            created_at: row.created_at,
            in_reply_to_id: row.in_reply_to_id.clone(),
            in_reply_to_account_id: row.in_reply_to_account_id.clone(),
            sensitive: row.sensitive,
            spoiler_text: row.spoiler_text.clone(),
            visibility: row.visibility.clone(),
            language: row.language.clone(),
            uri: row.uri.clone().unwrap_or_else(|| url.clone()),
            url: Some(url),
            replies_count: row.replies_count,
            reblogs_count: row.reblogs_count,
            favourites_count: row.favourites_count,
            edited_at: row.edited_at,
            content: row.content_html.clone(),
            content_format: row.content_format.clone(),
            content_source: row.content_source.clone(),
            reblog: None,
            account: AccountDto::from_row(account, instance),
            media_attachments: media
                .iter()
                .map(|row| MediaAttachmentDto::from_row(row, instance))
                .collect(),
            mentions: Vec::new(),
            tags: Vec::new(),
            emojis: Vec::new(),
            card: None,
            poll: None,
            application: Some(ApplicationDto {
                name: "Nodus".to_owned(),
                website: None,
            }),
            favourited: false,
            reblogged: false,
            muted: false,
            bookmarked: false,
            reactions: Vec::new(),
        }
    }
}

/// `GET /api/v1/instance`.
#[derive(Debug, Serialize)]
pub struct InstanceV1Dto {
    pub uri: String,
    pub title: String,
    pub short_description: String,
    pub description: String,
    pub email: String,
    pub version: String,
    pub urls: serde_json::Value,
    pub stats: serde_json::Value,
    pub thumbnail: String,
    pub languages: Vec<String>,
    pub registrations: bool,
    pub approval_required: bool,
    pub invites_enabled: bool,
    pub configuration: ConfigurationDto,
    /// The instance's code of conduct, in ordinal order. Mastodon clients that show the
    /// rules before someone joins read this field on the instance document.
    pub rules: Vec<RuleDto>,
}

/// `GET /api/v2/instance`.
#[derive(Debug, Serialize)]
pub struct InstanceV2Dto {
    pub domain: String,
    pub title: String,
    pub version: String,
    pub source_url: String,
    pub description: String,
    pub usage: serde_json::Value,
    pub thumbnail: serde_json::Value,
    pub languages: Vec<String>,
    pub configuration: ConfigurationDto,
    pub registrations: RegistrationsDto,
    pub contact: serde_json::Value,
    pub rules: Vec<RuleDto>,
}

#[derive(Debug, Serialize)]
pub struct RegistrationsDto {
    pub enabled: bool,
    pub approval_required: bool,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ConfigurationDto {
    pub urls: serde_json::Value,
    pub accounts: serde_json::Value,
    pub statuses: StatusesDto,
    pub media_attachments: MediaDto,
    pub polls: serde_json::Value,
    pub translation: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct StatusesDto {
    pub max_characters: u32,
    pub max_media_attachments: usize,
    pub characters_reserved_per_url: u32,
}

#[derive(Debug, Serialize)]
pub struct MediaDto {
    pub supported_mime_types: Vec<&'static str>,
    pub image_size_limit: u64,
    pub image_matrix_limit: u64,
    pub video_size_limit: u64,
    pub video_frame_rate_limit: u32,
    pub video_matrix_limit: u64,
}

impl ConfigurationDto {
    /// The one place where advertised limits come from the constants the server
    /// enforces, so a client cannot size a compose box for 5 000 characters.
    #[must_use]
    pub fn build(instance: &InstanceConfig) -> Self {
        Self {
            urls: serde_json::json!({ "streaming": instance.url("/api/v1/streaming") }),
            accounts: serde_json::json!({ "max_featured_tags": 10 }),
            statuses: StatusesDto {
                max_characters: STATUS_MAX_CHARS,
                max_media_attachments: MEDIA_MAX_ATTACHMENTS,
                characters_reserved_per_url: URL_RESERVED_CHARS,
            },
            media_attachments: MediaDto {
                supported_mime_types: vec![
                    "image/jpeg",
                    "image/png",
                    "image/gif",
                    "image/webp",
                    "video/mp4",
                ],
                image_size_limit: IMAGE_SIZE_LIMIT,
                image_matrix_limit: 16_777_216,
                video_size_limit: VIDEO_SIZE_LIMIT,
                video_frame_rate_limit: 60,
                video_matrix_limit: 2_304_000,
            },
            polls: serde_json::json!({
                "max_options": 4, "max_characters_per_option": 50,
                "min_expiration": 300, "max_expiration": 2_629_746
            }),
            translation: serde_json::json!({ "enabled": false }),
        }
    }
}

/// One instance rule.
#[derive(Debug, Clone, Serialize)]
pub struct RuleDto {
    pub id: String,
    pub text: String,
    /// Zero-based position in the list; the number a reporter cites.
    pub ordinal: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

impl RuleDto {
    #[must_use]
    pub fn from_row(row: nodus_server_store::rules::RuleRow) -> Self {
        Self {
            id: row.id,
            text: row.text,
            ordinal: row.ordinal,
            hint: row.hint,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::still_url;

    #[test]
    fn a_profile_url_gets_a_still_twin() {
        assert_eq!(
            still_url("https://social.test/media/abc/avatar"),
            "https://social.test/media/abc/avatar_static"
        );
        assert_eq!(
            still_url("https://social.test/media/abc/header"),
            "https://social.test/media/abc/header_static"
        );
    }

    #[test]
    fn a_reference_without_a_still_twin_is_unchanged() {
        assert_eq!(
            still_url("https://remote.test/a.png"),
            "https://remote.test/a.png"
        );
        assert_eq!(still_url(""), "");
        // Legacy rows point at the preview; they get a still on the next profile save.
        assert_eq!(still_url("abc/preview"), "abc/preview");
    }
}

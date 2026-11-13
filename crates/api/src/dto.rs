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
use nodus_server_store::accounts::AccountRow;
use nodus_server_store::media::MediaRow;
use nodus_server_store::statuses::StatusRow;

use crate::state::InstanceConfig;

#[derive(Debug, Serialize)]
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
}

impl AccountDto {
    #[must_use]
    pub fn from_row(row: &AccountRow, instance: &InstanceConfig) -> Self {
        let acct = match &row.domain {
            Some(domain) => format!("{}@{domain}", row.username),
            None => row.username.clone(),
        };
        let avatar = instance.url(&format!(
            "/media/{}",
            row.avatar_ref.as_deref().unwrap_or("default-avatar.png")
        ));
        let header = instance.url(&format!(
            "/media/{}",
            row.header_ref.as_deref().unwrap_or("default-header.png")
        ));
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
            url: instance.url(&format!("/@{}", row.username)),
            avatar: avatar.clone(),
            avatar_static: avatar,
            header: header.clone(),
            header_static: header,
            followers_count: row.followers_count,
            following_count: row.following_count,
            statuses_count: row.statuses_count,
            last_status_at: row
                .last_status_at
                .map(|at| at.format("%Y-%m-%d").to_string()),
            noindex: !row.indexable,
            emojis: Vec::new(),
            fields: row.fields.as_array().cloned().unwrap_or_default(),
            moved: None,
            suspended: row.suspended_at.is_some(),
            limited: false,
        }
    }
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
    pub card: Option<serde_json::Value>,
    pub poll: Option<serde_json::Value>,
    pub application: Option<ApplicationDto>,
    pub favourited: bool,
    pub reblogged: bool,
    pub muted: bool,
    pub bookmarked: bool,
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
}

impl MediaAttachmentDto {
    #[must_use]
    pub fn from_row(row: &MediaRow, instance: &InstanceConfig) -> Self {
        let url = instance.url(&format!("/media/{}", row.id));
        let kind = match row.content_type.as_str() {
            "image/gif" => "gifv",
            "video/mp4" | "video/webm" | "video/quicktime" | "video/ogg" => "video",
            "audio/mpeg" | "audio/ogg" | "audio/wav" => "audio",
            content_type if content_type.starts_with("image/") => "image",
            _ => "unknown",
        };
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
            kind: kind.to_owned(),
            url: url.clone(),
            preview_url: url,
            remote_url: None,
            text_url: None,
            meta: serde_json::json!({ "original": original }),
            description: (!row.description.is_empty()).then(|| row.description.clone()),
            blurhash: row.blurhash.clone(),
            sensitive: row.sensitive,
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

    /// Builds a status with its already-loaded attachments.
    #[must_use]
    pub fn from_row_with_media(
        row: &StatusRow,
        account: &AccountRow,
        instance: &InstanceConfig,
        media: &[MediaRow],
    ) -> Self {
        let url = instance.url(&format!("/@{}/{}", account.username, row.id));
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
    pub rules: Vec<serde_json::Value>,
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

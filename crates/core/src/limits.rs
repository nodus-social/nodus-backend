//! Limits the API advertises and enforces.
//!
//! They live in one place because `GET /api/v2/instance` publishes them: an app sizes
//! its compose box from `configuration.statuses.max_characters`, so the constant and
//! the advertised value must be the same number, not two that agree today.

/// Maximum characters in a status body, counted as Unicode scalar values plus 23 per
/// link (Mastodon's rule, because a link is shortened after posting).
pub const STATUS_MAX_CHARS: u32 = 500;

/// Maximum media attachments on one status.
pub const MEDIA_MAX_ATTACHMENTS: usize = 4;

/// Characters reserved per URL when counting a status.
pub const URL_RESERVED_CHARS: u32 = 23;

/// Bytes accepted for one image upload.
pub const IMAGE_SIZE_LIMIT: u64 = 10 * 1024 * 1024;

/// Bytes accepted for one video upload.
pub const VIDEO_SIZE_LIMIT: u64 = 40 * 1024 * 1024;

/// Followers above which a local account is not materialised into follower timelines.
///
/// One constant shared by the producer (`fan_out`) and the reader (home timeline
/// union), because two copies of this number would give a window where a post is
/// written *and* merged, which shows it twice.
pub const BIG_ACCOUNT_THRESHOLD: i64 = 50_000;

/// Rows written per batch by `fan_out`, so one popular post cannot hold a long
/// transaction.
pub const FAN_OUT_BATCH: i64 = 5_000;

/// Default page size when a client does not ask.
pub const PAGE_DEFAULT: u32 = 20;

/// Largest page any endpoint returns, regardless of `limit`.
pub const PAGE_MAX: u32 = 40;

/// Largest page for account collections (`followers`, `following`), where Mastodon
/// allows more.
pub const PAGE_MAX_ACCOUNTS: u32 = 80;

/// Maximum characters in a media description (alt text).
pub const MEDIA_DESCRIPTION_MAX_CHARS: usize = 1_500;

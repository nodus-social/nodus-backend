//! Profile picture dimensions: one read for a page, not one per avatar and banner.
//!
//! The account row names the layer a profile picture is served from but stores no shape;
//! a client that has only the URL cannot reserve the box before the bytes arrive. The
//! variant row already records the rendered width and height, so this read joins the
//! account's reference to that row for every account on the page in one statement.
//!
//! A reference is `<media id>` or `<media id>/<layer>`; a bare id means the profile layer
//! (`avatar`/`header`), and an older `{id}/preview` reference asks for the layer it names.
//! The highest `max_edge` row wins when a layer has more than one rendition, matching
//! [`crate::media::variant`]. A picture with no variant row — a remote account, the
//! default asset, or a render that has not landed yet — is absent rather than padded:
//! the caller publishes `null`, which a browser can tell apart from a square picture.

use super::{Batch, EssentialOp, RowMap};

/// The rendered shape of one picture layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PictureSize {
    pub width: i32,
    pub height: i32,
}

/// The avatar and header shapes for one account; a slot with no variant row is `None`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProfilePictures {
    pub avatar: Option<PictureSize>,
    pub header: Option<PictureSize>,
}

impl ProfilePictures {
    /// Whether neither slot has a rendered layer, in which case the account is absent
    /// from the map.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.avatar.is_none() && self.header.is_none()
    }
}

impl Batch<'_> {
    /// Rendered avatar and header dimensions for these account ids. Essential: the page's
    /// layout reservation is part of what the page says about its accounts.
    #[must_use]
    pub fn profile_pictures(mut self, ids: &[String]) -> Self {
        self.essential
            .push(EssentialOp::ProfilePictures(ids.to_vec()));
        self
    }
}

/// One statement for both slots: the account's reference decides the layer, and a
/// lateral pick takes the highest-edge variant exactly as a single-row read does.
pub(super) async fn fetch_profile_pictures<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    account_ids: &[String],
) -> Result<RowMap<ProfilePictures>, sqlx::Error> {
    let rows = sqlx::query_as::<_, PictureRow>(
        "WITH requested AS (SELECT unnest($1::text[]) AS account_id), \
         refs AS ( \
             SELECT r.account_id, \
                    NULLIF(split_part(a.avatar_ref, '/', 1), '') AS avatar_media_id, \
                    COALESCE(NULLIF(split_part(a.avatar_ref, '/', 2), ''), 'avatar') AS avatar_layer, \
                    NULLIF(split_part(a.header_ref, '/', 1), '') AS header_media_id, \
                    COALESCE(NULLIF(split_part(a.header_ref, '/', 2), ''), 'header') AS header_layer \
               FROM requested r JOIN account a ON a.id = r.account_id \
         ) \
         SELECT refs.account_id, \
                avatar.width AS avatar_width, avatar.height AS avatar_height, \
                header.width AS header_width, header.height AS header_height \
           FROM refs \
           LEFT JOIN LATERAL ( \
               SELECT v.width, v.height FROM media_variant v \
                WHERE v.media_id = refs.avatar_media_id AND v.layer = refs.avatar_layer \
                ORDER BY v.max_edge DESC LIMIT 1 \
           ) avatar ON TRUE \
           LEFT JOIN LATERAL ( \
               SELECT v.width, v.height FROM media_variant v \
                WHERE v.media_id = refs.header_media_id AND v.layer = refs.header_layer \
                ORDER BY v.max_edge DESC LIMIT 1 \
           ) header ON TRUE \
          WHERE avatar.width IS NOT NULL OR header.width IS NOT NULL",
    )
    .bind(account_ids)
    .fetch_all(executor)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let pictures = ProfilePictures {
                avatar: picture_size(row.avatar_width, row.avatar_height),
                header: picture_size(row.header_width, row.header_height),
            };
            (!pictures.is_empty()).then_some((row.account_id, pictures))
        })
        .collect())
}

fn picture_size(width: Option<i32>, height: Option<i32>) -> Option<PictureSize> {
    width
        .zip(height)
        .map(|(width, height)| PictureSize { width, height })
}

#[derive(sqlx::FromRow)]
struct PictureRow {
    account_id: String,
    avatar_width: Option<i32>,
    avatar_height: Option<i32>,
    header_width: Option<i32>,
    header_height: Option<i32>,
}

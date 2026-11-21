//! Featured tags, instance rules and instance languages.
//!
//! Three small lists a client reads from a profile or an about screen. The featured-tag
//! writes are the only state change: everything else is a projection of what is already
//! stored.

use axum::extract::{Path, State};
use axum::{http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use nodus_server_core::Id;

use crate::auth::{Auth, MaybeAuth};
use crate::dto::{AccountDto, RuleDto};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// One highlighted tag, as Mastodon shapes it.
#[derive(Debug, Serialize)]
pub struct FeaturedTagDto {
    pub id: String,
    pub name: String,
    /// A number, not a string: Mastodon sends an integer and every client types it as
    /// one (`FeaturedTag::statuses_count: Option<u64>` in the shared model).
    pub statuses_count: u64,
    pub last_status_at: Option<String>,
}

/// One language the instance has posts in.
#[derive(Debug, Serialize)]
pub struct LanguageDto {
    pub code: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct FeatureTagForm {
    pub name: String,
}

/// `GET /api/v1/featured_tags` — the reader's own highlighted tags.
pub async fn mine(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<Vec<FeaturedTagDto>>> {
    auth.require_scope("read:accounts")?;
    Ok(Json(tags(&state, &auth.0.account.id).await?))
}

/// `GET /api/v1/accounts/{id}/featured_tags` — another profile's highlighted tags.
pub async fn for_account(
    State(state): State<AppState>,
    MaybeAuth(_auth): MaybeAuth,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<FeaturedTagDto>>> {
    let account = state
        .store()
        .account(&id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    Ok(Json(tags(&state, &account.id).await?))
}

async fn tags(state: &AppState, account_id: &str) -> ApiResult<Vec<FeaturedTagDto>> {
    let rows =
        nodus_server_store::highlights::featured_tags(state.store().pool(), account_id).await?;
    Ok(rows
        .into_iter()
        .map(|row| FeaturedTagDto {
            id: row.id,
            // Mastodon prints the tag without the leading `#`, and clients add it.
            name: row.name.trim_start_matches('#').to_owned(),
            // Counting every post carrying the tag on read is a scan we do not need: the
            // number is decoration, and a profile shows the tag itself.
            statuses_count: 0,
            last_status_at: None,
        })
        .collect())
}

/// `POST /api/v1/featured_tags`
pub async fn feature(
    State(state): State<AppState>,
    auth: Auth,
    Json(form): Json<FeatureTagForm>,
) -> ApiResult<Json<FeaturedTagDto>> {
    auth.require_scope("write:accounts")?;
    let name = form.name.trim().trim_start_matches('#').to_lowercase();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::unprocessable(
            "name must be a tag between 1 and 100 characters",
        ));
    }
    let row = nodus_server_store::highlights::feature_tag(
        state.store().pool(),
        &Id::new().to_string(),
        &auth.0.account.id,
        &name,
    )
    .await?;
    Ok(Json(FeaturedTagDto {
        id: row.id,
        name: row.name,
        statuses_count: 0,
        last_status_at: None,
    }))
}

/// `DELETE /api/v1/featured_tags/{id}`
pub async fn unfeature(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_scope("write:accounts")?;
    nodus_server_store::highlights::unfeature_tag(state.store().pool(), &auth.0.account.id, &id)
        .await?;
    // Mastodon answers an unfeature with an empty body, and a client does not care
    // whether the tag was there: the profile no longer shows it either way.
    Ok(StatusCode::OK)
}

/// Suggested tags: the tags this instance sees most, which is what a profile editor can
/// offer without asking the reader to remember a name.
///
/// Answered as `FeaturedTag` documents rather than bare names: a Mastodon client parses
/// this endpoint with the same model as `/api/v1/featured_tags`, and a list of strings
/// makes every one of them fail to deserialise. `id` is the name here because a suggestion
/// is not a featured tag yet — nothing has an id until it is featured.
pub async fn suggestions(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<Vec<FeaturedTagDto>>> {
    auth.require_scope("read:accounts")?;
    let rows = nodus_server_store::discovery::search_tags(state.store().pool(), "", 20)
        .await
        .unwrap_or_default();
    Ok(Json(
        rows.into_iter()
            .map(|row| FeaturedTagDto {
                id: row.name.clone(),
                name: row.name,
                statuses_count: u64::try_from(row.uses).unwrap_or_default(),
                last_status_at: None,
            })
            .collect(),
    ))
}

/// `GET /api/v1/instance/rules`
pub async fn rules(State(state): State<AppState>) -> ApiResult<Json<Vec<RuleDto>>> {
    let rows = nodus_server_store::rules::rules(state.store().pool()).await?;
    Ok(Json(rows.into_iter().map(RuleDto::from_row).collect()))
}

/// `GET /api/v1/instance/languages`
pub async fn languages(State(state): State<AppState>) -> ApiResult<Json<Vec<LanguageDto>>> {
    let rows = nodus_server_store::highlights::languages(state.store().pool()).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| LanguageDto {
                // The SDK falls back to the code when a name is missing, so an unknown
                // language still renders as something a reader can pick.
                name: language_name(&row.code).map_or_else(|| row.code.clone(), ToOwned::to_owned),
                code: row.code,
            })
            .collect(),
    ))
}

/// The languages Mastodon ships names for, so a picker is not a list of codes.
fn language_name(code: &str) -> Option<&'static str> {
    Some(match code {
        "en" => "English",
        "de" => "Deutsch",
        "fr" => "Français",
        "es" => "Español",
        "it" => "Italiano",
        "pt" => "Português",
        "nl" => "Nederlands",
        "pl" => "Polski",
        "ru" => "Русский",
        "uk" => "Українська",
        "ja" => "日本語",
        "ko" => "한국어",
        "zh" => "中文",
        "sv" => "Svenska",
        "da" => "Dansk",
        "fi" => "Suomi",
        "no" => "Norsk",
        "cs" => "Čeština",
        "tr" => "Türkçe",
        "ar" => "العربية",
        "he" => "עברית",
        "hi" => "हिन्दी",
        "id" => "Bahasa Indonesia",
        "vi" => "Tiếng Việt",
        "th" => "ไทย",
        _ => return None,
    })
}

/// `GET /api/v1/directory` — accounts this instance suggests.
#[derive(Debug, Deserialize)]
pub struct DirectoryQuery {
    #[serde(default)]
    pub local: Option<bool>,
    #[serde(default)]
    pub order: Option<String>,
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(default)]
    pub limit: Option<u32>,
}

pub async fn directory(
    State(state): State<AppState>,
    MaybeAuth(_auth): MaybeAuth,
    axum::extract::Query(query): axum::extract::Query<DirectoryQuery>,
) -> ApiResult<Json<Vec<AccountDto>>> {
    let size = nodus_server_core::pagination::PageSize::clamp(
        query.limit,
        nodus_server_core::limits::PAGE_MAX_ACCOUNTS,
    );
    let rows = nodus_server_store::accounts::directory(
        state.store().pool(),
        query.local.unwrap_or(false),
        query.order.as_deref() == Some("active"),
        query.offset.unwrap_or(0).max(0),
        i64::from(size.get()),
    )
    .await?;
    Ok(Json(
        rows.iter()
            .map(|row| AccountDto::from_row(row, state.instance()))
            .collect(),
    ))
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{delete, get};
    axum::Router::new()
        .route("/api/v1/directory", get(directory))
        .route("/api/v1/featured_tags", get(mine).post(feature))
        .route("/api/v1/featured_tags/suggestions", get(suggestions))
        .route("/api/v1/featured_tags/{id}", delete(unfeature))
        .route("/api/v1/accounts/{id}/featured_tags", get(for_account))
        .route("/api/v1/instance/rules", get(rules))
        .route("/api/v1/instance/languages", get(languages))
}

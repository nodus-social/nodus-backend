//! The HTTP surface.
//!
//! Handlers do three things and nothing else: parse the request, call the store, map
//! rows into `dto`. Domain decisions (who may see what) live in `nodus-server-store` or
//! `nodus-server-core`, so this file stays readable as a list of endpoints.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

use nodus_server_core::id::Id;
use nodus_server_core::{PageParams, PageSize};

use crate::auth::{Auth, MaybeAuth};
use crate::dto::{
    AccountDto, ConfigurationDto, InstanceV1Dto, InstanceV2Dto, RegistrationsDto, RuleDto,
    StatusDto,
};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// The query parameters every timeline accepts.
#[derive(Debug, Deserialize)]
pub struct PageQuery {
    pub max_id: Option<String>,
    pub since_id: Option<String>,
    pub min_id: Option<String>,
    pub limit: Option<u32>,
    /// `local=true` on `/timelines/public`; unknown values are ignored like Mastodon.
    pub local: Option<bool>,
}

impl PageQuery {
    /// Parses cursors, turning a malformed one into `422` instead of an empty page.
    pub(crate) fn params(&self) -> ApiResult<PageParams> {
        let parse = |raw: &Option<String>, field: &str| -> ApiResult<Option<Id>> {
            match raw {
                None => Ok(None),
                Some(value) => value
                    .parse::<Id>()
                    .map(Some)
                    .map_err(|_| ApiError::unprocessable(format!("{field} must be a valid id"))),
            }
        };
        let params = PageParams::new()
            .with_max_id(parse(&self.max_id, "max_id")?)
            .with_since_id(parse(&self.since_id, "since_id")?)
            .with_min_id(parse(&self.min_id, "min_id")?)
            .with_limit(self.limit);
        params
            .validate()
            .map_err(|error| ApiError::unprocessable(error.to_string()))
    }
}

/// `GET /api/v1/instance`
pub async fn instance_v1(State(state): State<AppState>) -> ApiResult<Json<InstanceV1Dto>> {
    let instance = state.instance();
    let rules = nodus_server_store::rules::rules(state.store().pool()).await?;
    Ok(Json(InstanceV1Dto {
        uri: instance.domain.clone(),
        title: instance.title.clone(),
        short_description: instance.description.clone(),
        description: instance.description.clone(),
        email: instance.contact_email.clone().unwrap_or_default(),
        version: instance.api_version.clone(),
        urls: serde_json::json!({ "streaming_api": instance.url("/api/v1/streaming") }),
        stats: serde_json::json!({ "user_count": 0, "status_count": 0, "domain_count": 1 }),
        thumbnail: instance.url("/media/thumbnail.png"),
        languages: vec!["en".to_owned()],
        registrations: instance.registrations_open,
        approval_required: false,
        invites_enabled: false,
        configuration: ConfigurationDto::build(instance),
        rules: rules.into_iter().map(RuleDto::from_row).collect(),
    }))
}

/// `GET /api/v2/instance`
pub async fn instance_v2(State(state): State<AppState>) -> ApiResult<Json<InstanceV2Dto>> {
    let instance = state.instance();
    let rules = nodus_server_store::rules::rules(state.store().pool()).await?;
    Ok(Json(InstanceV2Dto {
        domain: instance.domain.clone(),
        title: instance.title.clone(),
        version: instance.api_version.clone(),
        source_url: "https://github.com/nodus-social/nodus-backend".to_owned(),
        description: instance.description.clone(),
        usage: serde_json::json!({ "users": { "active_month": 0 } }),
        thumbnail: serde_json::json!({
            "url": instance.url("/media/thumbnail.png"),
            "blurhash": null,
            "versions": {}
        }),
        languages: vec!["en".to_owned()],
        configuration: ConfigurationDto::build(instance),
        registrations: RegistrationsDto {
            enabled: instance.registrations_open,
            approval_required: false,
            message: None,
        },
        // `email` is a string in Mastodon's payload and every client types it as one, so
        // an instance with no contact address sends `""` rather than `null`: a null here
        // is a decode failure in clients, not a missing value.
        contact: serde_json::json!({
            "email": instance.contact_email.clone().unwrap_or_default(),
            "account": null
        }),
        rules: rules.into_iter().map(RuleDto::from_row).collect(),
    }))
}

/// `GET /api/v1/timelines/public`
pub async fn public_timeline(
    State(state): State<AppState>,
    MaybeAuth(auth): MaybeAuth,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    let params = query.params()?;
    // Mastodon's default here is the federated view: the client that wants this
    // instance's own posts sends `local=true`, and a caller that sends nothing is
    // asking for everything the instance stores. The visibility rules (pause,
    // silence, block, quarantine) live in `public_page`, so "everything" still
    // never includes a post this instance has decided not to show.
    let page = nodus_server_store::statuses::public_page(
        state.store().pool(),
        params,
        query.local.unwrap_or(false),
    )
    .await?;
    timeline_response(
        &state,
        page.items,
        page.next_max_id,
        params,
        "/api/v1/timelines/public",
        auth.as_ref().map(|auth| auth.0.account.id.as_str()),
    )
    .await
}

/// `GET /api/v1/timelines/home`
pub async fn home_timeline(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    auth.require_scope("read")?;
    let params = query.params()?;
    // The cache when it can answer, `statuses::home_page` when it cannot: one read path,
    // one query, and no second implementation to keep in step. See `crate::home`.
    let page = crate::home::page(
        state.store().pool(),
        state.home().map(Arc::as_ref),
        &auth.0.account.id,
        params,
    )
    .await?;
    timeline_response(
        &state,
        page.items,
        page.next_max_id,
        params,
        "/api/v1/timelines/home",
        Some(auth.0.account.id.as_str()),
    )
    .await
}

/// `GET /api/v1/timelines/list/{id}`
///
/// A list that is not the caller's answers `404 Record not found`, the same body as a
/// list that does not exist: the id must not confirm that someone else's list is real.
pub async fn list_timeline(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    auth.require_scope("read")?;
    let params = query.params()?;
    let page = nodus_server_store::statuses::list_page(
        state.store().pool(),
        &auth.0.account.id,
        &id,
        params,
    )
    .await?
    .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let path = format!("/api/v1/timelines/list/{id}");
    timeline_response(
        &state,
        page.items,
        page.next_max_id,
        params,
        &path,
        Some(auth.0.account.id.as_str()),
    )
    .await
}

/// `GET /api/v1/timelines/tag/{tag}`
///
/// The path may carry the leading `#` a client copied from a post; the store's `citext`
/// column makes the match case-insensitive.
pub async fn tag_timeline(
    State(state): State<AppState>,
    auth: Auth,
    Path(tag): Path<String>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    auth.require_scope("read")?;
    let tag = tag.trim().trim_start_matches('#');
    let params = query.params()?;
    let page = nodus_server_store::statuses::tag_page(state.store().pool(), tag, params).await?;
    let path = format!("/api/v1/timelines/tag/{tag}");
    timeline_response(
        &state,
        page.items,
        page.next_max_id,
        params,
        &path,
        Some(auth.0.account.id.as_str()),
    )
    .await
}

/// `GET /api/v1/accounts/verify_credentials`
pub async fn verify_credentials(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<AccountDto>> {
    auth.require_scope("read")?;
    Ok(Json(AccountDto::from_row(
        &auth.0.account,
        state.instance(),
    )))
}

/// `GET /healthz` — the process answers. Deliberately does not touch the database:
/// a liveness probe that fails when the database is down would restart a healthy pod.
pub async fn healthz() -> &'static str {
    "ok"
}

/// `GET /readyz` — the database answers and the schema is at head.
pub async fn readyz(State(state): State<AppState>) -> Response {
    if state.store().ready().await {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
    }
}

/// Serialises a page and adds the `Link` header clients use to continue.
async fn timeline_response(
    state: &AppState,
    rows: Vec<nodus_server_store::statuses::StatusRow>,
    next_max_id: Option<String>,
    params: PageParams,
    path: &str,
    viewer: Option<&str>,
) -> ApiResult<Response> {
    let instance = state.instance();
    let status_ids: Vec<String> = rows.iter().map(|row| row.id.clone()).collect();
    // A page of twenty authors used to cost twenty account reads and a media scan; one
    // batch reads both in a single snapshot. The id-keyed maps are not the page order, so
    // the response is still built by walking `rows`.
    let mut author_ids: Vec<String> = rows.iter().map(|row| row.account_id.clone()).collect();
    author_ids.sort_unstable();
    author_ids.dedup();
    let hydrated = state
        .store()
        .batch()
        .accounts(&author_ids)
        .media_by_status(&status_ids)
        .decorations(&status_ids)
        .run()
        .await?;
    let polls = nodus_server_store::polls::by_status_ids(state.store().pool(), &status_ids).await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(account) = hydrated.accounts.get(&row.account_id) else {
            continue;
        };
        let attachments = hydrated
            .media_by_status
            .get(&row.id)
            .map_or(&[][..], Vec::as_slice);
        let mut dto = StatusDto::from_row_with_media(&row, account, instance, attachments);
        // Tags, emoji and mentions come from the same batch as the authors: a row with no
        // decorations is absent from the map and keeps the empty lists the DTO starts with.
        if let Some(decorations) = hydrated.decorations.get(&row.id) {
            crate::statuses::apply_decorations(&mut dto, decorations, instance);
        }
        if let Some(poll) = polls.get(&row.id) {
            let document = crate::polls::document(state, poll, viewer).await?;
            dto.poll = Some(serde_json::to_value(document).map_err(|error| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
            })?);
        }
        items.push(dto);
    }

    let mut response = Json(items).into_response();
    if let Some(next) = next_max_id {
        let size = PageSize::default_max(params.limit);
        if let Some(link) = params.next_link(path, next.parse().ok(), size) {
            if let Ok(value) = HeaderValue::from_str(&link) {
                response.headers_mut().insert(header::LINK, value);
            }
        }
    }
    Ok(response)
}

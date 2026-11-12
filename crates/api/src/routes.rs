//! The HTTP surface.
//!
//! Handlers do three things and nothing else: parse the request, call the store, map
//! rows into `dto`. Domain decisions (who may see what) live in `nodus-server-store` or
//! `nodus-server-core`, so this file stays readable as a list of endpoints.

use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use nodus_server_core::{PageParams, PageSize};
use nodus_server_core::id::Id;

use crate::auth::Auth;
use crate::dto::{
    AccountDto, ConfigurationDto, InstanceV1Dto, InstanceV2Dto, RegistrationsDto, StatusDto,
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
    fn params(&self) -> ApiResult<PageParams> {
        let parse = |raw: &Option<String>, field: &str| -> ApiResult<Option<Id>> {
            match raw {
                None => Ok(None),
                Some(value) => value.parse::<Id>().map(Some).map_err(|_| {
                    ApiError::unprocessable(format!("{field} must be a valid id"))
                }),
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
        registrations: true,
        approval_required: false,
        invites_enabled: false,
        configuration: ConfigurationDto::build(instance),
    }))
}

/// `GET /api/v2/instance`
pub async fn instance_v2(State(state): State<AppState>) -> ApiResult<Json<InstanceV2Dto>> {
    let instance = state.instance();
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
            enabled: true,
            approval_required: false,
            message: None,
        },
        contact: serde_json::json!({
            "email": instance.contact_email,
            "account": null
        }),
        rules: Vec::new(),
    }))
}

/// `GET /api/v1/timelines/public`
pub async fn public_timeline(
    State(state): State<AppState>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    let params = query.params()?;
    let page = nodus_server_store::statuses::public_page(
        state.store().pool(),
        params,
        query.local.unwrap_or(true),
    )
    .await?;
    timeline_response(&state, page.items, page.next_max_id, params, "/api/v1/timelines/public")
}

/// `GET /api/v1/timelines/home`
pub async fn home_timeline(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    auth.require_scope("read")?;
    let params = query.params()?;
    let page = nodus_server_store::statuses::home_page(
        state.store().pool(),
        &auth.0.account.id,
        params,
    )
    .await?;
    timeline_response(&state, page.items, page.next_max_id, params, "/api/v1/timelines/home")
}

/// `GET /api/v1/accounts/verify_credentials`
pub async fn verify_credentials(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<AccountDto>> {
    auth.require_scope("read")?;
    Ok(Json(AccountDto::from_row(&auth.0.account, state.instance())))
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
fn timeline_response(
    state: &AppState,
    rows: Vec<nodus_server_store::statuses::StatusRow>,
    next_max_id: Option<String>,
    params: PageParams,
    path: &str,
) -> ApiResult<Response> {
    let instance = state.instance();
    // The account of each status is loaded per row for now; one join in the page query
    // will replace this once the profile fields the DTO needs are settled.
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let account = match nodus_server_store::accounts::by_id(state.store().pool(), &row.account_id).await? {
            Some(account) => account,
            // A status whose author is gone is not renderable: skip rather than 500.
            None => continue,
        };
        items.push(StatusDto::from_row(&row, &account, instance));
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

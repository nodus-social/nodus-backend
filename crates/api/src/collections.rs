//! The reader's shelves: favourited and bookmarked statuses.
//!
//! Both are plain pages over a join table; the write side already exists on the status
//! endpoints (`/statuses/{id}/favourite`, `/statuses/{id}/bookmark`), so this module only
//! reads.

use axum::extract::{Query, State};
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};

use nodus_server_core::limits::PAGE_MAX;
use nodus_server_core::pagination::PageSize;

use crate::auth::Auth;
use crate::error::ApiResult;
use crate::mastodon::PageQuery;
use crate::state::AppState;

/// `GET /api/v1/favourites`
pub async fn favourites(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    auth.require_scope("read:favourites")?;
    page(&state, &auth, query, Shelf::Favourites).await
}

/// `GET /api/v1/bookmarks`
pub async fn bookmarks(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    auth.require_scope("read:bookmarks")?;
    page(&state, &auth, query, Shelf::Bookmarks).await
}

/// Which shelf a request is for; the two behave identically apart from the query.
#[derive(Debug, Clone, Copy)]
enum Shelf {
    Favourites,
    Bookmarks,
}

impl Shelf {
    fn path(self) -> &'static str {
        match self {
            Self::Favourites => "/api/v1/favourites",
            Self::Bookmarks => "/api/v1/bookmarks",
        }
    }
}

async fn page(
    state: &AppState,
    auth: &Auth,
    query: PageQuery,
    shelf: Shelf,
) -> ApiResult<Response> {
    let params = query.params()?;
    let size = PageSize::clamp(params.limit, PAGE_MAX);
    let cursor = params.max_id.map(|id| id.to_string());
    let rows = match shelf {
        Shelf::Favourites => {
            nodus_server_store::collections::favourites(
                state.store().pool(),
                &auth.0.account.id,
                cursor.as_deref(),
                i64::from(size.get()),
            )
            .await?
        }
        Shelf::Bookmarks => {
            nodus_server_store::collections::bookmarks(
                state.store().pool(),
                &auth.0.account.id,
                cursor.as_deref(),
                i64::from(size.get()),
            )
            .await?
        }
    };

    // The shelf is a page of statuses, so it is hydrated as one: the row count must not
    // decide how many statements build the payload. The cursor comes from the page's
    // last row before hydration, and the order is the shelf query's order.
    let link = rows
        .last()
        .and_then(|row| params.next_link(shelf.path(), row.id.parse().ok(), size))
        .and_then(|link| HeaderValue::from_str(&link).ok());
    let viewer = Some(auth.0.account.id.as_str());
    let (items, _, _) = crate::pages::hydrate_statuses(state, rows, viewer, &[], None).await?;

    let mut response = axum::Json(items).into_response();
    if let Some(link) = link {
        response
            .headers_mut()
            .insert(axum::http::header::LINK, link);
    }
    Ok(response)
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::get;
    axum::Router::new()
        .route("/api/v1/favourites", get(favourites))
        .route("/api/v1/bookmarks", get(bookmarks))
}

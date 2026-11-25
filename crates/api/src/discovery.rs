//! Search, trends and the instance's own emoji.
//!
//! Search is answered from local rows. `resolve=true` additionally looks up an account
//! the reader named explicitly — a handle (`@alice@remote.test`) or a link to a profile —
//! because that is how a person is added from another instance. A bare word never leaves
//! the server: turning every keystroke into an outbound crawl is what we are avoiding, and
//! only a name with a domain can be resolved anyway.

use axum::extract::{Query, State};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use nodus_server_core::limits::PAGE_MAX;
use nodus_server_core::pagination::PageSize;

use crate::auth::MaybeAuth;
use crate::dto::{accounts_with_pictures, AccountDto, StatusDto};
use crate::error::ApiResult;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    /// Mastodon calls the term `q`; an empty one is an empty result, not an error.
    #[serde(default)]
    pub q: String,
    /// `accounts`, `statuses`, or `hashtags`. Absent means "everything", which Mastodon
    /// expresses by omitting the field rather than sending `all`.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub resolve: Option<bool>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub offset: Option<u32>,
}

/// A hashtag in the shape both search and trends use.
#[derive(Debug, Serialize)]
pub struct TagDto {
    pub name: String,
    pub url: String,
    pub history: Vec<TagHistoryDto>,
    pub following: bool,
}

/// One day of tag activity. Clients draw a sparkline from these; we report the whole
/// window as a single bucket rather than inventing a daily breakdown.
#[derive(Debug, Serialize)]
pub struct TagHistoryDto {
    pub day: String,
    pub uses: String,
    pub accounts: String,
}

#[derive(Debug, Serialize)]
pub struct SearchDto {
    pub accounts: Vec<AccountDto>,
    pub statuses: Vec<StatusDto>,
    pub hashtags: Vec<TagDto>,
}

/// `GET /api/v2/search`
pub async fn search(
    State(state): State<AppState>,
    auth: MaybeAuth,
    Query(query): Query<SearchQuery>,
) -> ApiResult<Json<SearchDto>> {
    let viewer = auth.0.as_ref();
    if let Some(auth) = viewer {
        auth.require_scope("read:search")?;
    }
    let term = query.q.trim().to_string();
    let size = PageSize::clamp(query.limit, PAGE_MAX);
    let limit = i64::from(size.get());
    let want = query.kind.as_deref().unwrap_or("all");
    let empty = SearchDto {
        accounts: Vec::new(),
        statuses: Vec::new(),
        hashtags: Vec::new(),
    };
    if term.is_empty() {
        return Ok(Json(empty));
    }

    let pool = state.store().pool();
    let instance = state.instance();
    let mut result = empty;

    if want == "all" || want == "accounts" {
        let rows =
            nodus_server_store::discovery::search_accounts(pool, &term, &instance.domain, limit)
                .await?;
        let ids: Vec<String> = rows.iter().map(|row| row.id.clone()).collect();
        let pictures = state.store().batch().profile_pictures(&ids).run().await?;
        result.accounts = accounts_with_pictures(&rows, &pictures, instance);
        if query.resolve == Some(true) {
            if let Some(row) = resolve_named_account(&state, &term, &result.accounts).await {
                let pictures = state
                    .store()
                    .batch()
                    .profile_pictures(std::slice::from_ref(&row.id))
                    .run()
                    .await?;
                let mut documents =
                    accounts_with_pictures(std::slice::from_ref(&row), &pictures, instance);
                result
                    .accounts
                    .insert(0, documents.pop().expect("one account"));
            }
        }
    }
    if want == "all" || want == "statuses" {
        let rows = nodus_server_store::discovery::search_statuses(
            pool,
            &term,
            viewer.map(|auth| auth.0.account.id.as_str()),
            limit,
        )
        .await?;
        // Search returns a page of statuses, so it pays one page hydration rather than
        // one row read per hit. The store query already applied the audience predicate;
        // hydration keeps each row's own moderated-visibility check.
        let viewer = viewer.map(|auth| auth.0.account.id.as_str());
        let (statuses, _, _) =
            crate::pages::hydrate_statuses(&state, rows, viewer, &[], None).await?;
        result.statuses = statuses;
    }
    if want == "all" || want == "hashtags" {
        let rows = nodus_server_store::discovery::search_tags(pool, &term, limit).await?;
        result.hashtags = rows
            .into_iter()
            .map(|row| tag(&state, row, false))
            .collect();
    }
    Ok(Json(result))
}

/// Looks up the account a reader named, when the term is a handle or a link.
///
/// A failure here is silent by design: the reader asked for a search, and an instance
/// that is down should narrow the answer, not fail the page. The stored row makes the
/// next lookup local.
async fn resolve_named_account(
    state: &AppState,
    term: &str,
    found: &[AccountDto],
) -> Option<nodus_server_store::accounts::AccountRow> {
    let target = crate::remote::parse_target(term)?;
    let already_known = match &target {
        crate::remote::Target::Handle { user, host } => found.iter().any(|account| {
            account.username.eq_ignore_ascii_case(user)
                && account
                    .acct
                    .rsplit_once('@')
                    .is_some_and(|(_, domain)| domain.eq_ignore_ascii_case(host))
        }),
        crate::remote::Target::Link { .. } => false,
    };
    if already_known {
        return None;
    }
    // Instances in authorised-fetch mode refuse unsigned reads, so we sign as one of our
    // own actors when we have a key to sign with.
    let signer = nodus_server_store::accounts::local_signer(state.store().pool())
        .await
        .ok()
        .flatten()
        .map(|(username, uri, key)| {
            crate::remote::Signer::new(state.instance(), &username, uri.as_deref(), &key)
        });
    let actor = match crate::remote::resolve(term, signer.as_ref()).await {
        Ok(actor) => actor,
        Err(error) => {
            tracing::debug!(%term, status = %error.status(), "could not resolve a remote account");
            return None;
        }
    };
    nodus_server_store::accounts::upsert_remote(
        state.store().pool(),
        &nodus_server_store::accounts::RemoteAccount {
            uri: &actor.uri,
            username: &actor.username,
            domain: &actor.domain,
            display_name: &actor.display_name,
            note: &actor.note,
            avatar_url: actor.avatar_url.as_deref(),
            header_url: actor.header_url.as_deref(),
            inbox_url: actor.inbox_url.as_deref(),
            shared_inbox_url: actor.shared_inbox_url.as_deref(),
            public_key_pem: actor.public_key_pem.as_deref(),
            locked: actor.locked,
            bot: actor.bot,
        },
    )
    .await
    .map_err(|error| {
        tracing::warn!(%term, %error, "could not store a resolved account");
        error
    })
    .ok()
}

/// `GET /api/v1/search` — the same answer under the older path.
///
/// Kept on purpose: stock Mastodon clients and their older `v1` search callers still use it,
/// so it is compatibility surface, not a stale alias. Do not retire it in a dead-route audit.
pub async fn search_v1(
    state: State<AppState>,
    auth: MaybeAuth,
    query: Query<SearchQuery>,
) -> ApiResult<Json<SearchDto>> {
    search(state, auth, query).await
}

/// `GET /api/v1/trends/tags`
pub async fn trending_tags(State(state): State<AppState>) -> ApiResult<Json<Vec<TagDto>>> {
    let rows = nodus_server_store::discovery::trending_tags(
        state.store().pool(),
        i64::from(nodus_server_core::limits::PAGE_DEFAULT),
    )
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| tag(&state, row, false))
            .collect(),
    ))
}

/// `GET /api/v1/trends/statuses`
pub async fn trending_statuses(
    State(state): State<AppState>,
    auth: MaybeAuth,
) -> ApiResult<Json<Vec<StatusDto>>> {
    let rows = nodus_server_store::discovery::trending_statuses(
        state.store().pool(),
        i64::from(nodus_server_core::limits::PAGE_DEFAULT),
    )
    .await?;
    // Trends are the same page shape as search: one hydration for the whole list. Only
    // anonymous/public rows reach here, but the per-row moderation gate still runs.
    let viewer = auth.0.as_ref().map(|auth| auth.0.account.id.as_str());
    let (items, _, _) = crate::pages::hydrate_statuses(&state, rows, viewer, &[], None).await?;
    Ok(Json(items))
}

/// `GET /api/v1/trends/links` — preview cards.
///
/// Cards are built when a post is rendered, not stored, so there is nothing to rank here
/// yet. An empty list is the honest answer and is what clients render as "no trends".
pub async fn trending_links() -> Json<Vec<serde_json::Value>> {
    Json(Vec::new())
}

/// One emoji, in Mastodon's shape.
#[derive(Debug, Serialize)]
pub struct EmojiDto {
    pub shortcode: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub visible_in_picker: bool,
}

/// `GET /api/v1/custom_emojis`
pub async fn custom_emojis(State(state): State<AppState>) -> ApiResult<Json<Vec<EmojiDto>>> {
    let rows = nodus_server_store::collections::custom_emojis(state.store().pool(), false).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| EmojiDto {
                shortcode: row.shortcode,
                url: row.url,
                category: row.category,
                visible_in_picker: row.visible_in_picker,
            })
            .collect(),
    ))
}

/// Turns a counted tag into the wire shape.
pub(crate) fn tag(
    state: &AppState,
    row: nodus_server_store::discovery::TagCount,
    following: bool,
) -> TagDto {
    let instance = state.instance();
    TagDto {
        url: instance.url(&format!("/tags/{}", row.name)),
        history: vec![TagHistoryDto {
            day: Utc::now().format("%Y-%m-%d").to_string(),
            uses: row.uses.to_string(),
            accounts: row.accounts.to_string(),
        }],
        name: row.name,
        following,
    }
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::get;
    axum::Router::new()
        .route("/api/v2/search", get(search))
        // Kept for Mastodon-client compatibility, not a leftover: v1 clients still call it.
        .route("/api/v1/search", get(search_v1))
        .route("/api/v1/trends/tags", get(trending_tags))
        .route("/api/v1/trends/statuses", get(trending_statuses))
        .route("/api/v1/trends/links", get(trending_links))
        .route("/api/v1/custom_emojis", get(custom_emojis))
}

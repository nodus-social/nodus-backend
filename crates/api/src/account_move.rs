//! Account migration: the aliases a profile publishes and the `Move` redirect.
//!
//! This is the local half of migration. A Move is not a delete: the old profile stays
//! readable and answers with `movedTo`, so a follower can choose to follow the new
//! account. A target only accepts a mover that it already lists in `also_known_as`; that
//! consent is what stops anyone from redirecting somebody else's followers.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use nodus_server_store::accounts::{self, AccountRow};

use crate::auth::Auth;
use crate::body::{JsonOrForm, OptionalJsonOrForm};
use crate::dto::{accounts_with_pictures, own_account_with_pictures, AccountDto};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// The most aliases one account may list, matching what Mastodon publishes.
const MAX_ALIASES: usize = 5;

/// The `acct` member both write routes read.
#[derive(Debug, Default, Deserialize)]
pub struct AcctBody {
    #[serde(default)]
    pub acct: String,
}

/// One alias as Mastodon's account-alias entity renders it.
#[derive(Debug, Serialize)]
pub struct AliasDto {
    /// The target account's id, or its actor URI when this instance has no row for it.
    pub id: String,
    pub accounts: Vec<AccountDto>,
}

/// Splits `@user@host` into the handle the store keys on.
///
/// A local suffix is dropped, exactly as `/accounts/lookup` does: the store keys a local
/// account by name alone, so `user@this-instance` must not become a search for a remote
/// account with the same name.
fn parse_handle(instance: &crate::InstanceConfig, raw: &str) -> Option<(String, Option<String>)> {
    let value = raw.trim().trim_start_matches('@');
    if value.is_empty() {
        return None;
    }
    let (username, domain) = match value.rsplit_once('@') {
        Some((username, domain)) => (username, Some(domain)),
        None => (value, None),
    };
    if username.is_empty() {
        return None;
    }
    let domain = domain
        .map(str::trim)
        .filter(|domain| !domain.is_empty() && !domain.eq_ignore_ascii_case(&instance.domain))
        .map(str::to_owned);
    Some((username.to_owned(), domain))
}

/// The local row an alias URI names, including a local row whose actor identity has not
/// been minted yet (its stored URI is the fallback URL, not the row's `uri`).
async fn account_for_uri(state: &AppState, uri: &str) -> ApiResult<Option<AccountRow>> {
    if let Some(row) = accounts::by_uri(state.store().pool(), uri).await? {
        return Ok(row.deleted_at.is_none().then_some(row));
    }
    let Some(parsed) = url::Url::parse(uri).ok() else {
        return Ok(None);
    };
    if !parsed
        .host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case(&state.instance().domain))
    {
        return Ok(None);
    }
    let Some(username) = parsed
        .path_segments()
        .and_then(|segments| segments.rev().find(|segment| !segment.is_empty()))
    else {
        return Ok(None);
    };
    Ok(accounts::local_by_username(state.store().pool(), username.trim_start_matches('@')).await?)
}

/// Resolves the `acct` a write route receives, as a handle or as an actor URI.
async fn resolve_account(state: &AppState, raw: &str) -> ApiResult<Option<AccountRow>> {
    let value = raw.trim();
    if value.starts_with("https://") || value.starts_with("http://") {
        return account_for_uri(state, value).await;
    }
    let Some((username, domain)) = parse_handle(state.instance(), value) else {
        return Ok(None);
    };
    Ok(accounts::by_handle(state.store().pool(), &username, domain.as_deref()).await?)
}

/// The URI a peer knows this account by.
fn actor_uri(state: &AppState, account: &AccountRow) -> String {
    crate::activitypub::actor_url(state, account)
}

/// `POST /api/v1/accounts/move` — point this profile at another account.
pub async fn move_account(
    State(state): State<AppState>,
    auth: Auth,
    OptionalJsonOrForm(body): OptionalJsonOrForm<AcctBody>,
) -> ApiResult<Json<AccountDto>> {
    auth.require_scope("write:accounts")?;
    let source = auth.0.account.clone();
    if source.moved_to.is_some() {
        return Err(ApiError::unprocessable("This account has already moved"));
    }
    let target = resolve_account(&state, &body.acct)
        .await?
        .ok_or_else(|| ApiError::unprocessable("This instance does not know that account"))?;
    if target.id == source.id {
        return Err(ApiError::unprocessable(
            "You cannot move to the same account",
        ));
    }
    // The source has to be its own actor before its URI can match the alias the target
    // published. This writes the identity if the account has never been fetched.
    let source = crate::activitypub::ensure_identity(&state, source).await?;
    let source_uri = actor_uri(&state, &source);
    if !target
        .also_known_as
        .iter()
        .any(|alias| alias == &source_uri)
    {
        return Err(ApiError::unprocessable(
            "The target account has not listed you in also_known_as, so it has not agreed to this move",
        ));
    }
    let target_uri = actor_uri(&state, &target);
    let row = accounts::record_move(state.store().pool(), &source.id, &target_uri)
        .await?
        .ok_or_else(|| ApiError::unprocessable("This account has already moved"))?;
    let pictures = state
        .store()
        .batch()
        .profile_pictures(std::slice::from_ref(&row.id))
        .run()
        .await?;
    Ok(Json(own_account_with_pictures(
        &row,
        &pictures,
        state.instance(),
    )))
}

/// `POST /api/v1/accounts/aliases` — record an account this profile may move to.
pub async fn add_alias(
    State(state): State<AppState>,
    auth: Auth,
    JsonOrForm(body): JsonOrForm<AcctBody>,
) -> ApiResult<Json<AliasDto>> {
    auth.require_scope("write:accounts")?;
    let source = auth.0.account.clone();
    let target = resolve_account(&state, &body.acct)
        .await?
        .ok_or_else(|| ApiError::unprocessable("This instance does not know that account"))?;
    if target.id == source.id {
        return Err(ApiError::unprocessable(
            "You cannot add your own account as an alias",
        ));
    }
    let target_uri = actor_uri(&state, &target);
    if source
        .also_known_as
        .iter()
        .any(|alias| alias == &target_uri)
    {
        return Err(ApiError::unprocessable(
            "That account is already on your alias list",
        ));
    }
    if source.also_known_as.len() >= MAX_ALIASES {
        return Err(ApiError::unprocessable(
            "An account may list at most 5 aliases",
        ));
    }
    // The store repeats both checks inside the statement, so two requests racing on the
    // last slot cannot both win.
    if accounts::add_alias(state.store().pool(), &source.id, &target_uri)
        .await?
        .is_none()
    {
        return Err(ApiError::unprocessable(
            "Your alias list changed; try again",
        ));
    }
    let pictures = state
        .store()
        .batch()
        .profile_pictures(std::slice::from_ref(&target.id))
        .run()
        .await?;
    let documents =
        accounts_with_pictures(std::slice::from_ref(&target), &pictures, state.instance());
    Ok(Json(AliasDto {
        id: target.id,
        accounts: documents,
    }))
}

/// `GET /api/v1/accounts/aliases` — the aliases this profile publishes.
pub async fn list_aliases(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<Vec<AliasDto>>> {
    auth.require_scope("read:accounts")?;
    let source = auth.0.account;
    let mut accounts = Vec::with_capacity(source.also_known_as.len());
    for uri in &source.also_known_as {
        accounts.push((uri.clone(), account_for_uri(&state, uri).await?));
    }
    let ids: Vec<String> = accounts
        .iter()
        .filter_map(|(_, row)| row.as_ref().map(|row| row.id.clone()))
        .collect();
    let pictures = state.store().batch().profile_pictures(&ids).run().await?;
    let documents = accounts
        .iter()
        .map(|(uri, row)| match row {
            Some(row) => AliasDto {
                id: row.id.clone(),
                accounts: vec![AccountDto::from_row(row, state.instance())
                    .with_pictures(pictures.profile_pictures.get(&row.id))],
            },
            None => AliasDto {
                id: uri.clone(),
                accounts: Vec::new(),
            },
        })
        .collect();
    Ok(Json(documents))
}

/// `DELETE /api/v1/accounts/aliases/{id}` — remove one alias.
pub async fn remove_alias(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_scope("write:accounts")?;
    let source = auth.0.account;
    let alias = match state.store().account(&id).await? {
        Some(row) => actor_uri(&state, &row),
        None => id,
    };
    let removed = accounts::remove_alias(state.store().pool(), &source.id, &alias).await?;
    if removed.is_none() {
        return Err(ApiError::not_found("That alias is not on this account"));
    }
    Ok(StatusCode::NO_CONTENT)
}

//! Request bodies that may arrive in either encoding Mastodon accepts.
//!
//! Mastodon is a Rails application: it reads parameters from a JSON body and from a
//! form-encoded one alike, and real clients use both — the web client posts
//! `application/x-www-form-urlencoded` to `/api/v1/apps`, while our own SDK and tests
//! post JSON. A handler that insists on [`Json`] answers 415 before such a client can
//! register itself, which is a compatibility failure, not a client mistake.

use axum::extract::{FromRequest, Request};
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::de::DeserializeOwned;

/// A body decoded from JSON or from `application/x-www-form-urlencoded`.
pub struct JsonOrForm<T>(pub T);

impl<S, T> FromRequest<S> for JsonOrForm<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let form_encoded = request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .trim_start()
                    .to_ascii_lowercase()
                    .starts_with("application/x-www-form-urlencoded")
            });
        if form_encoded {
            let Form(value) = Form::<T>::from_request(request, state)
                .await
                .map_err(IntoResponse::into_response)?;
            return Ok(Self(value));
        }
        // Everything else, including a missing content type, is left to the JSON
        // extractor's own diagnostics: it names the offending header, which is more
        // useful than a blanket 415 of our own.
        let Json(value) = Json::<T>::from_request(request, state)
            .await
            .map_err(IntoResponse::into_response)?;
        Ok(Self(value))
    }
}

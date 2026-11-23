//! The two reset pages and the two notices. Separated from the handlers so the state
//! machine reads without HTML in the middle of it.

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use leptos::prelude::*;

pub(super) fn request_form(csrf_token: &str) -> String {
    super::shell(
        "Reset your password · Nodus",
        None,
        view! {
            <h1>"Reset your password"</h1>
            <p class="muted">"Enter the address on your account and we will send a link."</p>
            <form method="post" action="/auth/password/reset">
                <input type="hidden" name="csrf_token" value=csrf_token.to_owned()/>
                <label>"Email" <input type="email" name="email" required autocomplete="email"/></label>
                <button type="submit">"Send reset link"</button>
            </form>
            <p class="muted"><a href="/auth/login">"Back to sign in"</a></p>
        },
    )
}

pub(super) fn reset_form(token: &str, csrf_token: &str, error: Option<&str>) -> String {
    super::shell(
        "Choose a new password · Nodus",
        None,
        view! {
            <h1>"Choose a new password"</h1>
            <p class="muted">"This link works once and expires in one hour."</p>
            {error.map(|message| view! { <p class="error">{message.to_owned()}</p> })}
            <form method="post" action=format!("/auth/password/reset/{token}")>
                <input type="hidden" name="csrf_token" value=csrf_token.to_owned()/>
                <label>
                    "New password"
                    <input type="password" name="password" required minlength="8" autocomplete="new-password"/>
                </label>
                <label>
                    "Confirm new password"
                    <input type="password" name="password_confirmation" required minlength="8" autocomplete="new-password"/>
                </label>
                <button type="submit">"Set new password"</button>
            </form>
        },
    )
}

pub(super) fn notice_page(title: &str, message: &str) -> String {
    super::shell(
        title,
        None,
        view! {
            <h1>{title.trim_end_matches(" · Nodus").to_owned()}</h1>
            <p class="muted">{message.to_owned()}</p>
            <p><a href="/auth/login">"Back to sign in"</a></p>
        },
    )
}

pub(super) fn gone_page() -> Response {
    (
        StatusCode::GONE,
        Html(notice_page(
            "Reset link expired · Nodus",
            "This link is no longer valid. It may have expired or already been used.",
        )),
    )
        .into_response()
}

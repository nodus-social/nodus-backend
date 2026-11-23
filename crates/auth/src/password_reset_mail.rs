//! The reset mail, kept apart from the handlers so the HTML stays readable beside the
//! rule it has to obey: one absolute link and no remote images.

use crate::store::AuthStore;
use crate::{escape_html, AppState};

/// The reset message. Like the confirmation mail it carries one absolute link and no
/// remote images, so opening it tells no third party which address was requested.
pub(super) fn reset_message<S: AuthStore>(
    state: &AppState<S>,
    username: &str,
    email: &str,
    token: &str,
) -> nodus_mail::Message {
    let base_url = state
        .email_confirmation
        .as_ref()
        .map_or("", |confirmation| confirmation.base_url.as_str());
    let link = format!(
        "{}/auth/password/reset/{token}",
        base_url.trim_end_matches('/')
    );
    let subject = "Reset your Nodus password".to_owned();
    let text = format!(
        "Hello @{username},\n\nSomeone asked to reset the password for this Nodus account. \
         If it was you, choose a new password here:\n\n{link}\n\n\
         The link is valid for one hour and can be used once.\n\
         If you did not ask for this, ignore the message; your password has not changed.\n"
    );
    let username_html = escape_html(username);
    let email_html = escape_html(email);
    let html = format!(
        "<!doctype html><html><body>\
         <p>Hello @{username_html},</p>\
         <p>Someone asked to reset the password for this Nodus account. If it was you:</p>\
         <p><a href=\"{link}\">Reset the password for {email_html}</a></p>\
         <p>The link is valid for one hour and can be used once.</p>\
         <p>If you did not ask for this, ignore the message; your password has not changed.</p>\
         </body></html>"
    );
    nodus_mail::Message {
        to: email.to_owned(),
        subject,
        text,
        html: Some(html),
    }
}

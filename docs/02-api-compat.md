# 02 — Client API compatibility

Status: draft · Last revised: 2026-11-07

Compatibility means: an app written against Mastodon's client API, with no Nodus
branch in its code, works. That is a testable claim, so this document lists the
surface and the probe that covers each group.

## What we advertise

`GET /api/v2/instance` reports a Mastodon-compatible version so apps enable the
right features. We claim **`4.3.0`** (the API generation we implement), and put our
own build in `configuration.urls` and the `X-Nodus-Version` header — not in
`version`, because apps parse it [1].

```json
{
  "domain": "social.example",
  "title": "Nodus",
  "version": "4.3.0",
  "source_url": "https://github.com/nodus-social/nodus-backend",
  "configuration": {
    "statuses": { "max_characters": 500, "max_media_attachments": 4, "characters_reserved_per_url": 23 },
    "media_attachments": { "supported_mime_types": ["image/jpeg", "image/png", "image/webp", "video/mp4"], "image_size_limit": 10485760, "video_size_limit": 41943040 },
    "polls": { "max_options": 4, "max_characters_per_option": 50, "min_expiration": 300, "max_expiration": 2629746 },
    "accounts": { "max_featured_tags": 10 },
    "translation": { "enabled": false }
  }
}
```

Features we report as unavailable are exactly the ones we do not implement:
`translation.enabled: false`, no `v2` filters, no `/api/v1/trends/links`. An app
that probes a capability and falls back is supported; an app that assumes every
endpoint exists is not.

[1] Mastodon apps compare against `4.x` semver, including the web client shipped
inside Mastodon itself.

## Conventions every endpoint shares

| Rule | Detail |
| --- | --- |
| Errors | `{"error": "…"}` with the right status; validation failures use `422` with `error` naming the field, never a bare `400` |
| Ids | opaque strings, 26-char lowercase ULIDs; `max_id`/`since_id`/`min_id` are exclusive as Mastodon defines them |
| Pagination | `limit` clamped to the endpoint's max silently; a full page returns `Link: <…?max_id=…>; rel="next"` **only when another page exists** |
| Auth | `Authorization: Bearer <token>`; unauthenticated GETs are public-timeline-scoped, unauthenticated writes are `401` |
| Scopes | `read` ⊃ public data, `write` ⊃ posting, `follow` ⊃ relationships, `push` ⊃ webpush; a missing scope is `403` with `error` naming it |
| Rate limits | `X-RateLimit-Limit/Remaining/Reset` on every authenticated response; `429` carries `Retry-After` |
| Content | `content` is sanitised HTML (see below), `plain_text`-style client rendering is not our problem |
| Timestamps | RFC 3339 with offset, always `Z` |

## HTML sanitisation

Mastodon clients render `content` as HTML. We therefore sanitise on **write** and
store the sanitised form: allow `p`, `br`, `a[href,rel,class]`, `span[class]`,
`strong`, `em`, `del`, `code`, `pre`, `blockquote`; rewrite mentions to
`<span class="h-card"><a class="u-url mention" href="…">@acct</a></span>` and
hashtags to `<a class="mention hashtag" href="…">#tag</a>`. Unknown tags are
unwrapped, not deleted, so no text is lost. Links get
`rel="nofollow noopener noreferrer"` and `target="_blank"`.

## Surface

| Group | Endpoints | M0 |
| --- | --- | --- |
| Instance | `/api/v1/instance`, `/api/v2/instance`, `/api/v1/instance/activity` | yes |
| Apps & auth | `/api/v1/apps`, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke` | yes |
| Accounts | `/api/v1/accounts/:id`, `/verify_credentials`, `/update_credentials`, `/statuses`, `/followers`, `/following`, `/follow`, `/unfollow`, `/block`, `/mute`, `/relationships`, `/search`, `/lookup` | yes |
| Statuses | `POST /api/v1/statuses`, `GET/DELETE /:id`, `/context`, `/reblog`, `/unreblog`, `/favourite`, `/unfavourite`, `/bookmark`, `/history`, `/source`, `PUT /:id` | yes |
| Timelines | `/api/v1/timelines/home`, `/public`, `/tag/:hashtag`, `/list/:id` (M2) | yes |
| Notifications | `/api/v1/notifications`, `/:id`, `/clear`, `/dismiss` | yes |
| Media | `POST /api/v2/media`, `GET /api/v1/media/:id`, `PUT /api/v2/media/:id` | yes |
| Streaming | `/api/v1/streaming` (SSE + WS): `user`, `public`, `public:local`, `direct`, `list` (M2) | yes |
| Markers, lists, filters, polls, push | as Mastodon defines them | M2 |

## How it is probed

1. **Contract tests in-repo** (`crates/api/tests`): every handler asserted against
   recorded Mastodon responses — status codes, `Link` headers, error bodies, and the
   shape of one representative payload per endpoint.
2. **A live probe** (`scripts/api-probe.sh`): registers an app, does PKCE, posts,
   reblogs, favourites, pages a timeline, opens streaming, and asserts the events
   arrive in order.
3. **Real clients, by hand**: Tusky (Android) and Mona (iOS) against a dev
   deployment. This is the only test that catches "works per spec, breaks in an app",
   so it gates the milestone rather than the pull request.

## Known deviations, stated up front

- **No `/api/v1/trends/*` in M0.** Requires aggregation we have not designed; the
  endpoint answers `404` and `configuration` does not advertise it.
- **`/api/v1/statuses/:id/history`** returns the current version only until edit
  history lands; `edited_at` is still set, so apps show the edit marker.
- **Streaming health**: the endpoint accepts both `Accept: text/event-stream` and a
  WebSocket upgrade on the same path, because some clients send the request twice
  and expect the second to upgrade.

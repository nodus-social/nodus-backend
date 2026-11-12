# 06 — Server-rendered frontend

Status: design · Last revised: 2026-11-07

`nodus-web` is a Leptos app. It is mounted **into** `nodus-server` rather than
deployed beside it, and it is **both** server-rendered and hydrated: every page is
painted on the server with its first page of data, hydrated into the same component
tree, and then continues on the client.

| Path | Server renders | Client continues |
| --- | --- | --- |
| `/@user`, `/@user/:id`, `/tags/:tag`, `/about`, `/` (signed out) | the page, `og:` tags, nothing interactive | nothing beyond routing |
| `/` (signed in), `/notifications` | page 1 of the timeline/notifications and its `max_id` cursor | hydration, infinite scroll, streaming, optimistic updates |

The signed-in shell is therefore not "CSR only": it is SSR for the first page and
CSR from the second page on. That is the difference between a feed that can be
crawled, shared and painted before JavaScript loads, and one that starts with a
spinner.

## Scope: every path, the session decides

The server renders each route, public or private. The session cookie decides which
of the two views is painted: a signed-out visitor gets the public page, an account
holder gets the authenticated one with page 1 and its cursor in the markup. Neither
is rendered and then replaced — the server never paints a stranger's page to an
account holder, which is what makes "SSR only where we are sure" unnecessary.

The client owns what a document cannot do: infinite scroll continuing the same
cursor, streaming, optimistic actions, and the OAuth callback (which has nothing to
render until it has exchanged a code).

**Unknown is a state.** Whatever the server does not know must be rendered as
missing, not as a default: a third state (`Option`), a disabled control, or nothing.
A hydrated page then never changes a value the server already painted, and a client
fetch never swaps content under the reader.

## What the server has and what the browser has

The server *issues* the OAuth token, so it already holds it in `oauth_token`; an
authenticated page can be rendered without shipping the token to anyone. The rule is
narrower than "the server never sees a token" (which would be false) and is worth
stating exactly, because the whole design rests on it:

- **Rendered output never contains a token.** Not in HTML, not in a JSON island, not
  in a `<script>`. The SSR payload carries data and cursors only.
- **The browser app keeps its own token** from the PKCE exchange, in `sessionStorage`
  as the SDK already does, and uses it for the client API and streaming.
- **SSR authenticates with a cookie**, `nodus_session`, `HttpOnly; Secure;
  SameSite=Lax`, mapped to an `oauth_token` row server-side. It carries no bearer
  material; it is a session pointer whose only privilege is "render pages as this
  account".
- Revoking a token drops both: the cookie lookup fails and the client's next request
  is `401`.

## Mounting

`nodus-web` exposes one function, compiled only with the `ssr` feature:

```rust
// nodus-web, feature = "ssr"
pub fn router(hooks: Arc<dyn PageData>) -> axum::Router {
    let leptos_options = /* … */;
    let routes = leptos_axum::generate_route_list(app);
    axum::Router::new()
        .leptos_routes_with_context(&leptos_options, routes, move || {
            leptos::prelude::provide_context(hooks.clone())   // the inversion point
        }, app)
        .fallback(leptos_axum::file_and_error_handler::<_, _>(leptos_options, app))
}
```

`nodus-server` mounts it as the fallback, so `/api/*` and `/inbox` win over the
frontend and everything else is a page:

```rust
Router::new()
    .nest("/api", api::router(state.clone()))
    .route("/inbox", post(federation::shared_inbox))
    .fallback_service(web::router(state.page_data()))
```

## The inversion point

Two dependencies are allowed and one is forbidden:

| Layer | Used by | Why |
| --- | --- | --- |
| `nodus-instance` (protocol model) and `nodus-shared` (the DTOs the two products share) — the *headless* SDK | SSR and the API | they describe what a status *is* on the wire, with no lifecycle |
| `AppState`, `Command`, `Sdk`, ports — the *stateful* SDK | the browser only | a state machine exists to make one long-lived app coherent |

The SSR render is a pure function of (request, database row): it has no subscription,
no cache policy, no pagination state, and no lifetime longer than one HTTP response.
Putting `Sdk` on the server would give it a cache it must invalidate, a `Command`
history nobody asked for, and two sources of truth for the same timeline — the
database and an in-process `AppState` that the next request would throw away.
So the server renders from headless types, and the browser hydrates into the state
machine seeded with that same first page.

`nodus-web` must not depend on `nodus-server-store` either; that would make the
frontend compile the whole schema and invert the dependency direction of the
workspace. Instead it declares the data it needs:

```rust
pub trait PageData: Send + Sync + 'static {
    fn profile(&self, acct: &str) -> impl Future<Output = Option<ProfilePage>> + Send;
    fn status(&self, id: &str) -> impl Future<Output = Option<StatusPage>> + Send;
    fn instance(&self) -> impl Future<Output = InstancePage> + Send;
}
```

The server implements it over `store` and `provide_context`s it before rendering.
Server functions are therefore not used for page data at all: they exist only for
mutations the CSR app cannot do (e.g. the OAuth code exchange), and those go through
the client API.

Because `PageData` returns headless types, the server render and the JSON the client
API emits describe the same status the same way. A field the browser needs but the SSR
payload lacks is then a compile error in one crate, not a hydration mismatch
discovered in a browser.

## Consequences

- **No double-fetch.** The SSR render loads the page's data once and hands it to the
  client through Leptos' serialised resource stream; the hydrated app does not
  re-request the profile it was just given, and the timeline's first page is seeded
  into `AppState::timelines` instead of being fetched again.
- **Infinite scroll is the client's job, on the same cursor.** The SSR page ends
  with `next_max_id`, serialised as part of the page. After hydration the SDK issues
  `Sdk::load_timeline(which, cursor, limit)` against `/api/v1/timelines/…` and appends
  — same endpoint, same cursor type, same dedupe by status id. Nothing in the scroll
  path is server-rendered, and nothing in the first paint is client-only.
- **No hydration mismatch.** Cursors and ids come from the database, not from
  timestamps computed on both sides; the client never derives a cursor from a clock.
- **The headless SDK is the only shared code.** SSR and API share DTOs; SSR and the
  browser share nothing else. A change to `AppState` cannot affect a server render,
  which is what keeps the SSR path from needing the browser's lifecycle guarantees.
- **Cards and crawlers work without JavaScript**, including `og:`/`twitter:` tags
  built from sanitised status HTML — which is what `nodus-recommender`'s `/s/` route
  does today for shared links, so that renderer can retire once this lands.
- **The dev loop needs two builds.** `trunk serve` runs the CSR app and proxies
  `/api` to the server; `cargo run -p nodus-server` runs the SSR router. The client
  API is the contract between them, so the two loops cannot drift.
- **Streaming stays client-side.** SSE/WS subscriptions are opened after hydration;
  a server render has no socket, and pretending otherwise would buffer events that
  the first paint already shows.

## What is not in scope

- No server-side streaming of timelines into HTML (an endless feed is a client
  concern; the server sends the first page and the cursor).
- No per-page code splitting beyond Leptos' route-level islands; the bundle budget in
  `nodus-web/docs/05-quality.md` stays the authority.
- No server-rendered *interaction*: every mutation still goes through the client API
  with the browser's token, so a hydrated page and a CSR page behave identically.

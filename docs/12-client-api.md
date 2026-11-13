# Client API surfaces

The server exposes three independent surfaces over one domain model.

| Surface | Prefix | Token style | Purpose |
| --- | --- | --- | --- |
| Nodus | `/api/v1/nodus` | Bearer | Batch, events and state sync for Nodus clients |
| Mastodon | `/api/v1`, `/api/v2` | Bearer | Compatibility for existing Mastodon clients |
| Misskey | `/api` | Body `i` | Compatibility for existing Misskey clients |
| ActivityPub | `/users`, `/statuses`, `/inbox` | HTTP signatures | Federation |

The surfaces share storage and policy. They do not share wire types: Mastodon DTOs stay in
`nodus-server-api::mastodon`, Misskey DTOs in `nodus-server-api::misskey`, and ActivityPub
documents in `nodus-activitypub-core`. A feature added to one surface is not automatically
a feature of another.

## Feature ownership

| Feature | Nodus | Mastodon | Misskey | ActivityPub |
| --- | --- | --- | --- | --- |
| Timeline read | batch/sync | `/timelines/*` | `/notes/*timeline` | `outbox`/`inbox` |
| Status write | planned | `/statuses` | `/notes/create` | `Create` activity |
| Reactions | planned | `/statuses/{id}/reaction` | `/notes/reactions/*` | `Like` activity |
| Follow graph | planned | `/accounts/{id}/follow` | `/following/*` | `Follow` activity |
| Notifications | planned | `/notifications` | `/i/notifications` | `Create`/`Follow` |
| Streaming | events SSE | `/api/v1/streaming` | `/streaming` | inbox delivery |

## Administration

Administration is not a protocol surface. The routes live under `/api/v1/admin` and require
an account with `admin:read` or `admin:write`.

- `GET /admin/reports?state=&limit=`, `POST /admin/reports/{id}/resolve|reopen`
- `GET /admin/accounts?local=&limit=`, `GET /api/v2/admin/accounts?status=pending`
- `POST /admin/accounts/{id}/action` with form `type=approve|reject|silence|suspend|enable`
- `GET|POST /admin/domain_blocks`, `DELETE /admin/domain_blocks/{id}`
- `GET|POST /admin/domain_allows`, `DELETE /admin/domain_allows/{id}`
- `POST /admin/measures` (`new_users`, `statuses`, `interactions`, `reports`)
- `GET /admin/audit`
- `GET /admin/alerts`, `POST /admin/alerts/{id}/ack`
- `POST /admin/accounts/{id}/lossless`

Every mutation writes an `audit_log` row with actor, action, target and detail. A rejected
account cannot authenticate (`account.approved` is checked with the token); a suspended
account is rejected by the same query. Reports are user-facing and separated from the
operator audit trail.

## Protocol detection

`nodus-client-sdk` exposes `protocol::Probe` for documents a caller already fetched, and
`protocol::detect(base)` behind the `native` feature for native clients. Detection order is
Nodus, Misskey, Mastodon. A missing document is evidence of absence, not an error. The
chosen `Protocol::endpoints()` selects the timeline and instance paths and whether the token
travels as a bearer header or a Misskey body field.

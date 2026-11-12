# 10 — Authentication and identity

Status: design · Last revised: 2026-11-13

There are two different jobs called "auth" here, and mixing them is how a
Mastodon-compatible server ends up with a login flow no Mastodon app can use:

1. **Client authorization** — a third-party app gets a scoped token for one account.
   This must be the Mastodon OAuth flow, because that is what existing apps speak.
2. **Account authentication** — a person proves who they are to the instance. This
   can be local, or delegated to an OIDC provider such as a Nodus Auth service.

The server supports both, but they meet at one place: after either flow succeeds,
the server issues the same opaque, scoped token.

## Default: built-in OAuth 2.1 authorization server

A fresh instance works with no external identity provider:

- `POST /api/v1/apps` registers a client (name, redirect URIs, scopes, website).
- `GET /oauth/authorize` shows consent and requires **PKCE** (`S256`) for public
  clients; the code is single-use and expires in 10 minutes.
- `POST /oauth/token` supports `authorization_code` and `refresh_token`.
- `POST /oauth/revoke` revokes an access or refresh token.
- Access tokens are opaque random values, stored only as a SHA-256 digest. They
  carry Mastodon scopes (`read`, `write`, `follow`, `push`) and an account id.
- Refresh tokens rotate on use; reuse of a rotated token revokes the family.

The authorize page is rendered by `nodus-web` when present, and by a minimal
server-rendered form when the frontend is not mounted. Neither ever puts a token in
HTML.

This is deliberately the **Mastodon client flow**, not a new one. Tusky, Mona and
the Mastodon web client must not need a Nodus branch.

## Optional: external OIDC provider (MAS-like)

For an instance that already has an identity system — or wants one login across
several services — the account-authentication step can be delegated to an OIDC
provider. The model is the same one Matrix Authentication Service uses: the
application is an OAuth client of the identity provider, and the provider owns
login, MFA, password reset and session policy.

```text
browser ──▶ nodus /oauth/authorize
              │  (no local session)
              ▼
         Nodus Auth / OIDC provider
              │  authorization code + PKCE
              ▼
         nodus callback ──▶ local account lookup by `sub`
              │
              ▼
         Mastodon authorization code ──▶ app /oauth/token
```

Configuration:

```toml
[auth]
mode = "local"                 # local | oidc
issuer = "https://auth.example"
client_id = "nodus"
client_secret_ref = "env:NODUS_OIDC_SECRET"
scopes = ["openid", "profile", "email"]
account_claim = "sub"          # stable, never email
auto_provision = false         # true only for trusted providers
```

Rules:

- The OIDC `sub` is the identity key. Email and username may change; `sub` must not.
- `auto_provision = false` by default: an unknown `sub` is rejected, not silently
  given an account. Provisioning is an explicit admin/invite flow.
- The provider authenticates the person; Nodus still authorizes the *client* and
  issues the Mastodon token. An OIDC token is never accepted as a Mastodon bearer
  token.
- Group/role claims can map to moderator/admin, but only from a configured claim and
  only when the provider is trusted for it.
- Logout revokes the local session and, when the provider supports it, ends the
  provider session; it does not revoke unrelated app tokens.

The external service is optional. In the monolith, `mode = "local"` uses the
built-in endpoints; `nodus-auth` is a separate deployment only when an operator
wants SSO or centralized account lifecycle.

## What is never done

- No custom login protocol for third-party apps. Mastodon apps get Mastodon OAuth.
- No password grant. It is removed from OAuth 2.1 and encourages credential
  collection by clients.
- No token in a URL fragment, query string, HTML island or SSR payload.
- No implicit flow. Authorization code + PKCE only.
- No "trusted" redirect URI matching by prefix; exact match after normalization.

## Federation identity is separate

ActivityPub actor keys are not user login credentials. An actor's RSA key signs
server-to-server requests; a person's OIDC identity authenticates them to this
instance. The two are linked only by the local account row, and rotating one does
not rotate the other.

## Deployment

| Mode | Processes | Use |
| --- | --- | --- |
| local | `nodus` only | default, small instance |
| oidc | `nodus` + external IdP | SSO, MFA, existing identity system |
| split | `nodus-api` + `nodus-store` + IdP | larger deployment; auth stays HTTP, not gRPC |

The OIDC discovery document is served by the provider, not by Nodus. Nodus exposes
its own `/.well-known/oauth-authorization-server` only for the built-in mode.

# Service boundaries

The server is a monolith by default, but not an unstructured one. Domain services are
separate crates with their own contracts, and the same contract is used whether the
call stays in-process or crosses a process boundary.

## Decision

- **Crates are the boundary.** `accounts`, `statuses`, `timelines`, `federation`,
  `media`, `search`, `notifications` and `store` own their data and expose a service
  trait plus a protobuf contract. No service reaches into another service's tables.
- **gRPC is the contract, not the default transport.** In the monolith the runtime
  composes in-process adapters that implement the generated service trait. In split
  mode the same trait is implemented by a generated gRPC client. This keeps one
  contract and avoids paying serialization and loopback latency for every local call.
- **Strict mode exists for verification.** `--ipc=grpc` starts each service's gRPC
  server on a Unix domain socket and wires the clients through it. `--ipc=local` uses
  the in-process adapters. Strict mode is for integration tests, boundary checks and
  reproducing split-mode failures; it is not the production default.
- **No separate Tokio runtime per service.** Services are tasks in one runtime. A
  second runtime inside the same process adds shutdown races and thread-pool
  fragmentation without creating a real isolation boundary.
- **Auth is the exception.** `nodus-auth` is a separate deployable because it renders
  SSR pages, owns the login/consent surface and may be operated with a different
  security policy. It can also be mounted into the monolith behind the `auth` feature;
  the handlers and storage trait are the same.

## Runtime modes

| Mode | Composition | Transport |
| --- | --- | --- |
| `monolith` | one process, all services | in-process adapters |
| `monolith --ipc=grpc` | one process, service tasks | gRPC over Unix sockets |
| `split` | api/worker/auth processes | gRPC over TCP with mTLS |
| `embedded` | api + selected services | in-process adapters |

## Authentication

Every RPC that crosses a process boundary carries `x-nodus-service-secret`.
The server interceptor validates it with `nodus_service_sdk::SharedSecret::verify`
before the request reaches the service trait; the client attaches it with
`SharedSecret::attach`. A missing, empty or wrong secret is an authentication
error, never an anonymous request. Each service gets its own secret in split
mode so one compromised service cannot call every other service.

In-process adapters do not carry the secret because no process boundary exists.
`--ipc=grpc` and split mode always do. mTLS remains transport hardening; it does
not replace the per-service secret. `/healthz` and `/readyz` stay on a separate
unauthenticated listener with no service methods.

## Enforcement

- A service crate may depend on `proto`, `core` and its own store module, never on
  another service crate's implementation.
- The API gateway depends on service traits, not on SQL.
- `store` is the only crate that opens a `PgPool`; every other crate receives a
  repository interface.
- CI runs the workspace with `--ipc=grpc` for the contract tests, so a handler that
  bypasses its service boundary fails before merge.

## Consequences

The monolith remains one deployable and one database, but the call graph is explicit and
the split path is exercised. The cost is maintaining protobuf contracts and two
adapters per service; the benefit is that “extract this service later” is a deployment
change, not a rewrite.

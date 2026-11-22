# The media cluster

Media is content-addressed, so the cluster needs no index of "which node has that file":
the digest and the member list are enough to say where a blob belongs, and a request can
be routed there before anything is looked up. What the cluster does need is for every node
to agree on the member list, for a node that owns bytes it has not received yet to be able
to fetch them, and for a replica that quietly lost a file to be noticed and refilled.

This document describes the placement rule, the membership contract, the routes nodes use
to talk to each other, the read and write paths, the range rules both paths obey, the repair
walk, the proof that runs two nodes on one host, and the two limits that no amount of code
removes.

Everything here is off until `NODUS_MEDIA_CLUSTER_TOKEN` is set. A single node with no
token registers itself, serves from its own disk, and never calls a peer; the internal
routes are not even registered, so they answer the same 404 as any unknown path.

## Placement: rendezvous hashing

`crates/media/src/cluster.rs` ranks members for a digest with a highest-random-weight
score:

```text
score(digest, name) = first 8 bytes, big-endian, of SHA-256(digest || NUL || name)
```

The NUL is a separator, not a delimiter: without it `"ab" + "c"` would hash the same as
`"a" + "bc"`, and two different pairs would collide by construction.

The owner is the highest score. The replica is the next one, and replication is that
ranking cut at `REPLICAS = 2`, clamped to the number of members and never zero when there
is a member. Ties are broken by name ascending, so two processes given the same rows always
pick the same owner no matter what order the database returned them in. That matters
because the ranking is recomputed independently on every node, on every request; there is
no consensus step to reconcile a disagreement.

Rendezvous rather than `hash % n` because adding a node moves only the keys that node now
wins — about `1/n` of them — instead of reshuffling almost everything. The test
`adding_a_member_moves_fewer_than_half_of_the_digests` is a sanity bound on that, not a
proof of the hash.

One literal answer is pinned: `a_known_digest_has_a_known_owner` asserts that the
all-zero digest over members `alpha`, `beta`, `gamma` ranks `gamma`, `alpha`, `beta`. A
refactor may change the ranking of everything else, but not by accident — changing this
test has to be deliberate, because it is the only thing that would notice a silent change
of the formula, and a silent change means every node that did not restart disagrees about
where the bytes are.

`MEMBER_MAX_AGE` is 600 seconds: a node whose last heartbeat is older than that is not a
placement target anywhere. That is the membership window, not a timeout — see below.

## Membership: the heartbeat contract

A media node writes one row into `media_node` and keeps writing it:

| variable | default | meaning |
| --- | --- | --- |
| `NODUS_MEDIA_NODE` | the bind address as text | this process's name in the table |
| `NODUS_MEDIA_ENDPOINT` | `http://127.0.0.1:<port>` | where peers should reach it |

The name is the identity: the heartbeat is an upsert on `name`, so a node restarted on a
new address replaces its own row rather than accumulating one per address, and no operator
has to edit a member list. Two processes on one host must therefore be given two names —
`NODUS_MEDIA_NODE=a` and `NODUS_MEDIA_NODE=b` — or the second heartbeat overwrites the
first and the cluster is one member pretending to be two.

The beat is every **15 seconds** (`HEARTBEAT_EVERY` in `services/media/src/main.rs`). A
missed beat is not a removal: the row stays a placement target for `MEMBER_MAX_AGE` (600 s,
forty beats), which is long enough that a restart or a slow database never takes a healthy
node out of the ring. Once per ten minutes (`FORGET_EVERY = 40` beats) the same task deletes
rows older than that window, so a decommissioned node does not linger forever.

`media_nodes::members` filters by age and orders by name, and the ordering is part of the
contract: placement breaks ties by name, and every process must see the same list in the
same order.

## The internal routes

Peers talk over four methods on one path, plus one view:

| route | what it does |
| --- | --- |
| `PUT /internal/media/{digest}` | store these bytes (verified against the digest), replicate them behind the answer |
| `GET /internal/media/{digest}` | the raw bytes, no catalogue check |
| `HEAD /internal/media/{digest}` | presence only, without reading the file |
| `DELETE /internal/media/{digest}` | delete here and fan out to every member |
| `GET /internal/placement/{digest}` | `{owner, replicas, local}`, for an operator or a peer checking its view |

Every one of them — including `HEAD`, which would otherwise tell an unauthenticated caller
which digests a node holds — requires the header `x-nodus-cluster: <token>` where the token
is `NODUS_MEDIA_CLUSTER_TOKEN`. It is compared in constant time over equal lengths; a wrong
or missing token is a 401.

`PUT` hashes the body and refuses a mismatch with a 400, so a corrupt or malicious send
cannot occupy the address of content it does not match. The digest itself must be 64
lowercase hex characters: it becomes a file name, and that check is what keeps `..` and
slashes out of the path. Writes land in a temporary name beside the target and are renamed
into place, so a reader sees either the previous state or the whole new file. A `PUT` for a
digest already present answers 200 without writing; a new one answers 201. Bodies are capped
at 64 MiB (`MAX_INTERNAL_UPLOAD`), well above the 40 MiB upload limit, as defence against a
peer that sends more.

`DELETE` fans out to **every** member, not only the current placement, because a replica
that stopped being in the placement keeps its copy and only a fan-out reaches it. The peer
that receives the fan-out marks it with `x-nodus-no-fanout` and does not pass it on, so two
nodes cannot bounce one delete back and forth.

## The read path

`GET /media/{id}` reads the catalogue row and then tries, in order:

1. **Local disk** — `NODUS_MEDIA_DIR/{digest}`. This is the normal case and the only case in
   an unclustered instance.
2. **Peers** — on a local miss, `copy_from_placement` reads the member list, takes the
   placement for the digest with this node excluded, and asks each peer in ranking order.
   Each peer gets `PEER_DEADLINE` (2 s) and the whole search gets `PEER_BUDGET` (6 s), so a
   cluster of dead peers becomes a fast 404 instead of a hung request. A peer that answers
   404, or with bytes that do not hash to the digest, is a miss and the next peer is tried.
   The bytes that arrive are written here with the same atomic rename, so the next read is
   local: that is read repair, and it is why a node can own a digest it has never seen.
   Concurrent misses for one digest share one fetch — a single-flight map keyed by digest —
   and the others wait and re-read the file.
3. **The variant ladder** — `compressed`, then `preview`, from
   `NODUS_MEDIA_VARIANTS_DIR`. A variant is only ever read from local disk; peers are never
   asked for one. `/media/{id}/{layer}` tries its own layer first and then falls back to the
   same ladder through `serve`.

If all three are empty the answer is 404. A suspended or deleted account is a 404 before any
of this, at every layer.

## Range requests

A client that seeks sends `Range: bytes=…`, and the media node answers it, because the bytes
are what it holds. Both public routes and the internal read go through one helper for the
slice, so the rules cannot drift between the API-facing and peer-facing answers:

| route | no `Range` | one satisfiable range | a range naming no byte | anything else |
| --- | --- | --- | --- | --- |
| `GET /media/{id}` | 200, whole original | 206 + `Content-Range: bytes a-b/len` | 416 + `Content-Range: bytes */len` | 200, whole original |
| `GET /media/{id}/{layer}` | 200, whole variant | 206 over the variant's bytes | 416 with the variant's length | 200, whole variant |
| `GET /internal/media/{digest}` | 200, whole digest | 206 | 416 | 200 |

`Accept-Ranges: bytes` is on every byte answer, and `Content-Length` is the length actually
sent: a 206 declares the slice, not the object, and a 416 carries no body at all — its
`Content-Range` is the only part a client can act on. `/media/{id}/{layer}` falls back to the
original when the layer is absent, and the range is applied to whichever bytes the answer
carries, so a client never receives a slice of one representation with the length of another.
A variant is only ever served from local disk, so ranged variant reads never ask a peer.

Multi-range requests (`bytes=0-1,5-6`) are not supported. RFC 9110 lets a server ignore a
range it cannot serve, so they are treated as unparseable and answered with the whole
representation: a 200 is an answer every client can use, while a 416 for a header the client
meant as two slices is not. `/media/default-avatar.png` and `HEAD /internal/media/{digest}`
take no range at all — the first is one small static picture, and the second reports
presence, not length.

## Writes: replicate on write, and where variants live

An upload is accepted by the API process, which computes the digest and hands the original
to a media node when `NODUS_MEDIA_CLUSTER_URL` and `NODUS_MEDIA_CLUSTER_TOKEN` are both set:

```http
PUT {NODUS_MEDIA_CLUSTER_URL}/internal/media/{digest}
x-nodus-cluster: <token>
```

with a 10-second timeout. Any 2xx means the node owns the digest and the API writes nothing
under `NODUS_MEDIA_DIR`. Any other answer — 4xx, 5xx, a connection that never lands inside
the timeout — falls back to the local write with a warning, because the user has already
sent the bytes and a media node that is down must not turn that into a failed upload. With
either variable unset the upload path is byte-for-byte what it was before the cluster
existed.

The node that accepted the `PUT` replicates behind the answer: the client is not made to
wait for a peer, and a peer that is down cannot fail a stored upload. One digest is offered
to one peer up to three times with 200 ms, 1 s and 4 s between attempts, re-reading the
file from disk before each send so a copy that was deleted in the meantime is not pushed.
The whole replication of one digest is bounded by `REPLICATION_BUDGET` — **10 seconds** — so
a cluster of silent peers cannot leave one task per upload running forever. A peer that
answers success is done; a peer that never does is a warning in the log and nothing more.

Variants stay local. This process renders them into `NODUS_MEDIA_VARIANTS_DIR` from the
bytes it already holds — from a scratch copy of the original when the cluster took it, and
the scratch copy is removed as soon as the variants exist. A media node never generates a
variant: on a read of a layer it does not have, it serves the original instead, so the
original is the only byte path the cluster carries, and the peer path "regenerates" nothing
but the original.

Deletes go the other way: `delete_original` asks the media service
(`NODUS_MEDIA_INTERNAL_URL`, default `http://127.0.0.1:3003`) to delete the digest, which
fans the delete out to every member and answers once its own peers were tried (15-second
budget). If that call does not confirm, the API unlinks its local copy exactly as before.

### When a node dies mid-upload

A `PUT` is one request: the node receives the body, hashes it, writes it beside the target
as `.{digest}.{ulid}.part`, and renames it to `{digest}` only once the whole body arrived and
matched. A node that dies half-way never reaches the rename, so the digest is simply absent
from that node. There is no half-written file under the digest's name for a reader to find,
because reads open `{digest}` and nothing else. The abandoned `.part` is waste on disk, not
damage: it sits outside the digest namespace, no read or peer fetch can pick it up, and a
later upload of the same bytes writes its own temp file and renames over the target.

What the client sees depends on how far the request got:

- **The API never got a 2xx** — a reset connection, a timeout, a 5xx — so it falls back to
  writing the bytes under its own `NODUS_MEDIA_DIR` and the upload still answers 201, with a
  warning in the log. The client is never told that a node died.
- **The upload was retried** and landed on a live node, so the bytes are stored normally and
  the dead node's gap is not the client's problem.

Meanwhile the media id has not been handed out yet, because the upload has not answered, so
no reader can be asking for it. If one does — a retry racing the first attempt, or the id
reached a reader some other way — the read is the ordinary miss: a peer that holds the digest
answers, and when no peer holds it the answer is the 404 every missing digest gets. The
half-written temp file is not visible in either answer.

## The repair pass

Replication on write is best effort, so a digest written while a peer was down would stay
missing on that peer until something noticed. The repair walk is that something: every
**ten minutes** (`REPAIR_EVERY`) — and for the first time after `min(60 s, cadence)` — each
node pages the catalogue 500 rows at a time, recomputes the placement per page, and:

- takes a copy from a peer when this node's own file is missing (`repaired`),
- pushes the local copy to a replica that does not have it (`pushed`),
- counts digests no member holds at all (`unreadable`),
- counts copies held outside the current placement (`extra`).

It **never deletes**. A membership change moves keys for a moment, so a copy that looks
extra today may be what protects the digest until the next write repairs the new owner;
deleting it would be a loss no later pass could undo. Extras are counted so drift is
visible.

One line per pass, at INFO:

```text
media repair pass repaired=<n> pushed=<n> unreadable=<n> extra=<n>
```

The cadence is `NODUS_MEDIA_REPAIR_SECS` when set, which exists so a proof can watch a pass
instead of waiting ten minutes. A value that is not a number stops the process — a
deployment mistake, not a silent default. `NODUS_MEDIA_REPAIR=off` leaves the walk to
another node.

## Proving it

`deploy/proof/media-cluster.sh` starts two nodes on one host against one throwaway
database, breaks things on purpose and checks each promise:

```sh
DATABASE_URL=postgres://nodus:nodus@localhost:5432/nodus ./deploy/proof/media-cluster.sh
```

It refuses a database that is not obviously disposable: the name must end in `_proof`, or
`DATABASE_URL_ALLOW=1` must say you know what you are doing; otherwise it derives
`<name>_proof` and creates it. Both nodes run from the workspace's debug binaries against
their own storage directories under a temporary root, on ports 3901 and 3902
(`PORT_A`/`PORT_B`), with `NODUS_MEDIA_REPAIR_SECS=2` so a pass happens while the script
waits. `KEEP=1` leaves the temporary root, both logs and both env files for a post-mortem.

What it asserts, one `ok <name>` or `FAIL <name>` per check (19 in all, any failure exits
non-zero):

1. `PUT` an original to node A is a 201.
2. A's replicate-on-write reaches B: `HEAD` 200 and identical bytes.
3. Delete A's file: A still answers 200 with the right bytes, and the file is back on disk —
   the miss was fetched from B and written down.
4. `curl -r 0-3` the public route on A: a 206, a `Content-Range: bytes 0-3/…` header, and
   exactly the first four bytes of the original.
5. Delete both, require 404, `PUT` to A again, wait for B, delete B's copy, and require the
   repair walk to put it back (nothing wrote to B this time).
6. Kill A: B still serves, and a miss on B is a 404 inside the peer budget rather than a
   hang on a dead peer.

If the workspace cannot even load — the development container mounts this repository
without its siblings — the script re-runs itself in `rust:1-bookworm` with the whole
superproject mounted, which is the same image the deploy builds in.

## Running two nodes behind Caddy

When a second media node exists, the website needs to route to it. Hash the request URI so
the same `/media/{id}` always lands on the same node, and give Caddy a couple of seconds to
try another one:

```caddyfile
nodus.luxuride.eu {
	handle /media/* {
		reverse_proxy 10.0.0.11:3003 10.0.0.12:3003 {
			lb_policy hash {http.request.uri}
			lb_try_duration 2s
		}
	}
}
```

`hash {http.request.uri}` is the important half: with round-robin, half the requests for a
digest would land on the node that does not own it — correctness survives, because a miss
fetches from the peer and the repair walk refills it, but every such request pays the peer
fetch and writes a copy on a node placement said should not have one. Hashing the URI puts
each digest on its owner, and `lb_try_duration 2s` covers the case where that owner is
restarting.

Uploads do not go through this: the API writes an original with its own `PUT` to
`NODUS_MEDIA_CLUSTER_URL`, and that name may be this same site vhost because the hash sends
it to the owner anyway.

### Two nodes on CT 118

The production instance runs both media nodes on one container, because that is where its
storage is:

| unit | port | `NODUS_MEDIA_NODE` | `NODUS_MEDIA_DIR` | telemetry socket |
| --- | --- | --- | --- | --- |
| `nodus-media` | 3003 | `media1` | `/mnt/nodus-media` (Storage Box mount) | `media-telemetry.sock` |
| `nodus-media2` | 3005 | `media2` | `/var/lib/nodus/media-b` | `media2-telemetry.sock` |

`nodus-media` takes everything from `/etc/nodus-backend.env` and adds only a name, through
`/etc/systemd/system/nodus-media.service.d/10-node.conf`: the heartbeat is an upsert on the
name, so two unnamed nodes would keep overwriting one row and the cluster would be one
member pretending to be two.

`nodus-media2.service` reads two environment files: the shared one, then
`/etc/nodus-media2.env`. That order is the mechanism, not a detail. systemd lets a later
`EnvironmentFile=` override an earlier one, while values from those files override
`Environment=` — so a `NODUS_MEDIA_DIR=` written in the unit would lose to the shared
file's `/mnt/nodus-media`, and node 2 would quietly serve node 1's directory. The name, the
directory and the telemetry socket therefore live in the second file, which is read last.

**The storage is a trade-off, not a posture.** Node 1 is the Storage Box mount; node 2 is
local disk on CT 118 (8 GB, and not durable across a rebuild). That is enough to prove the
mechanism — placement, replicate-on-write, peer fetch, repair — and it is not two replicas
in any useful sense: the same host, its power and its kernel are still a single point of
failure, and neither copy is a backup. Two directories on the same FUSE mount would prove
less still, because a "replica" there is the same bytes behind the same mount.

The cluster token is one line in the shared env file — `openssl rand -hex 32` into
`NODUS_MEDIA_CLUSTER_TOKEN`, file `0640 root:nodus` — so both media units and both API
units see it. The API pair write originals through `NODUS_MEDIA_CLUSTER_URL`
(`http://10.0.1.18:3003` in production); that node answers, replicates to the placement
peer, and the front door serves the digest from whichever node Caddy hashes it to.

The Caddy block above is the one in `/etc/caddy/nodus.caddy` on CT 100, with two changes
forced by the installed version: the policy is spelled `lb_policy uri_hash` (this build of
Caddy 2.6 names the request-URI hash that way; upstream 2.7 spells it
`hash {http.request.uri}`) and the upstreams are `10.0.1.18:3003 10.0.1.18:3005`. The
intent is unchanged: one blob resolves to one node, and `lb_try_duration 2s` lets the other
answer while that node restarts.

To run the proof against the running pair, from inside CT 118:

```sh
set -a; . /etc/nodus-backend.env; set +a
MODE=external PORT_A=3003 PORT_B=3005 NODE_A=media1 NODE_B=media2 \
  STORE_A=/mnt/nodus-media STORE_B=/var/lib/nodus/media-b \
  CLUSTER_TOKEN="$NODUS_MEDIA_CLUSTER_TOKEN" \
  PUBLIC_URL=https://nodus.luxuride.eu STOP_UNIT_A=nodus-media \
  DATABASE_URL="$NODUS_DATABASE_URL" REPAIR_WAIT=420 \
  ./deploy/proof/media-cluster.sh
```

`MODE=external` starts nothing and creates no database: it seeds one throwaway catalogue
row and one throwaway variant, removes both rows and both files on the way out, and stops
`nodus-media` for the dead-peer check and starts it again. Every file it deletes it created
itself, under a digest computed from its own payload; the instance's data is never touched.
`PUBLIC_URL` is the front door, so the range and read-repair checks go through Caddy rather
than around it. `REPAIR_WAIT` is longer than the lab's because a production node keeps the
ten-minute cadence and its first pass lands about a minute after it starts.

## Two limits, in plain words

**R=2 on one host buys nothing against that host.** Two processes with two storage
directories on one machine protect against a process crash, a corrupt file, a bad upload —
and nothing else. The host's disk, its kernel, its power supply and its network are still a
single point of failure for both copies; losing the machine loses the owner and the replica
together. Replication only starts to mean durability when the nodes are on different
machines, ideally in different places.

**There is no backup.** Nothing here writes a second copy anywhere else, no object store
receives a blob, and nothing preserves a digest that every node has lost. A blob survives
only while some node holds it: delete it everywhere, lose both disks, or let a prune remove
the last copy, and the bytes are gone. The cluster makes copies, it does not make archives.

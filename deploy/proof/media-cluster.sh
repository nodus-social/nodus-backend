#!/usr/bin/env bash
#
# Two media nodes, one host, one throwaway database: every promise the cluster makes,
# checked and printed one line at a time.
#
#   DATABASE_URL=postgres://nodus:nodus@localhost:5432/nodus ./deploy/proof/media-cluster.sh
#
# The cluster is a rendezvous hash over the members in `media_node`, replicate-on-write on
# upload, a peer fetch on a read miss, and a repair walk that pushes what a peer lost. None
# of that is visible in a single-node deployment, so the only way to know it works is to run
# two nodes and break things on purpose. This script does, in order:
#
#   1. PUT an original to node A and require 201.
#   2. Wait for A's replicate-on-write to reach B: HEAD 200 and identical bytes.
#   3. Delete A's file; require A still answers, and require the file is back on disk —
#      the read miss fetched it from B and wrote what it fetched.
#   4. Read bytes 0-3 of the original through A's public route and require a 206 carrying
#      `Content-Range` and exactly those four bytes — the API is not in this path. Then read
#      the same four bytes of a variant through `/media/{id}/{layer}`, which reads a
#      different file through the same slicing code.
#   5. Delete both files; require 404. PUT to A again, wait for the replica, delete B's
#      copy, and require the repair walk puts it back (nothing wrote to B this time).
#   6. Kill A; require B still answers, and require a miss on B is a 404 that arrives
#      inside the peer budget instead of hanging on a dead peer.
#
# Each check prints `ok <name>` or `FAIL <name>`, and any failure exits non-zero, so the
# output is the evidence and the exit status is the verdict.
#
# It will not touch a database that is not obviously disposable. The name must end in
# `_proof`, or `DATABASE_URL_ALLOW=1` must say you know what you are doing; otherwise the
# script derives `<name>_proof` and creates it. The database is created when absent, since
# the point of a proof database is that it can be thrown away.
#
# Both nodes run from the workspace's own debug binaries against fresh storage directories
# in a temporary root, and both are killed on the way out. `KEEP=1` leaves that root in
# place for a post-mortem.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
PORT_A=${PORT_A:-3901}
PORT_B=${PORT_B:-3902}
NODE_A=${NODE_A:-a}
NODE_B=${NODE_B:-b}
TOKEN=${CLUSTER_TOKEN:-proof}
# The repair cadence the two nodes are given. Short enough that a pass happens while the
# script waits, long enough that a replicate-on-write cannot be mistaken for a repair.
REPAIR_SECS=${REPAIR_SECS:-2}
MEDIA_ID=proof-media-0001
# The variant hangs off a second id. `/media/{id}` answers with a variant when its own file
# is gone (the route falls back down the layer ladder), so a variant on the id above would
# make section 4's "both copies gone still answers" check read 200 and mean nothing. The
# second row names the same blob: deduplication is a thing the schema allows, and it keeps
# the repair walk with one digest to think about.
VARIANT_ID=proof-variant-0001

now_ms() { date +%s%3N; }
say() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }

ok=0
bad=0
pass() { ok=$((ok + 1)); printf 'ok   %s\n' "$1"; }
fail() { bad=$((bad + 1)); printf 'FAIL %s\n' "$1"; }

# `expect <name> <wanted> <got>`: the assertion form used for everything that is a single
# answer rather than a wait.
expect() {
    if [[ "$3" == "$2" ]]; then
        pass "$1"
    else
        fail "$1 (wanted '$2', got '$3')"
    fi
}

# `wait_until <name> <seconds> <command...>`: polls a predicate. It always returns 0 so a
# failed wait does not end the script under `set -e`; the failure is recorded and the later
# checks report what the missing step actually broke.
wait_until() {
    local name=$1 seconds=$2
    shift 2
    local deadline
    deadline=$(($(now_ms) + seconds * 1000))
    while :; do
        if "$@"; then
            pass "$name"
            return 0
        fi
        if (($(now_ms) >= deadline)); then
            fail "$name (gave up after ${seconds}s)"
            return 0
        fi
        sleep 0.2
    done
}

status_of() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@" 2>/dev/null || true
}
is_status() { [[ "$(status_of "$2")" == "$1" ]]; }

# The internal routes are the peer's view: the token goes on every one of them, including
# HEAD, because a HEAD that skipped the check would tell an unauthenticated caller which
# digests a node holds.
internal() { printf 'http://127.0.0.1:%s/internal/media/%s' "$1" "$DIGEST"; }
head_status() {
    curl -s -o /dev/null -I -w '%{http_code}' --max-time 5 \
        -H "x-nodus-cluster: $TOKEN" "$1" 2>/dev/null || true
}
has_digest() { [[ "$(head_status "$(internal "$1")")" == 200 ]]; }

# ---------------------------------------------------------------- the throwaway database

: "${DATABASE_URL:?set DATABASE_URL to the postgres server the proof may use}"

# This repository's workspace needs its siblings (`../../../server-sdk`, `../../../sdk`), and
# the dev container that is opened on this repository alone mounts neither. When cargo cannot
# load the workspace, the proof runs itself in the image the deploy builds in, with the whole
# superproject mounted at the paths cargo already has fingerprints for. The nodes still bind
# loopback, and `--network host` keeps `localhost:5432` meaning the database the caller named.
if [[ ${PROOF_IN_CONTAINER:-0} != 1 ]] && ! cargo metadata --no-deps --format-version 1 \
    --manifest-path "$ROOT/Cargo.toml" >/dev/null 2>&1; then
    if ! command -v docker >/dev/null 2>&1; then
        echo "cargo cannot load this workspace here and docker is not available" >&2
        echo "run the proof from the superproject checkout instead" >&2
        exit 2
    fi
    super=$(cd "$ROOT/.." && pwd)
    printf 'cargo cannot load this workspace here; running the proof in rust:1-bookworm\n'
    exec docker run --rm -u "$(id -u):$(id -g)" \
        -v "$super:$super" -w "$ROOT" \
        -v "${CARGO_HOME:-$HOME/.cargo}:/cargo" -e CARGO_HOME=/cargo \
        --network host \
        -e "DATABASE_URL=$DATABASE_URL" \
        -e "DATABASE_URL_ALLOW=${DATABASE_URL_ALLOW:-0}" \
        -e PROOF_IN_CONTAINER=1 -e "KEEP=${KEEP:-0}" \
        -e "PORT_A=$PORT_A" -e "PORT_B=$PORT_B" -e "REPAIR_SECS=$REPAIR_SECS" \
        rust:1-bookworm ./deploy/proof/media-cluster.sh
fi
base=${DATABASE_URL%%\?*}
query=""
[[ $DATABASE_URL == *\?* ]] && query="?${DATABASE_URL#*\?}"
db=${base##*/}
if [[ $db == *_proof ]]; then
    PROOF_DB=$db
elif [[ ${DATABASE_URL_ALLOW:-0} == 1 ]]; then
    PROOF_DB=$db
    note "DATABASE_URL_ALLOW=1: using $PROOF_DB as given"
else
    PROOF_DB=${db}_proof
fi
PROOF_URL="${base%/*}/$PROOF_DB$query"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/media-cluster-proof.XXXXXX")
STORE_A=$WORK/storage-a
STORE_B=$WORK/storage-b
mkdir -p "$STORE_A/variants" "$STORE_B/variants"

pids=()
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    if [[ ${KEEP:-0} == 1 ]]; then
        printf '\nkept %s\n' "$WORK"
    else
        rm -rf "$WORK"
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

say "database"
note "server $PROOF_URL"
# The development container has no psql, so the workspace lends the proof its own sqlx.
cargo run -q --manifest-path "$ROOT/Cargo.toml" -p nodus-server-store --example proofdb -- \
    create "$PROOF_DB"

say "binaries"
if [[ ! -x $ROOT/target/debug/nodus-media ]]; then
    note "building nodus-media"
    cargo build -q --manifest-path "$ROOT/Cargo.toml" -p nodus-media
fi
BIN=$ROOT/target/debug/nodus-media
note "$BIN"

# The blob the whole proof moves around. It is fixed rather than random so the digest is
# stable across runs: the catalogue row and the file on disk then agree on the second run
# as well as the first, and a leftover directory cannot make the proof pass by accident.
BLOB=$WORK/blob
printf 'nodus media cluster proof payload\n' >"$BLOB"
DIGEST=$(sha256sum "$BLOB" | cut -d' ' -f1)
SIZE=$(wc -c <"$BLOB")
note "digest $DIGEST ($SIZE bytes)"

# A variant is a second file with its own digest and its own row, so the range section needs
# one of each. The bytes deliberately do not start with the original's
# (`nodu`) and are a different length: an answer taken from the original instead of the
# variant is still a 206 and still carries a `Content-Range`, so only its bytes and its total
# give it away.
VARIANT_BLOB=$WORK/variant
printf 'preview bytes for the media cluster proof\n' >"$VARIANT_BLOB"
VARIANT_DIGEST=$(sha256sum "$VARIANT_BLOB" | cut -d' ' -f1)
VARIANT_SIZE=$(wc -c <"$VARIANT_BLOB")
note "variant digest $VARIANT_DIGEST ($VARIANT_SIZE bytes)"

# ---------------------------------------------------------------- two nodes, one host

# Each node is a file of environment, so what it was told is on disk if a run goes wrong.
# Two nodes on one host still need different directories: the same storage would let a
# read-repair pass by reading the other node's copy through the filesystem.
write_env() {
    local file=$1 port=$2 name=$3 store=$4
    cat >"$file" <<EOF
NODUS_BIND=127.0.0.1:$port
NODUS_DATABASE_URL=$PROOF_URL
NODUS_MEDIA_NODE=$name
NODUS_MEDIA_ENDPOINT=http://127.0.0.1:$port
NODUS_MEDIA_CLUSTER_TOKEN=$TOKEN
NODUS_MEDIA_REPAIR_SECS=$REPAIR_SECS
NODUS_MEDIA_DIR=$store
NODUS_MEDIA_VARIANTS_DIR=$store/variants
RUST_LOG=info
EOF
}

start_node() {
    local env_file=$1 log=$2
    # `set -a` exports the file's assignments for this one command, so the nodes share the
    # shell's environment but not each other's settings. `stdbuf -oL` keeps the log readable
    # while the node is still running: a block-buffered log is empty until the buffer fills,
    # which would hide the repair lines this proof greps for at the end.
    (
        set -a
        # shellcheck disable=SC1090
        . "$env_file"
        set +a
        exec stdbuf -oL "$BIN" >"$log" 2>&1
    ) &
    pids+=("$!")
}

say "start"
write_env "$WORK/node-a.env" "$PORT_A" "$NODE_A" "$STORE_A"
write_env "$WORK/node-b.env" "$PORT_B" "$NODE_B" "$STORE_B"
start_node "$WORK/node-a.env" "$WORK/node-a.log"
start_node "$WORK/node-b.env" "$WORK/node-b.log"
note "a on 127.0.0.1:$PORT_A (pid ${pids[0]}), b on 127.0.0.1:$PORT_B (pid ${pids[1]})"

wait_until "node a is listening" 60 is_status 200 "http://127.0.0.1:$PORT_A/media/default-avatar.png"
wait_until "node b is listening" 60 is_status 200 "http://127.0.0.1:$PORT_B/media/default-avatar.png"

# Both nodes must be members before anything is placed: a single member is a single-node
# instance, and a single-node instance takes none of the cluster paths.
both_members() {
    local body
    body=$(curl -s --max-time 5 -H "x-nodus-cluster: $TOKEN" \
        "http://127.0.0.1:$PORT_A/internal/placement/$DIGEST" 2>/dev/null || true)
    [[ $body == *"\"$NODE_A\""* && $body == *"\"$NODE_B\""* ]]
}
wait_until "both nodes are cluster members" 30 both_members

# ---------------------------------------------------------------- the catalogue row

# `/media/{id}` answers from the catalogue, so a read-repair needs a row: the digest is the
# file, the id is what a client asks for. The row is upserted so a second run of the proof
# finds the same thing the first one left.
# The helper takes the database from DATABASE_URL, and the proof inserted into a named
# database: name it here rather than relying on the inherited value, which is the caller's
# own database and must never be written to.
#
# The variant needs a row on a second id and a file of its own: `/media/{id}/{layer}` answers
# from `media_variant` and silently falls back to the original when the row is absent, so the
# file goes where the processor would have written it on A and the row is seeded beside the
# original's. The database outlives a run, so any variant row left on the original's id goes
# first: `/media/{id}` falls back to a variant when its own file is gone, and a leftover row
# would answer the check in section 4 with a 200 it does not deserve.
cp "$VARIANT_BLOB" "$STORE_A/variants/$VARIANT_DIGEST"
DATABASE_URL="$PROOF_URL" cargo run -q --manifest-path "$ROOT/Cargo.toml" \
    -p nodus-server-store --example proofdb -- sql \
    "INSERT INTO account (id, username) VALUES ('proof-account', 'proof')
       ON CONFLICT DO NOTHING;
     INSERT INTO media_attachment (id, account_id, digest, content_type, size, processing_state)
       VALUES ('$MEDIA_ID', 'proof-account', '$DIGEST', 'image/png', $SIZE, 'ready')
       ON CONFLICT (id) DO UPDATE
         SET digest = EXCLUDED.digest, size = EXCLUDED.size, original_pruned = false;
     INSERT INTO media_attachment (id, account_id, digest, content_type, size, processing_state)
       VALUES ('$VARIANT_ID', 'proof-account', '$DIGEST', 'image/png', $SIZE, 'ready')
       ON CONFLICT (id) DO UPDATE
         SET digest = EXCLUDED.digest, size = EXCLUDED.size, original_pruned = false;
     DELETE FROM media_variant WHERE media_id IN ('$MEDIA_ID', '$VARIANT_ID');
     INSERT INTO media_variant (media_id, layer, max_edge, object_key, content_type, digest, size)
       VALUES ('$VARIANT_ID', 'preview', 512, 'variants/$VARIANT_DIGEST', 'image/png',
               '$VARIANT_DIGEST', $VARIANT_SIZE);" >/dev/null

# ---------------------------------------------------------------- 1. replicate on write

say "replicate on write"
expect "put to a is created" 201 \
    "$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X PUT \
        -H "x-nodus-cluster: $TOKEN" --data-binary "@$BLOB" "$(internal "$PORT_A")")"

wait_until "a's replica reaches b" 20 has_digest "$PORT_B"

curl -s --max-time 10 -H "x-nodus-cluster: $TOKEN" "$(internal "$PORT_B")" -o "$WORK/b-copy" || true
if cmp -s "$BLOB" "$WORK/b-copy"; then
    pass "b holds the same bytes"
else
    fail "b holds the same bytes"
fi

# ---------------------------------------------------------------- 2. peer fetch on a miss

say "read repair"
# A's file goes away and A's own read puts it back: the miss is answered by the peer, and
# the answer is written down so the next read is local.
rm -f "$STORE_A/$DIGEST"
code=$(curl -s -o "$WORK/a-copy" -w '%{http_code}' --max-time 20 \
    "http://127.0.0.1:$PORT_A/media/$MEDIA_ID")
expect "a answers after losing its file" 200 "$code"
if cmp -s "$BLOB" "$WORK/a-copy"; then
    pass "a serves the bytes it fetched from b"
else
    fail "a serves the bytes it fetched from b"
fi
wait_until "a wrote the fetched bytes back to disk" 10 test -f "$STORE_A/$DIGEST"

# ---------------------------------------------------------------- 3. the public range

say "range on the public route"
# A browser seeking in a video sends `Range`, and the answer comes from the media node, not
# the API. A public route that ignored it would answer 200 with the whole body: the client
# would still play the file, so the failure is silent. The check therefore asserts all
# three parts of the answer — the status, the header that places the slice, and the bytes.
head -c 4 "$BLOB" >"$WORK/first-four"
code=$(curl -s -D "$WORK/range-headers" -o "$WORK/range-body" -w '%{http_code}' \
    --max-time 10 -r 0-3 "http://127.0.0.1:$PORT_A/media/$MEDIA_ID")
expect "a ranged public read is a 206" 206 "$code"
if grep -qai '^content-range: bytes 0-3/' "$WORK/range-headers"; then
    pass "the ranged answer says which bytes it carries"
else
    fail "the ranged answer says which bytes it carries"
fi
if cmp -s "$WORK/range-body" "$WORK/first-four"; then
    pass "the ranged answer is exactly the first four bytes of the original"
else
    fail "the ranged answer is exactly the first four bytes of the original"
fi

# The variant route slices with the same helpers but reads a different file, so it carries
# the same three assertions against its own bytes. The total in `Content-Range` is part of
# the check because it is the variant's length, not the original's: an answer that fell back
# to the original would otherwise look like a ranged read that worked.
head -c 4 "$VARIANT_BLOB" >"$WORK/variant-first-four"
code=$(curl -s -D "$WORK/variant-range-headers" -o "$WORK/variant-range-body" \
    -w '%{http_code}' --max-time 10 -r 0-3 \
    "http://127.0.0.1:$PORT_A/media/$VARIANT_ID/preview")
expect "a ranged variant read is a 206" 206 "$code"
if grep -qai "^content-range: bytes 0-3/$VARIANT_SIZE" "$WORK/variant-range-headers"; then
    pass "the ranged variant answer says which bytes of the variant it carries"
else
    fail "the ranged variant answer says which bytes of the variant it carries"
fi
if cmp -s "$WORK/variant-range-body" "$WORK/variant-first-four"; then
    pass "the ranged variant answer is exactly the first four bytes of the variant"
else
    fail "the ranged variant answer is exactly the first four bytes of the variant"
fi

# ---------------------------------------------------------------- 4. repair pushes

say "repair push"
rm -f "$STORE_A/$DIGEST" "$STORE_B/$DIGEST"
expect "a is empty once both copies are gone" 404 \
    "$(status_of "http://127.0.0.1:$PORT_A/media/$MEDIA_ID")"

expect "re-put to a is created" 201 \
    "$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X PUT \
        -H "x-nodus-cluster: $TOKEN" --data-binary "@$BLOB" "$(internal "$PORT_A")")"
wait_until "b receives the re-put" 20 has_digest "$PORT_B"

# Nothing writes to B from here on: only the repair walk can put the file back, which is
# exactly the case it exists for — a replica lost to a disk or a crashed upload.
rm -f "$STORE_B/$DIGEST"
wait_until "a repair pass puts b's lost replica back" 30 has_digest "$PORT_B"

# ---------------------------------------------------------------- 5. a dead peer

say "dead peer"
kill "${pids[0]}" 2>/dev/null || true
wait "${pids[0]}" 2>/dev/null || true
pids=("${pids[1]}")

expect "b still serves after a dies" 200 \
    "$(status_of "http://127.0.0.1:$PORT_B/media/$MEDIA_ID")"

# A miss has to stay a miss. A is still a member for another ten minutes (that is the
# membership window), so B will try to fetch from it and find nothing listening: the answer
# must come back as a 404 inside the peer budget, not as a request that waits forever.
rm -f "$STORE_B/$DIGEST"
started=$(now_ms)
code=$(status_of "http://127.0.0.1:$PORT_B/media/$MEDIA_ID")
took=$(($(now_ms) - started))
expect "b answers 404 for a miss a cannot serve" 404 "$code"
if ((took < 8000)); then
    pass "b's miss came back in ${took}ms (peer budget 6s)"
else
    fail "b's miss came back in ${took}ms (peer budget 6s)"
fi

# ---------------------------------------------------------------- verdict

say "repair log"
note "a: $(grep -c 'media repair pass' "$WORK/node-a.log" || true) pass(es), last: $(grep 'media repair pass' "$WORK/node-a.log" | tail -1 || true)"
note "b: $(grep -c 'media repair pass' "$WORK/node-b.log" || true) pass(es), last: $(grep 'media repair pass' "$WORK/node-b.log" | tail -1 || true)"

if ((bad > 0)); then
    printf '\n%d ok, %d failed\n' "$ok" "$bad"
    printf '\n-- node a log (tail) --\n'
    tail -n 20 "$WORK/node-a.log" || true
    printf '\n-- node b log (tail) --\n'
    tail -n 20 "$WORK/node-b.log" || true
    exit 1
fi

printf '\nall %d assertions passed\n' "$ok"

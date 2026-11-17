#!/usr/bin/env bash
# Build the server binary for Debian 12 (glibc 2.36) and push it into the LXC container.
#
#   ./nodus-backend/deploy/lxc/deploy.sh
#   HOST=root@hyper.luxuride.eu VMID=118 ./nodus-backend/deploy/lxc/deploy.sh
#
# The build runs in rust:1-bookworm for the same reason the recommender does: the
# development container is trixie (glibc 2.38), and a binary built there dies on the
# container with "version `GLIBC_2.38' not found (required by /usr/local/bin/nodus-backend)".
set -euo pipefail

# Every ssh line interpolates the target on purpose: the local shell decides where the
# command runs, and SC2029 wants the opposite. Declared once for the whole file.
# shellcheck disable=SC2029

HOST="${HOST:-root@hyper.luxuride.eu}"
VMID="${VMID:-118}"
UNIT="${UNIT:-nodus-backend}"
PORT="${PORT:-3001}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CACHE_VOLUME="${CACHE_VOLUME:-nodus-cargo}"
BINARY="${ROOT}/nodus-backend/target-bookworm/release/nodus-server"

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  echo "==> building for bookworm in ${ROOT}/nodus-backend"
  docker run --rm \
    -v "${ROOT}:/src" \
    -v "${CACHE_VOLUME}:/cargo" \
    -w /src/nodus-backend \
    -e CARGO_HOME=/cargo \
    rust:1-bookworm \
    cargo build --release --locked --bin nodus-server --target-dir /src/nodus-backend/target-bookworm
fi

[[ -x "${BINARY}" ]] || { echo "missing ${BINARY}" >&2; exit 1; }

echo "==> staging the binary"
scp -q "${BINARY}" "${HOST}:/tmp/nodus-backend-new"
ssh "${HOST}" "pct exec ${VMID} -- systemctl stop ${UNIT}"
ssh "${HOST}" "pct exec ${VMID} -- cp -a /usr/local/bin/nodus-backend /usr/local/bin/nodus-backend.bak-previous || true"
ssh "${HOST}" "pct push ${VMID} /tmp/nodus-backend-new /usr/local/bin/nodus-backend --perms 0755"

echo "==> starting ${UNIT} (migrations run on boot)"
ssh "${HOST}" "pct exec ${VMID} -- systemctl start ${UNIT}"

echo "==> waiting for /readyz (migrations run before the listener opens)"
for _ in $(seq 1 30); do
  if ssh "${HOST}" "pct exec ${VMID} -- curl -fsS --max-time 3 http://127.0.0.1:${PORT}/readyz" >/dev/null 2>&1; then
    echo "==> ready"
    break
  fi
  sleep 2
done

ssh "${HOST}" "pct exec ${VMID} -- systemctl --no-pager --lines=0 status ${UNIT}" || true
ssh "${HOST}" "pct exec ${VMID} -- curl -fsS --max-time 5 http://127.0.0.1:${PORT}/healthz" || true
echo
echo "==> done"

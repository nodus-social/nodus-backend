#!/usr/bin/env bash
# Build every service for Debian 12 (glibc 2.36) and push it into the LXC container.
#
#   ./nodus-backend/deploy/lxc/deploy.sh
#   HOST=root@hyper.luxuride.eu VMID=118 ./nodus-backend/deploy/lxc/deploy.sh
#
# The build runs in rust:1-bookworm for the same reason the recommender does: the
# development container is trixie (glibc 2.38), and a binary built there dies on the
# container with "version `GLIBC_2.38' not found".
#
# Five binaries, five units, one database. The units are this repository's, not the
# container's: a change to what a service needs is a change here.
set -euo pipefail

# Every ssh line interpolates the target on purpose: the local shell decides where the
# command runs, and SC2029 wants the opposite. Declared once for the whole file.
# shellcheck disable=SC2029

HOST="${HOST:-root@hyper.luxuride.eu}"
VMID="${VMID:-118}"
PORT="${PORT:-3001}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CACHE_VOLUME="${CACHE_VOLUME:-nodus-cargo}"
SERVICES=(api media feed scan prune calc)
BUILD_DIR="${ROOT}/nodus-backend/target-bookworm/release"

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  echo "==> building every service for bookworm in ${ROOT}/nodus-backend"
  docker run --rm \
    -v "${ROOT}:/src" \
    -v "${CACHE_VOLUME}:/cargo" \
    -w /src/nodus-backend \
    -e CARGO_HOME=/cargo \
    rust:1-bookworm \
    cargo build --release --locked --target-dir /src/nodus-backend/target-bookworm \
    --bin nodus-api --bin nodus-media --bin nodus-feed --bin nodus-scan --bin nodus-prune --bin nodus-calc
fi

for service in "${SERVICES[@]}"; do
  [[ -x "${BUILD_DIR}/nodus-${service}" ]] || { echo "missing ${BUILD_DIR}/nodus-${service}" >&2; exit 1; }
done

echo "==> staging binaries and units"
for service in "${SERVICES[@]}"; do
  scp -q "${BUILD_DIR}/nodus-${service}" "${HOST}:/tmp/nodus-${service}-new"
  scp -q "${ROOT}/nodus-backend/deploy/systemd/nodus-${service}.service" "${HOST}:/tmp/nodus-${service}.service"
done

# The monolith is retired here rather than later: two processes must not claim the same
# tables, and its socket directory is now the workers' neighbourhood.
echo "==> stopping the old monolith"
ssh "${HOST}" "pct exec ${VMID} -- systemctl disable --now nodus-backend || true"

# Every unit is stopped before anything is pushed: a running binary cannot be replaced
# ("Text file busy"), and a half-replaced set is worse than the build it replaces.
for service in "${SERVICES[@]}"; do
  ssh "${HOST}" "pct exec ${VMID} -- systemctl stop nodus-${service} || true"
done

for service in "${SERVICES[@]}"; do
  # Keep the binary that is running now: a rollback is a `cp` in the container.
  ssh "${HOST}" "pct exec ${VMID} -- sh -c 'cp -a /usr/local/bin/nodus-${service} /usr/local/bin/nodus-${service}.bak-previous 2>/dev/null || true'"
  ssh "${HOST}" "pct push ${VMID} /tmp/nodus-${service}-new /usr/local/bin/nodus-${service} --perms 0755"
  ssh "${HOST}" "pct push ${VMID} /tmp/nodus-${service}.service /etc/systemd/system/nodus-${service}.service --perms 0644"
done

ssh "${HOST}" "pct exec ${VMID} -- systemctl daemon-reload"
for service in "${SERVICES[@]}"; do
  ssh "${HOST}" "pct exec ${VMID} -- systemctl enable nodus-${service}"
done

# The API first: it migrates, and a worker that starts before the schema exists fails its
# first pass for no reason.
echo "==> starting nodus-api (migrations run on boot)"
ssh "${HOST}" "pct exec ${VMID} -- systemctl restart nodus-api"
for _ in $(seq 1 30); do
  if ssh "${HOST}" "pct exec ${VMID} -- curl -fsS --max-time 3 http://127.0.0.1:${PORT}/readyz" >/dev/null 2>&1; then
    echo "==> api ready"
    break
  fi
  sleep 2
done

for service in media feed scan prune calc; do
  echo "==> starting nodus-${service}"
  ssh "${HOST}" "pct exec ${VMID} -- systemctl restart nodus-${service}"
done

sleep 2
echo "==> units"
for service in "${SERVICES[@]}"; do
  ssh "${HOST}" "pct exec ${VMID} -- systemctl is-active nodus-${service}" || true
done
ssh "${HOST}" "pct exec ${VMID} -- curl -fsS --max-time 5 http://127.0.0.1:${PORT}/healthz" || true
echo
echo "==> done"

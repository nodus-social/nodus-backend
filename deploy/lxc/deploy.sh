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
#
# Safety: a deploy must never leave the instance with every unit stopped. Each binary is
# replaced with an atomic rename (the running process keeps its old inode) and its unit
# is restarted on its own, so at most one service is briefly unavailable. A trap on
# EXIT/INT/TERM starts and verifies every unit on any exit path. SIGKILL cannot run a
# trap, which is why the per-unit restart order matters: there is no point at which the
# script has stopped all six waiting to start them again.
set -euo pipefail

# Every ssh line interpolates the target on purpose: the local shell decides where the
# command runs, and SC2029 wants the opposite. Declared once for the whole file.
# shellcheck disable=SC2029

HOST="${HOST:-root@hyper.luxuride.eu}"
VMID="${VMID:-118}"
WEB_VMID="${WEB_VMID:-100}"
PORT="${PORT:-3001}"
HEALTH_URL="${HEALTH_URL:-https://nodus.luxuride.eu/healthz}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CACHE_VOLUME="${CACHE_VOLUME:-nodus-cargo}"
SERVICES=(api media feed scan prune calc)
BUILD_DIR="${ROOT}/nodus-backend/target-bookworm/release"

# Units this run has touched (restart is the only stop we do now). Kept for the trap so
# it can name the affected units even if that list ever grows a stop step.
TOUCHED=()

remote() {
  ssh "${HOST}" "pct exec ${VMID} -- $*"
}

# On any exit path, no unit may be left stopped. Start what is not active, then verify
# with is-active and name the unit that is still not up. The incoming exit status wins:
# a failed deploy stays failed even if the units were rescued.
require_up() {
  local rc=$?
  local service state
  trap - EXIT INT TERM
  set +e
  for service in "${SERVICES[@]}"; do
    state=$(remote "systemctl is-active nodus-${service}" 2>/dev/null | tr -d '[:space:]')
    if [[ "${state}" != "active" ]]; then
      echo "!! nodus-${service} is ${state:-unknown}: starting it (deploy interrupted)" >&2
      remote "systemctl start nodus-${service}" >/dev/null 2>&1
    fi
    state=$(remote "systemctl is-active nodus-${service}" 2>/dev/null | tr -d '[:space:]')
    if [[ "${state}" != "active" ]]; then
      echo "!! FAILED to leave nodus-${service} active (state: ${state:-unknown})" >&2
      rc=1
    fi
  done
  if [[ ${#TOUCHED[@]} -gt 0 ]]; then
    echo "==> trap returned ${#TOUCHED[@]} unit(s) to service: ${TOUCHED[*]}" >&2
  fi
  exit "${rc}"
}
trap require_up EXIT INT TERM

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

# Units are installed before any binary moves; the binaries wait as `.new` files.
for service in "${SERVICES[@]}"; do
  ssh "${HOST}" "pct push ${VMID} /tmp/nodus-${service}.service /etc/systemd/system/nodus-${service}.service --perms 0644"
  ssh "${HOST}" "pct push ${VMID} /tmp/nodus-${service}-new /usr/local/bin/nodus-${service}.new --perms 0755"
done
ssh "${HOST}" "pct exec ${VMID} -- systemctl daemon-reload"
for service in "${SERVICES[@]}"; do
  ssh "${HOST}" "pct exec ${VMID} -- systemctl enable nodus-${service}"
done

# Replace + restart, one service at a time. `mv` is a rename, so a running binary keeps its
# old inode and is never "Text file busy"; systemd stops the old process only for the unit
# being restarted. The API goes first: it migrates, and a worker that starts before the
# schema exists fails its first pass for no reason.
for service in "${SERVICES[@]}"; do
  TOUCHED+=("nodus-${service}")
  echo "==> replacing and restarting nodus-${service}"
  # Keep the binary that is running now: a rollback is a `cp` in the container.
  remote "sh -c 'cp -a /usr/local/bin/nodus-${service} /usr/local/bin/nodus-${service}.bak-previous 2>/dev/null || true'"
  remote "mv -f /usr/local/bin/nodus-${service}.new /usr/local/bin/nodus-${service}"
  remote "systemctl restart nodus-${service}"

  if [[ "${service}" == "api" ]]; then
    echo "==> waiting for nodus-api readiness (migrations)"
    ready=0
    for _ in $(seq 1 30); do
      if remote "curl -fsS --max-time 3 http://127.0.0.1:${PORT}/readyz" >/dev/null 2>&1; then
        ready=1
        break
      fi
      sleep 2
    done
    [[ "${ready}" == "1" ]] || { echo "!! nodus-api did not become ready" >&2; exit 1; }
    echo "==> api ready"
  fi
done

echo "==> verifying deployment"
failures=()
for service in "${SERVICES[@]}"; do
  state=$(remote "systemctl is-active nodus-${service}" 2>/dev/null | tr -d '[:space:]')
  [[ "${state}" == "active" ]] || failures+=("unit nodus-${service} is ${state:-unknown} (expected active)")
done

if ! body=$(remote "curl -fsS --max-time 5 http://127.0.0.1:${PORT}/healthz" 2>/dev/null); then
  failures+=("GET http://127.0.0.1:${PORT}/healthz failed from CT ${VMID}")
elif [[ "${body}" != "ok" ]]; then
  failures+=("GET http://127.0.0.1:${PORT}/healthz returned '${body}' (expected 'ok')")
fi

if ! body=$(ssh "${HOST}" "pct exec ${WEB_VMID} -- curl -fsS --max-time 10 '${HEALTH_URL}'" 2>/dev/null); then
  failures+=("GET ${HEALTH_URL} failed from CT ${WEB_VMID}")
elif [[ "${body}" != "ok" ]]; then
  failures+=("GET ${HEALTH_URL} returned '${body}' (expected 'ok')")
fi

if [[ ${#failures[@]} -gt 0 ]]; then
  echo "!! deployment verification failed:" >&2
  for failure in "${failures[@]}"; do echo "!!   - ${failure}" >&2; done
  exit 1
fi

trap - EXIT INT TERM
echo "==> six units active, /healthz ok in CT ${VMID}, ${HEALTH_URL} ok from CT ${WEB_VMID}"
echo "==> done"

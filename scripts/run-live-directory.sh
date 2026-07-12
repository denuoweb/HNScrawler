#!/usr/bin/env bash
set -euo pipefail

LIVE_ROOT="${LIVE_ROOT:-/mnt/hns-topology/live-directory}"
LIVE_REPO_DIR="${LIVE_REPO_DIR:-$LIVE_ROOT/HNScrawler}"
TOPOLOGY_DB="${TOPOLOGY_DB:-/mnt/hns-topology/topology.sqlite}"
LIVE_DB="${LIVE_DB:-$LIVE_ROOT/data/live.sqlite}"
LIVE_PUBLIC_DIR="${LIVE_PUBLIC_DIR:-$LIVE_ROOT/public}"
LIVE_LIMIT="${LIVE_LIMIT:-100}"
LIVE_CONCURRENCY="${LIVE_CONCURRENCY:-4}"
LIVE_MIN_DELAY_MS="${LIVE_MIN_DELAY_MS:-250}"
LIVE_TIMEOUT="${LIVE_TIMEOUT:-5}"
LIVE_MAX_NAMESERVERS="${LIVE_MAX_NAMESERVERS:-3}"
LIVE_MAX_ADDRESSES="${LIVE_MAX_ADDRESSES:-4}"
LIVE_FALLBACK_RESOLVER="${LIVE_FALLBACK_RESOLVER:-}"
LIVE_SWEEP_LIMIT="${LIVE_SWEEP_LIMIT:-500}"
LIVE_SWEEP_PAGE_SIZE="${LIVE_SWEEP_PAGE_SIZE:-1000}"
LIVE_SWEEP_CONCURRENCY="${LIVE_SWEEP_CONCURRENCY:-50}"
LIVE_SWEEP_MIN_DELAY_MS="${LIVE_SWEEP_MIN_DELAY_MS:-100}"
LIVE_SWEEP_AUTHORITY_DELAY_MS="${LIVE_SWEEP_AUTHORITY_DELAY_MS:-500}"
LIVE_SWEEP_TIMEOUT="${LIVE_SWEEP_TIMEOUT:-2}"
LIVE_SWEEP_MAX_NAMESERVERS="${LIVE_SWEEP_MAX_NAMESERVERS:-2}"
LIVE_SWEEP_MAX_ADDRESSES="${LIVE_SWEEP_MAX_ADDRESSES:-2}"

mountpoint -q /mnt/hns-topology || {
  echo "/mnt/hns-topology is not mounted; refusing to use the web VM boot disk" >&2
  exit 2
}
test -r "$TOPOLOGY_DB" || {
  echo "topology snapshot is not readable: $TOPOLOGY_DB" >&2
  exit 2
}
test -x "$LIVE_REPO_DIR/.venv/bin/hns-live-directory" || {
  echo "live-directory virtualenv is not installed at $LIVE_REPO_DIR/.venv" >&2
  exit 2
}

mkdir -p "$LIVE_ROOT/data" "$LIVE_ROOT/run"
exec 9>"$LIVE_ROOT/run/live-directory.lock"
if ! flock -n 9; then
  echo "another live-directory cycle is already running" >&2
  exit 0
fi

args=(cycle
  --topology-db "$TOPOLOGY_DB"
  --db "$LIVE_DB"
  --out "$LIVE_PUBLIC_DIR"
  --limit "$LIVE_LIMIT"
  --concurrency "$LIVE_CONCURRENCY"
  --min-delay-ms "$LIVE_MIN_DELAY_MS"
  --timeout "$LIVE_TIMEOUT"
  --max-nameservers "$LIVE_MAX_NAMESERVERS"
  --max-addresses "$LIVE_MAX_ADDRESSES"
  --sweep-limit "$LIVE_SWEEP_LIMIT"
  --sweep-page-size "$LIVE_SWEEP_PAGE_SIZE"
  --sweep-concurrency "$LIVE_SWEEP_CONCURRENCY"
  --sweep-min-delay-ms "$LIVE_SWEEP_MIN_DELAY_MS"
  --sweep-authority-delay-ms "$LIVE_SWEEP_AUTHORITY_DELAY_MS"
  --sweep-timeout "$LIVE_SWEEP_TIMEOUT"
  --sweep-max-nameservers "$LIVE_SWEEP_MAX_NAMESERVERS"
  --sweep-max-addresses "$LIVE_SWEEP_MAX_ADDRESSES")
if [[ -n "$LIVE_FALLBACK_RESOLVER" ]]; then
  args+=(--fallback-resolver "$LIVE_FALLBACK_RESOLVER")
fi

cd "$LIVE_REPO_DIR"
exec .venv/bin/hns-live-directory "${args[@]}"

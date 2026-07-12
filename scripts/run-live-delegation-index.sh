#!/usr/bin/env bash
set -euo pipefail

LIVE_ROOT="${LIVE_ROOT:-/mnt/hns-topology/live-directory}"
LIVE_REPO_DIR="${LIVE_REPO_DIR:-$LIVE_ROOT/HNScrawler}"
LIVE_DB="${LIVE_DB:-$LIVE_ROOT/data/live.sqlite}"
TOPOLOGY_SITE_DIR="${TOPOLOGY_SITE_DIR:-/mnt/hns-topology/site}"
LIVE_DELEGATION_MIN_MEMBERS="${LIVE_DELEGATION_MIN_MEMBERS:-2}"
LIVE_DELEGATION_MAX_MEMBERS="${LIVE_DELEGATION_MAX_MEMBERS:-250}"

mountpoint -q /mnt/hns-topology || {
  echo "/mnt/hns-topology is not mounted; refusing to use the web VM boot disk" >&2
  exit 2
}
test -r "$TOPOLOGY_SITE_DIR/data/nameservers/index.json" || {
  echo "nameserver export is not readable: $TOPOLOGY_SITE_DIR" >&2
  exit 2
}

mkdir -p "$LIVE_ROOT/run"
exec 9>"$LIVE_ROOT/run/live-directory.lock"
if ! flock -n 9; then
  echo "a live-directory cycle or delegation-index refresh is already running" >&2
  exit 0
fi

cd "$LIVE_REPO_DIR"
exec .venv/bin/hns-live-directory index-delegations \
  --db "$LIVE_DB" \
  --topology-site "$TOPOLOGY_SITE_DIR" \
  --min-members "$LIVE_DELEGATION_MIN_MEMBERS" \
  --max-members "$LIVE_DELEGATION_MAX_MEMBERS"

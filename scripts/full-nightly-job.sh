#!/usr/bin/env bash
set -euo pipefail

TOPOLOGY_DB="${TOPOLOGY_DB:-data/topology.sqlite}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
CHECK_HSD_READY="${CHECK_HSD_READY:-1}"
RUN_LIVE_CHECKS="${RUN_LIVE_CHECKS:-1}"
RUN_ARCHIVE="${RUN_ARCHIVE:-0}"
RUN_PUBLISH="${RUN_PUBLISH:-1}"
START_HSD_FOR_UPDATES="${START_HSD_FOR_UPDATES:-1}"
STOP_HSD_AFTER_UPDATES="${STOP_HSD_AFTER_UPDATES:-1}"

. .venv/bin/activate
if [ -d "$INDEXER_MOUNT" ] && ! mountpoint -q "$INDEXER_MOUNT"; then
  echo "$INDEXER_MOUNT exists but is not mounted; refusing to run nightly job on boot disk" >&2
  exit 2
fi
if [ -f "$INDEXER_MOUNT/secrets/hsd.env" ]; then
  set -a
  . "$INDEXER_MOUNT/secrets/hsd.env"
  set +a
fi

hsd_started_for_update=0
hsd_is_active() {
  command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet hsd
}

start_hsd_for_update() {
  if [ "$START_HSD_FOR_UPDATES" = "1" ]; then
    echo "[full-nightly] $(date -u +%Y-%m-%dT%H:%M:%SZ) starting hsd for update phase" >&2
    sudo systemctl start hsd
    hsd_started_for_update=1
  fi
}

stop_hsd_after_update() {
  if [ "$STOP_HSD_AFTER_UPDATES" = "1" ] && { [ "$hsd_started_for_update" = "1" ] || hsd_is_active; }; then
    echo "[full-nightly] $(date -u +%Y-%m-%dT%H:%M:%SZ) stopping hsd before live checks/site generation" >&2
    sudo systemctl stop hsd
    hsd_started_for_update=0
  fi
}

cleanup_hsd() {
  stop_hsd_after_update || true
}
trap cleanup_hsd EXIT

start_hsd_for_update
if [ "$CHECK_HSD_READY" = "1" ]; then
  scripts/check-hsd-ready.sh
fi
hns-topology reorg-check --db "$TOPOLOGY_DB" --rollback

scripts/run-incremental.sh
stop_hsd_after_update
if [ "$RUN_LIVE_CHECKS" = "1" ]; then
  scripts/run-live-checks.sh
fi
scripts/generate-site.sh
scripts/verify-release.sh
if [ "$RUN_ARCHIVE" = "1" ]; then
  scripts/archive-release.sh
fi
if [ "$RUN_PUBLISH" = "1" ]; then
  scripts/publish-site.sh
fi

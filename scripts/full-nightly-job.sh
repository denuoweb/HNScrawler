#!/usr/bin/env bash
set -euo pipefail

TOPOLOGY_DB="${TOPOLOGY_DB:-data/topology.sqlite}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
CHECK_HSD_READY="${CHECK_HSD_READY:-1}"
RUN_LIVE_CHECKS="${RUN_LIVE_CHECKS:-1}"
RUN_ARCHIVE="${RUN_ARCHIVE:-0}"
RUN_PUBLISH="${RUN_PUBLISH:-1}"

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
if [ "$CHECK_HSD_READY" = "1" ]; then
  scripts/check-hsd-ready.sh
fi
hns-topology reorg-check --db "$TOPOLOGY_DB" --rollback

scripts/run-incremental.sh
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

#!/usr/bin/env bash
set -euo pipefail

TOPOLOGY_DB="${TOPOLOGY_DB:-data/topology.sqlite}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
. .venv/bin/activate
if [ -f "$INDEXER_MOUNT/secrets/hsd.env" ]; then
  set -a
  . "$INDEXER_MOUNT/secrets/hsd.env"
  set +a
fi
hns-topology reorg-check --db "$TOPOLOGY_DB" --rollback

scripts/run-incremental.sh
scripts/run-live-checks.sh
scripts/generate-site.sh
scripts/publish-site.sh

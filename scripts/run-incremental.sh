#!/usr/bin/env bash
set -euo pipefail

TOPOLOGY_DB="${TOPOLOGY_DB:-data/topology.sqlite}"
PROVIDER_RULES="${PROVIDER_RULES:-configs/provider_rules.json}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
CHECK_HSD_READY="${CHECK_HSD_READY:-1}"
CHANGED_NAMES_FILE="${CHANGED_NAMES_FILE:-}"
SCAN_BLOCK_HEIGHT="${SCAN_BLOCK_HEIGHT:-}"

. .venv/bin/activate
if [ -d "$INDEXER_MOUNT" ] && ! mountpoint -q "$INDEXER_MOUNT"; then
  echo "$INDEXER_MOUNT exists but is not mounted; refusing to write incremental data to boot disk" >&2
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

if [[ -n "$CHANGED_NAMES_FILE" ]]; then
  hns-topology incremental --db "$TOPOLOGY_DB" --rules "$PROVIDER_RULES" --changed-names-file "$CHANGED_NAMES_FILE"
elif [[ -n "$SCAN_BLOCK_HEIGHT" ]]; then
  hns-topology incremental --db "$TOPOLOGY_DB" --rules "$PROVIDER_RULES" --scan-block-height "$SCAN_BLOCK_HEIGHT"
else
  echo "Set CHANGED_NAMES_FILE or SCAN_BLOCK_HEIGHT for incremental mode." >&2
  exit 2
fi

#!/usr/bin/env bash
set -euo pipefail

TOPOLOGY_DB="${TOPOLOGY_DB:-data/topology.sqlite}"
PROVIDER_RULES="${PROVIDER_RULES:-configs/provider_rules.json}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
CHECK_HSD_READY="${CHECK_HSD_READY:-1}"
CHANGED_NAMES_FILE="${CHANGED_NAMES_FILE:-}"
SCAN_BLOCK_HEIGHT="${SCAN_BLOCK_HEIGHT:-}"
ALLOW_EMPTY_BLOCK_SCAN="${ALLOW_EMPTY_BLOCK_SCAN:-0}"
ALLOW_UNRESOLVED_NAME_HASHES="${ALLOW_UNRESOLVED_NAME_HASHES:-0}"
INCREMENTAL_MAX_BLOCKS="${INCREMENTAL_MAX_BLOCKS:-300}"
INCREMENTAL_TO_HEIGHT="${INCREMENTAL_TO_HEIGHT:-}"

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
  args=(incremental --db "$TOPOLOGY_DB" --rules "$PROVIDER_RULES" --scan-block-height "$SCAN_BLOCK_HEIGHT")
  if [ "$ALLOW_EMPTY_BLOCK_SCAN" = "1" ]; then
    args+=(--allow-empty-block-scan)
  fi
  if [ "$ALLOW_UNRESOLVED_NAME_HASHES" = "1" ]; then
    args+=(--allow-unresolved-name-hashes)
  fi
  hns-topology "${args[@]}"
else
  args=(incremental --db "$TOPOLOGY_DB" --rules "$PROVIDER_RULES" --catch-up-max-blocks "$INCREMENTAL_MAX_BLOCKS")
  if [ -n "$INCREMENTAL_TO_HEIGHT" ]; then
    args+=(--catch-up-to-height "$INCREMENTAL_TO_HEIGHT")
  fi
  if [ "$ALLOW_UNRESOLVED_NAME_HASHES" = "1" ]; then
    args+=(--allow-unresolved-name-hashes)
  fi
  hns-topology "${args[@]}"
fi

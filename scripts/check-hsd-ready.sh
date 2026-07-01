#!/usr/bin/env bash
set -euo pipefail

INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
HSD_MAX_BLOCK_LAG="${HSD_MAX_BLOCK_LAG:-2}"
HSD_MIN_BLOCK_HEIGHT="${HSD_MIN_BLOCK_HEIGHT:-300000}"
HSD_ALLOW_REMOTE_RPC="${HSD_ALLOW_REMOTE_RPC:-0}"

. .venv/bin/activate

if [ -f "$INDEXER_MOUNT/secrets/hsd.env" ]; then
  set -a
  . "$INDEXER_MOUNT/secrets/hsd.env"
  set +a
fi

args=(hsd-status --max-block-lag "$HSD_MAX_BLOCK_LAG" --min-block-height "$HSD_MIN_BLOCK_HEIGHT")
if [ "$HSD_ALLOW_REMOTE_RPC" = "1" ]; then
  args+=(--allow-remote-rpc)
fi

hns-topology "${args[@]}"

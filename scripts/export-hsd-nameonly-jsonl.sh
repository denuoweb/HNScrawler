#!/usr/bin/env bash
set -euo pipefail

INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
JSONL_PATH="${JSONL_PATH:-$INDEXER_MOUNT/data/nameonly-experimental.jsonl}"
HSD_NETWORK="${HSD_NETWORK:-main}"
NAMEONLY_FROM_HEIGHT="${NAMEONLY_FROM_HEIGHT:-0}"
NAMEONLY_TO_HEIGHT="${NAMEONLY_TO_HEIGHT:-}"
NAMEONLY_LIMIT_BLOCKS="${NAMEONLY_LIMIT_BLOCKS:-}"
NAMEONLY_PROGRESS="${NAMEONLY_PROGRESS:-1000}"
NAMEONLY_REORG_WINDOW="${NAMEONLY_REORG_WINDOW:-300}"

if [ -f "$INDEXER_MOUNT/secrets/hsd.env" ]; then
  # shellcheck disable=SC1091
  . "$INDEXER_MOUNT/secrets/hsd.env"
fi

args=(
  --out "$JSONL_PATH"
  --network "$HSD_NETWORK"
  --from-height "$NAMEONLY_FROM_HEIGHT"
  --progress "$NAMEONLY_PROGRESS"
  --reorg-window "$NAMEONLY_REORG_WINDOW"
)

if [ -n "${HSD_RPC_URL:-}" ]; then
  args+=(--rpc-url "$HSD_RPC_URL")
fi

if [ -n "${HSD_API_KEY:-}" ]; then
  args+=(--api-key "$HSD_API_KEY")
fi

if [ -n "$NAMEONLY_TO_HEIGHT" ]; then
  args+=(--to-height "$NAMEONLY_TO_HEIGHT")
fi

if [ -n "$NAMEONLY_LIMIT_BLOCKS" ]; then
  args+=(--limit-blocks "$NAMEONLY_LIMIT_BLOCKS")
fi

node scripts/hsd-nameonly-replay-jsonl.js "${args[@]}"

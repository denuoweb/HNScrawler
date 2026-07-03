#!/usr/bin/env bash
set -euo pipefail

TOPOLOGY_DB="${TOPOLOGY_DB:-data/topology.sqlite}"
PUBLIC_DIR="${PUBLIC_DIR:-public}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
NAMES_LIMIT="${NAMES_LIMIT:-0}"

. .venv/bin/activate
if [ -d "$INDEXER_MOUNT" ] && ! mountpoint -q "$INDEXER_MOUNT"; then
  echo "$INDEXER_MOUNT exists but is not mounted; refusing to write generated site to boot disk" >&2
  exit 2
fi
hns-topology generate-site --db "$TOPOLOGY_DB" --out "$PUBLIC_DIR" --names-limit "$NAMES_LIMIT"

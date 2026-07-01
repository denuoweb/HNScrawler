#!/usr/bin/env bash
set -euo pipefail

TOPOLOGY_DB="${TOPOLOGY_DB:-data/topology.sqlite}"
PROVIDER_RULES="${PROVIDER_RULES:-configs/provider_rules.json}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
CHECK_HSD_READY="${CHECK_HSD_READY:-1}"
BOOTSTRAP_LIMIT="${BOOTSTRAP_LIMIT:-}"
ALLOW_UNPAGINATED_GETNAMES="${ALLOW_UNPAGINATED_GETNAMES:-0}"

. .venv/bin/activate
if [ -d "$INDEXER_MOUNT" ] && ! mountpoint -q "$INDEXER_MOUNT"; then
  echo "$INDEXER_MOUNT exists but is not mounted; refusing to write bootstrap data to boot disk" >&2
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

args=(bootstrap --db "$TOPOLOGY_DB" --rules "$PROVIDER_RULES")
if [ -n "$BOOTSTRAP_LIMIT" ]; then
  args+=(--limit "$BOOTSTRAP_LIMIT")
fi
if [ "$ALLOW_UNPAGINATED_GETNAMES" = "1" ]; then
  args+=(--allow-unpaginated-getnames)
fi

hns-topology "${args[@]}"

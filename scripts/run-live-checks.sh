#!/usr/bin/env bash
set -euo pipefail

TOPOLOGY_DB="${TOPOLOGY_DB:-data/topology.sqlite}"
PROVIDER_RULES="${PROVIDER_RULES:-configs/provider_rules.json}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
LIVE_LIMIT="${LIVE_LIMIT:-10}"
LIVE_CONCURRENCY="${LIVE_CONCURRENCY:-4}"
LIVE_DELAY_MS="${LIVE_DELAY_MS:-250}"
LIVE_TIMEOUT="${LIVE_TIMEOUT:-5}"

. .venv/bin/activate
if [ -d "$INDEXER_MOUNT" ] && ! mountpoint -q "$INDEXER_MOUNT"; then
  echo "$INDEXER_MOUNT exists but is not mounted; refusing to write live-check data to boot disk" >&2
  exit 2
fi

hns-topology discover-hosts --db "$TOPOLOGY_DB"

args=(live-check-hosts
  --db "$TOPOLOGY_DB"
  --rules "$PROVIDER_RULES"
  --limit "$LIVE_LIMIT"
  --concurrency "$LIVE_CONCURRENCY"
  --min-delay-ms "$LIVE_DELAY_MS"
  --timeout "$LIVE_TIMEOUT")

hns-topology "${args[@]}"

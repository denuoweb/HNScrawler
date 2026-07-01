#!/usr/bin/env bash
set -euo pipefail

TOPOLOGY_DB="${TOPOLOGY_DB:-data/topology.sqlite}"
PROVIDER_RULES="${PROVIDER_RULES:-configs/provider_rules.json}"
CHANGED_NAMES_FILE="${CHANGED_NAMES_FILE:-}"
SCAN_BLOCK_HEIGHT="${SCAN_BLOCK_HEIGHT:-}"

. .venv/bin/activate

if [[ -n "$CHANGED_NAMES_FILE" ]]; then
  hns-topology incremental --db "$TOPOLOGY_DB" --rules "$PROVIDER_RULES" --changed-names-file "$CHANGED_NAMES_FILE"
elif [[ -n "$SCAN_BLOCK_HEIGHT" ]]; then
  hns-topology incremental --db "$TOPOLOGY_DB" --rules "$PROVIDER_RULES" --scan-block-height "$SCAN_BLOCK_HEIGHT"
else
  echo "Set CHANGED_NAMES_FILE or SCAN_BLOCK_HEIGHT for incremental mode." >&2
  exit 2
fi


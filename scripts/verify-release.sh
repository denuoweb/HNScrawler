#!/usr/bin/env bash
set -euo pipefail

TOPOLOGY_DB="${TOPOLOGY_DB:-data/topology.sqlite}"
PUBLIC_DIR="${PUBLIC_DIR:-public}"
REQUIRE_LIVE_CHECKS="${REQUIRE_LIVE_CHECKS:-0}"
MIN_INDEXED_HEIGHT="${MIN_INDEXED_HEIGHT:-0}"

. .venv/bin/activate

args=(validate-release --db "$TOPOLOGY_DB" --public-dir "$PUBLIC_DIR")
if [ "$REQUIRE_LIVE_CHECKS" = "1" ]; then
  args+=(--require-live-checks)
fi
if [ "$MIN_INDEXED_HEIGHT" != "0" ]; then
  args+=(--min-indexed-height "$MIN_INDEXED_HEIGHT")
fi

hns-topology "${args[@]}"

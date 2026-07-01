#!/usr/bin/env bash
set -euo pipefail

TOPOLOGY_DB="${TOPOLOGY_DB:-data/topology.sqlite}"
PROVIDER_RULES="${PROVIDER_RULES:-configs/provider_rules.json}"
LIVE_LIMIT="${LIVE_LIMIT:-1000}"
LIVE_CONCURRENCY="${LIVE_CONCURRENCY:-4}"
LIVE_DELAY_MS="${LIVE_DELAY_MS:-250}"
LIVE_TIMEOUT="${LIVE_TIMEOUT:-5}"

. .venv/bin/activate
hns-topology live-check \
  --db "$TOPOLOGY_DB" \
  --rules "$PROVIDER_RULES" \
  --limit "$LIVE_LIMIT" \
  --concurrency "$LIVE_CONCURRENCY" \
  --min-delay-ms "$LIVE_DELAY_MS" \
  --timeout "$LIVE_TIMEOUT"


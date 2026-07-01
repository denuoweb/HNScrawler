#!/usr/bin/env bash
set -euo pipefail

TOPOLOGY_DB="${TOPOLOGY_DB:-data/topology.sqlite}"
PROVIDER_RULES="${PROVIDER_RULES:-configs/provider_rules.json}"

. .venv/bin/activate
hns-topology bootstrap --db "$TOPOLOGY_DB" --rules "$PROVIDER_RULES"


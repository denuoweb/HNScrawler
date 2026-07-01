#!/usr/bin/env bash
set -euo pipefail

TOPOLOGY_DB="${TOPOLOGY_DB:-data/topology.sqlite}"
PUBLIC_DIR="${PUBLIC_DIR:-public}"
NAMES_LIMIT="${NAMES_LIMIT:-5000}"

. .venv/bin/activate
hns-topology generate-site --db "$TOPOLOGY_DB" --out "$PUBLIC_DIR" --names-limit "$NAMES_LIMIT"


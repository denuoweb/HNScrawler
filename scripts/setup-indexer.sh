#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y git curl jq rsync python3 python3-venv python3-pip nodejs npm

if ! command -v hsd >/dev/null 2>&1; then
  sudo npm install -g hsd hs-client
fi

INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
if [ -d "$INDEXER_MOUNT" ] && ! mountpoint -q "$INDEXER_MOUNT"; then
  echo "$INDEXER_MOUNT exists but is not mounted; run scripts/setup-indexer-disk.sh first" >&2
  exit 2
fi
mkdir -p "$INDEXER_MOUNT/data" "$INDEXER_MOUNT/public" "$INDEXER_MOUNT/logs"

python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -e '.[dev]'

mkdir -p data public

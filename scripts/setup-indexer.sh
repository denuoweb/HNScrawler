#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y git curl rsync python3 python3-venv python3-pip nodejs npm

if ! command -v hsd >/dev/null 2>&1; then
  sudo npm install -g hsd hs-client
fi

python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -e '.[dev]'

mkdir -p data public


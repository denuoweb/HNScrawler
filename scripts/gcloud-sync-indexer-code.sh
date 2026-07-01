#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_REPO_DIR="${INDEXER_REPO_DIR:-/mnt/hnscrawler/HNScrawler}"
REPO_URL="${REPO_URL:-https://github.com/denuoweb/HNScrawler.git}"

gcloud compute ssh "$INDEXER_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "set -euo pipefail
if ! command -v git >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y git
fi
if [ ! -d '$INDEXER_REPO_DIR/.git' ]; then
  rm -rf '$INDEXER_REPO_DIR'
  git clone '$REPO_URL' '$INDEXER_REPO_DIR'
else
  git -C '$INDEXER_REPO_DIR' fetch --prune
  git -C '$INDEXER_REPO_DIR' checkout main
  git -C '$INDEXER_REPO_DIR' pull --ff-only
fi
git -C '$INDEXER_REPO_DIR' status --short --branch"

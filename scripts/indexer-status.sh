#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
INDEXER_REPO_DIR="${INDEXER_REPO_DIR:-/mnt/hnscrawler/HNScrawler}"
INDEXER_HSD_PREFIX="${INDEXER_HSD_PREFIX:-/mnt/hnscrawler/hsd}"

gcloud compute ssh "$INDEXER_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "set -euo pipefail
echo '== disks =='
df -h / '$INDEXER_MOUNT' 2>/dev/null || df -h /
if mountpoint -q '$INDEXER_MOUNT'; then
  echo '$INDEXER_MOUNT mounted'
else
  echo '$INDEXER_MOUNT not mounted'
fi

echo
echo '== repo =='
if [ -d '$INDEXER_REPO_DIR/.git' ]; then
  git -C '$INDEXER_REPO_DIR' status --short --branch
  git -C '$INDEXER_REPO_DIR' rev-parse --short HEAD
else
  echo '$INDEXER_REPO_DIR is not a git checkout'
fi

echo
echo '== hsd service =='
systemctl is-enabled hsd 2>/dev/null || true
systemctl is-active hsd 2>/dev/null || true
du -sh '$INDEXER_HSD_PREFIX' 2>/dev/null || true

echo
echo '== readiness =='
if [ -x '$INDEXER_REPO_DIR/.venv/bin/hns-topology' ]; then
  cd '$INDEXER_REPO_DIR'
  scripts/check-hsd-ready.sh || true
else
  echo 'hns-topology venv is not installed'
fi"

#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"

gcloud compute ssh "$INDEXER_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "set -euo pipefail
df -h / '$INDEXER_MOUNT' 2>/dev/null || df -h /
systemctl is-enabled hsd 2>/dev/null || true
systemctl is-active hsd 2>/dev/null || true
if [ -f '$INDEXER_MOUNT/secrets/hsd.env' ]; then
  set -a
  . '$INDEXER_MOUNT/secrets/hsd.env'
  set +a
  curl -sS --max-time 5 -u x:\$HSD_API_KEY -H 'Content-Type: application/json' --data '{\"method\":\"getblockchaininfo\",\"params\":[]}' \$HSD_RPC_URL || true
fi"

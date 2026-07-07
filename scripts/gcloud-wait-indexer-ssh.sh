#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_SSH_READY_ATTEMPTS="${INDEXER_SSH_READY_ATTEMPTS:-24}"
INDEXER_SSH_READY_INTERVAL_SECONDS="${INDEXER_SSH_READY_INTERVAL_SECONDS:-5}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/gcloud-ssh-lib.sh"

for attempt in $(seq 1 "$INDEXER_SSH_READY_ATTEMPTS"); do
  if gcloud_compute_ssh "$INDEXER_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --quiet \
    --command "true" >/dev/null 2>&1; then
    echo "indexer SSH ready"
    exit 0
  fi
  echo "indexer SSH not ready; attempt $attempt/$INDEXER_SSH_READY_ATTEMPTS, sleeping $INDEXER_SSH_READY_INTERVAL_SECONDS seconds"
  sleep "$INDEXER_SSH_READY_INTERVAL_SECONDS"
done

echo "indexer SSH did not become ready" >&2
exit 1

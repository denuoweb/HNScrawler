#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_PUBLIC_DIR="${INDEXER_PUBLIC_DIR:-/mnt/hnscrawler/public}"
LOCAL_TMP="${LOCAL_TMP:-}"

cleanup() {
  if [[ -n "${CREATED_TMP:-}" && -d "$CREATED_TMP" ]]; then
    rm -rf "$CREATED_TMP"
  fi
}
trap cleanup EXIT

if [[ -z "$LOCAL_TMP" ]]; then
  CREATED_TMP="$(mktemp -d)"
  LOCAL_TMP="$CREATED_TMP"
fi

mkdir -p "$LOCAL_TMP/public"

gcloud compute ssh "$INDEXER_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "set -euo pipefail
test -f '$INDEXER_PUBLIC_DIR/index.html'
tar -C '$INDEXER_PUBLIC_DIR' -czf /tmp/hns-topology-public.tar.gz ."

gcloud compute scp \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  "$INDEXER_VM:/tmp/hns-topology-public.tar.gz" \
  "$LOCAL_TMP/hns-topology-public.tar.gz"

tar -C "$LOCAL_TMP/public" -xzf "$LOCAL_TMP/hns-topology-public.tar.gz"
PUBLIC_DIR="$LOCAL_TMP/public" scripts/publish-site.sh


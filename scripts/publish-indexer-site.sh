#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
INDEXER_PUBLIC_DIR="${INDEXER_PUBLIC_DIR:-/mnt/hnscrawler/public}"
INDEXER_ARCHIVE="${INDEXER_ARCHIVE:-/mnt/hnscrawler/hns-topology-public.tar.gz}"
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
mountpoint -q '$INDEXER_MOUNT' || { echo '$INDEXER_MOUNT is not mounted; refusing to archive on boot disk' >&2; exit 2; }
case '$INDEXER_ARCHIVE' in
  '$INDEXER_MOUNT'/*) ;;
  *) echo 'refusing to archive at $INDEXER_ARCHIVE; expected a path under $INDEXER_MOUNT' >&2; exit 2 ;;
esac
test -f '$INDEXER_PUBLIC_DIR/index.html'
tar -C '$INDEXER_PUBLIC_DIR' -czf '$INDEXER_ARCHIVE' ."

gcloud compute scp \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  "$INDEXER_VM:$INDEXER_ARCHIVE" \
  "$LOCAL_TMP/hns-topology-public.tar.gz"

gcloud compute ssh "$INDEXER_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "rm -f '$INDEXER_ARCHIVE'"

tar -C "$LOCAL_TMP/public" -xzf "$LOCAL_TMP/hns-topology-public.tar.gz"
PUBLIC_DIR="$LOCAL_TMP/public" scripts/publish-site.sh

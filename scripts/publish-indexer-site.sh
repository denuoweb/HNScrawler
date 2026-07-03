#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
INDEXER_REPO_DIR="${INDEXER_REPO_DIR:-/mnt/hnscrawler/HNScrawler}"
INDEXER_PUBLIC_DIR="${INDEXER_PUBLIC_DIR:-/mnt/hnscrawler/public}"
INDEXER_ARCHIVE="${INDEXER_ARCHIVE:-/mnt/hnscrawler/hns-topology-public.tar.gz}"
MIN_INDEXED_HEIGHT="${MIN_INDEXED_HEIGHT:-${HSD_MIN_BLOCK_HEIGHT:-300000}}"
LOCAL_TMP="${LOCAL_TMP:-}"

log() {
  printf '[publish-indexer] %s\n' "$*" >&2
}

cleanup() {
  if [[ -n "${CREATED_TMP:-}" && -d "$CREATED_TMP" ]]; then
    rm -rf "$CREATED_TMP"
  fi
}
trap cleanup EXIT

if [[ -z "$LOCAL_TMP" ]]; then
  LOCAL_TMP_PARENT="${LOCAL_TMP_PARENT:-$PWD/run-logs}"
  mkdir -p "$LOCAL_TMP_PARENT"
  CREATED_TMP="$(mktemp -d "$LOCAL_TMP_PARENT/hns-topology-publish.XXXXXX")"
  LOCAL_TMP="$CREATED_TMP"
fi

log "validating public site on $INDEXER_VM"
gcloud compute ssh "$INDEXER_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "set -euo pipefail
cd '$INDEXER_REPO_DIR'
. .venv/bin/activate
validate_args=(validate-public --public-dir '$INDEXER_PUBLIC_DIR')
if [ '$MIN_INDEXED_HEIGHT' != '0' ]; then
  validate_args+=(--min-indexed-height '$MIN_INDEXED_HEIGHT')
fi
hns-topology \"\${validate_args[@]}\""

log "creating compressed public archive on $INDEXER_VM from $INDEXER_PUBLIC_DIR"
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

log "downloading public archive to $LOCAL_TMP"
gcloud compute scp \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  "$INDEXER_VM:$INDEXER_ARCHIVE" \
  "$LOCAL_TMP/hns-topology-public.tar.gz"

log "removing temporary archive from $INDEXER_VM"
gcloud compute ssh "$INDEXER_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "rm -f '$INDEXER_ARCHIVE'"

log "publishing validated archive to web VM"
TMPDIR="$LOCAL_TMP" VALIDATE_BEFORE_PUBLISH=0 MIN_INDEXED_HEIGHT="$MIN_INDEXED_HEIGHT" PUBLISH_ARCHIVE="$LOCAL_TMP/hns-topology-public.tar.gz" scripts/publish-site.sh

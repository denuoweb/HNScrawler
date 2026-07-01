#!/usr/bin/env bash
set -euo pipefail

TOPOLOGY_DB="${TOPOLOGY_DB:-data/topology.sqlite}"
PUBLIC_DIR="${PUBLIC_DIR:-public}"
ARCHIVE_DIR="${ARCHIVE_DIR:-archives}"
ARCHIVE_KEEP="${ARCHIVE_KEEP:-10}"
BACKUP_BUCKET_URI="${BACKUP_BUCKET_URI:-}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"

. .venv/bin/activate

case "$ARCHIVE_DIR" in
  "$INDEXER_MOUNT"|"$INDEXER_MOUNT"/*)
    if ! mountpoint -q "$INDEXER_MOUNT"; then
      echo "$INDEXER_MOUNT is not mounted; refusing to archive to an indexer-disk path" >&2
      exit 2
    fi
    ;;
esac

args=(archive-release --db "$TOPOLOGY_DB" --public-dir "$PUBLIC_DIR" --out-dir "$ARCHIVE_DIR")
if [ -n "$ARCHIVE_KEEP" ]; then
  args+=(--keep "$ARCHIVE_KEEP")
fi

hns-topology "${args[@]}"

if [ -n "$BACKUP_BUCKET_URI" ]; then
  case "$BACKUP_BUCKET_URI" in
    gs://*) ;;
    *)
      echo "BACKUP_BUCKET_URI must start with gs://" >&2
      exit 2
      ;;
  esac
  gcloud storage cp "$ARCHIVE_DIR"/* "$BACKUP_BUCKET_URI"/
fi

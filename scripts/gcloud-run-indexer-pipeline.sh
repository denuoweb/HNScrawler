#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_REPO_DIR="${INDEXER_REPO_DIR:-/mnt/hnscrawler/HNScrawler}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
INDEXER_HSD_PREFIX="${INDEXER_HSD_PREFIX:-/mnt/hnscrawler/hsd}"
TOPOLOGY_DB="${TOPOLOGY_DB:-/mnt/hnscrawler/data/topology.sqlite}"
PUBLIC_DIR="${PUBLIC_DIR:-/mnt/hnscrawler/public}"
PROVIDER_RULES="${PROVIDER_RULES:-/mnt/hnscrawler/HNScrawler/configs/provider_rules.json}"
PIPELINE_MODE="${PIPELINE_MODE:-incremental}"
CHECK_HSD_READY="${CHECK_HSD_READY:-1}"
RUN_ARCHIVE="${RUN_ARCHIVE:-0}"
ARCHIVE_DIR="${ARCHIVE_DIR:-/mnt/hnscrawler/archives}"
ARCHIVE_KEEP="${ARCHIVE_KEEP:-10}"
BACKUP_BUCKET_URI="${BACKUP_BUCKET_URI:-}"
NAMES_LIMIT="${NAMES_LIMIT:-0}"
START_HSD_FOR_UPDATES="${START_HSD_FOR_UPDATES:-1}"
STOP_HSD_AFTER_UPDATES="${STOP_HSD_AFTER_UPDATES:-1}"
HSD_MAX_BLOCK_LAG="${HSD_MAX_BLOCK_LAG:-2}"
HSD_MIN_BLOCK_HEIGHT="${HSD_MIN_BLOCK_HEIGHT:-300000}"
MIN_INDEXED_HEIGHT="${MIN_INDEXED_HEIGHT:-$HSD_MIN_BLOCK_HEIGHT}"
HSD_ALLOW_REMOTE_RPC="${HSD_ALLOW_REMOTE_RPC:-0}"
BOOTSTRAP_LIMIT="${BOOTSTRAP_LIMIT:-}"
ALLOW_UNPAGINATED_GETNAMES="${ALLOW_UNPAGINATED_GETNAMES:-0}"
ALLOW_EMPTY_BLOCK_SCAN="${ALLOW_EMPTY_BLOCK_SCAN:-0}"
ALLOW_UNRESOLVED_NAME_HASHES="${ALLOW_UNRESOLVED_NAME_HASHES:-0}"
INCREMENTAL_MAX_BLOCKS="${INCREMENTAL_MAX_BLOCKS:-300}"
INCREMENTAL_TO_HEIGHT="${INCREMENTAL_TO_HEIGHT:-}"
JSONL_PATH="${JSONL_PATH:-}"
EXPORT_LIMIT="${EXPORT_LIMIT:-}"
EXPORT_FORMAT="${EXPORT_FORMAT:-compact}"
JSONL_BOOTSTRAP_BATCH_SIZE="${JSONL_BOOTSTRAP_BATCH_SIZE:-5000}"
STOP_HSD_FOR_EXPORT="${STOP_HSD_FOR_EXPORT:-1}"
RESTART_HSD_AFTER_EXPORT="${RESTART_HSD_AFTER_EXPORT:-0}"
ALLOW_RUNNING_HSD_EXPORT="${ALLOW_RUNNING_HSD_EXPORT:-0}"
HSD_NETWORK="${HSD_NETWORK:-main}"
HSD_MODULE_ROOT="${HSD_MODULE_ROOT:-}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/gcloud-ssh-lib.sh"

case "$PIPELINE_MODE" in
  bootstrap|incremental|jsonl|extract-jsonl)
    ;;
  *)
    echo "PIPELINE_MODE must be bootstrap, incremental, jsonl, or extract-jsonl" >&2
    exit 2
    ;;
esac

gcloud_compute_ssh "$INDEXER_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "set -euo pipefail
mountpoint -q '$INDEXER_MOUNT' || { echo '$INDEXER_MOUNT is not mounted' >&2; exit 2; }
cd '$INDEXER_REPO_DIR'
git pull --ff-only
. .venv/bin/activate
export TOPOLOGY_DB='$TOPOLOGY_DB'
export PUBLIC_DIR='$PUBLIC_DIR'
export PROVIDER_RULES='$PROVIDER_RULES'
export INDEXER_HSD_PREFIX='$INDEXER_HSD_PREFIX'
export CHECK_HSD_READY='$CHECK_HSD_READY'
export START_HSD_FOR_UPDATES='$START_HSD_FOR_UPDATES'
export STOP_HSD_AFTER_UPDATES='$STOP_HSD_AFTER_UPDATES'
export NAMES_LIMIT='$NAMES_LIMIT'
export ARCHIVE_DIR='$ARCHIVE_DIR'
export ARCHIVE_KEEP='$ARCHIVE_KEEP'
export BACKUP_BUCKET_URI='$BACKUP_BUCKET_URI'
export HSD_MAX_BLOCK_LAG='$HSD_MAX_BLOCK_LAG'
export HSD_MIN_BLOCK_HEIGHT='$HSD_MIN_BLOCK_HEIGHT'
export MIN_INDEXED_HEIGHT='$MIN_INDEXED_HEIGHT'
export HSD_ALLOW_REMOTE_RPC='$HSD_ALLOW_REMOTE_RPC'
export BOOTSTRAP_LIMIT='$BOOTSTRAP_LIMIT'
export ALLOW_UNPAGINATED_GETNAMES='$ALLOW_UNPAGINATED_GETNAMES'
export ALLOW_EMPTY_BLOCK_SCAN='$ALLOW_EMPTY_BLOCK_SCAN'
export ALLOW_UNRESOLVED_NAME_HASHES='$ALLOW_UNRESOLVED_NAME_HASHES'
export INCREMENTAL_MAX_BLOCKS='$INCREMENTAL_MAX_BLOCKS'
export INCREMENTAL_TO_HEIGHT='$INCREMENTAL_TO_HEIGHT'
export JSONL_PATH='$JSONL_PATH'
export EXPORT_LIMIT='$EXPORT_LIMIT'
export EXPORT_FORMAT='$EXPORT_FORMAT'
export JSONL_BOOTSTRAP_BATCH_SIZE='$JSONL_BOOTSTRAP_BATCH_SIZE'
export STOP_HSD_FOR_EXPORT='$STOP_HSD_FOR_EXPORT'
export RESTART_HSD_AFTER_EXPORT='$RESTART_HSD_AFTER_EXPORT'
export ALLOW_RUNNING_HSD_EXPORT='$ALLOW_RUNNING_HSD_EXPORT'
export HSD_NETWORK='$HSD_NETWORK'
export HSD_MODULE_ROOT='$HSD_MODULE_ROOT'
if [ -f '$INDEXER_MOUNT/secrets/hsd.env' ]; then
  set -a
  . '$INDEXER_MOUNT/secrets/hsd.env'
  set +a
fi
log_step() {
  printf '[pipeline] %s %s\n' \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\" \"\$1\"
}
update_needs_hsd() {
  case '$PIPELINE_MODE' in
    bootstrap|incremental|extract-jsonl) return 0 ;;
    *) return 1 ;;
  esac
}
hsd_started_for_update=0
start_hsd_for_update() {
  if update_needs_hsd && [ \"\$START_HSD_FOR_UPDATES\" = '1' ]; then
    log_step 'hsd start for update'
    sudo systemctl start hsd
    hsd_started_for_update=1
  fi
}
stop_hsd_after_update() {
  if [ \"\$hsd_started_for_update\" = '1' ] && [ \"\$STOP_HSD_AFTER_UPDATES\" = '1' ]; then
    log_step 'hsd stop after update'
    sudo systemctl stop hsd
    hsd_started_for_update=0
  fi
}
cleanup_hsd() {
  stop_hsd_after_update || true
}
trap cleanup_hsd EXIT
log_step 'start mode=$PIPELINE_MODE names_limit=$NAMES_LIMIT'
start_hsd_for_update
case '$PIPELINE_MODE' in
  bootstrap)
    log_step 'bootstrap start'
    scripts/run-bootstrap.sh
    log_step 'bootstrap done'
    ;;
  incremental)
    log_step 'incremental start'
    scripts/run-incremental.sh
    log_step 'incremental done'
    ;;
  jsonl)
    [ -n \"\$JSONL_PATH\" ] || { echo 'JSONL_PATH is required for PIPELINE_MODE=jsonl' >&2; exit 2; }
    log_step 'jsonl bootstrap start'
    hns-topology bootstrap-jsonl --jsonl \"\$JSONL_PATH\" --db '$TOPOLOGY_DB' --rules '$PROVIDER_RULES' --batch-size \"\$JSONL_BOOTSTRAP_BATCH_SIZE\"
    log_step 'jsonl bootstrap done'
    ;;
  extract-jsonl)
    if [ -z \"\$JSONL_PATH\" ]; then
      export JSONL_PATH='$INDEXER_MOUNT/data/extracted_names.jsonl'
    fi
    log_step 'extract-jsonl start'
    scripts/export-hsd-jsonl.sh
    log_step 'jsonl bootstrap start'
    hns-topology bootstrap-jsonl --jsonl \"\$JSONL_PATH\" --db '$TOPOLOGY_DB' --rules '$PROVIDER_RULES' --batch-size \"\$JSONL_BOOTSTRAP_BATCH_SIZE\"
    log_step 'extract-jsonl done'
    ;;
esac
stop_hsd_after_update
log_step 'generate site start'
scripts/generate-site.sh
log_step 'generate site done'
log_step 'verify release start'
scripts/verify-release.sh
log_step 'verify release done'
if [ '$RUN_ARCHIVE' = '1' ]; then
  log_step 'archive start'
  scripts/archive-release.sh
  log_step 'archive done'
fi
log_step 'public file listing start'
find '$PUBLIC_DIR' -maxdepth 2 -type f | sort | sed -n '1,80p'"

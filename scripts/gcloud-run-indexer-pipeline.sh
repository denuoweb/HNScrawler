#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_REPO_DIR="${INDEXER_REPO_DIR:-/mnt/hnscrawler/HNScrawler}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
INDEXER_USER="${INDEXER_USER:-den}"
INDEXER_HSD_PREFIX="${INDEXER_HSD_PREFIX:-/mnt/hnscrawler/hsd}"
TOPOLOGY_DB="${TOPOLOGY_DB:-/mnt/hnscrawler/data/topology.sqlite}"
PUBLIC_DIR="${PUBLIC_DIR:-/mnt/hnscrawler/public}"
PROVIDER_RULES="${PROVIDER_RULES:-/mnt/hnscrawler/HNScrawler/configs/provider_rules.json}"
PIPELINE_MODE="${PIPELINE_MODE:-incremental}"
CHECK_HSD_READY="${CHECK_HSD_READY:-1}"
RUN_ARCHIVE="${RUN_ARCHIVE:-0}"
RUN_PUBLISH_FROM_INDEXER="${RUN_PUBLISH_FROM_INDEXER:-0}"
ARCHIVE_DIR="${ARCHIVE_DIR:-/mnt/hnscrawler/archives}"
ARCHIVE_KEEP="${ARCHIVE_KEEP:-10}"
BACKUP_BUCKET_URI="${BACKUP_BUCKET_URI:-}"
NAMES_LIMIT="${NAMES_LIMIT:-0}"
START_HSD_FOR_UPDATES="${START_HSD_FOR_UPDATES:-1}"
STOP_HSD_AFTER_UPDATES="${STOP_HSD_AFTER_UPDATES:-1}"
HSD_MAX_BLOCK_LAG="${HSD_MAX_BLOCK_LAG:-2}"
HSD_MIN_BLOCK_HEIGHT="${HSD_MIN_BLOCK_HEIGHT:-300000}"
HSD_START_READY_ATTEMPTS="${HSD_START_READY_ATTEMPTS:-60}"
HSD_START_READY_INTERVAL_SECONDS="${HSD_START_READY_INTERVAL_SECONDS:-5}"
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
INDEXER_GIT_PULL="${INDEXER_GIT_PULL:-1}"
INDEXER_PIPELINE_RUNNER="${INDEXER_PIPELINE_RUNNER:-systemd}"
INDEXER_PIPELINE_UNIT="${INDEXER_PIPELINE_UNIT:-hns-topology-indexer-pipeline}"
INDEXER_PIPELINE_WAIT="${INDEXER_PIPELINE_WAIT:-1}"
INDEXER_PIPELINE_STATUS_INTERVAL_SECONDS="${INDEXER_PIPELINE_STATUS_INTERVAL_SECONDS:-60}"
INDEXER_PIPELINE_LOG="${INDEXER_PIPELINE_LOG:-$INDEXER_MOUNT/logs/$INDEXER_PIPELINE_UNIT.log}"
INDEXER_PIPELINE_TAIL_LINES="${INDEXER_PIPELINE_TAIL_LINES:-80}"
DENUO_WEB_VM="${DENUO_WEB_VM:-denuoweb-vm}"
DENUO_WEB_PATH="${DENUO_WEB_PATH:-/var/www/denuoweb/hns-topology}"
DENUO_WEB_TARGET_TAGS="${DENUO_WEB_TARGET_TAGS:-denuoweb}"
PROD_ARTIFACT_MOUNT="${PROD_ARTIFACT_MOUNT:-/mnt/hns-topology}"
PROD_LOOKUP_DB="${PROD_LOOKUP_DB:-$PROD_ARTIFACT_MOUNT/topology.sqlite}"
PUBLISH_LOOKUP_DB="${PUBLISH_LOOKUP_DB:-1}"
ALLOW_BOOT_DISK_PUBLISH="${ALLOW_BOOT_DISK_PUBLISH:-0}"
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

case "$INDEXER_PIPELINE_RUNNER" in
  systemd|ssh)
    ;;
  *)
    echo "INDEXER_PIPELINE_RUNNER must be systemd or ssh" >&2
    exit 2
    ;;
esac

remote_quote() {
  printf "%q" "$1"
}

write_env_var() {
  local name="$1"
  local value="$2"
  printf "%s=%q\n" "$name" "$value"
}

run_ssh_runner() {
  gcloud_compute_ssh "$INDEXER_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --quiet \
    --command "set -euo pipefail
cd $(remote_quote "$INDEXER_REPO_DIR")
export INDEXER_REPO_DIR=$(remote_quote "$INDEXER_REPO_DIR")
export INDEXER_MOUNT=$(remote_quote "$INDEXER_MOUNT")
export INDEXER_HSD_PREFIX=$(remote_quote "$INDEXER_HSD_PREFIX")
export TOPOLOGY_DB=$(remote_quote "$TOPOLOGY_DB")
export PUBLIC_DIR=$(remote_quote "$PUBLIC_DIR")
export PROVIDER_RULES=$(remote_quote "$PROVIDER_RULES")
export PIPELINE_MODE=$(remote_quote "$PIPELINE_MODE")
export CHECK_HSD_READY=$(remote_quote "$CHECK_HSD_READY")
export RUN_ARCHIVE=$(remote_quote "$RUN_ARCHIVE")
export RUN_PUBLISH_FROM_INDEXER=$(remote_quote "$RUN_PUBLISH_FROM_INDEXER")
export ARCHIVE_DIR=$(remote_quote "$ARCHIVE_DIR")
export ARCHIVE_KEEP=$(remote_quote "$ARCHIVE_KEEP")
export BACKUP_BUCKET_URI=$(remote_quote "$BACKUP_BUCKET_URI")
export NAMES_LIMIT=$(remote_quote "$NAMES_LIMIT")
export START_HSD_FOR_UPDATES=$(remote_quote "$START_HSD_FOR_UPDATES")
export STOP_HSD_AFTER_UPDATES=$(remote_quote "$STOP_HSD_AFTER_UPDATES")
export HSD_MAX_BLOCK_LAG=$(remote_quote "$HSD_MAX_BLOCK_LAG")
export HSD_MIN_BLOCK_HEIGHT=$(remote_quote "$HSD_MIN_BLOCK_HEIGHT")
export HSD_START_READY_ATTEMPTS=$(remote_quote "$HSD_START_READY_ATTEMPTS")
export HSD_START_READY_INTERVAL_SECONDS=$(remote_quote "$HSD_START_READY_INTERVAL_SECONDS")
export MIN_INDEXED_HEIGHT=$(remote_quote "$MIN_INDEXED_HEIGHT")
export HSD_ALLOW_REMOTE_RPC=$(remote_quote "$HSD_ALLOW_REMOTE_RPC")
export BOOTSTRAP_LIMIT=$(remote_quote "$BOOTSTRAP_LIMIT")
export ALLOW_UNPAGINATED_GETNAMES=$(remote_quote "$ALLOW_UNPAGINATED_GETNAMES")
export ALLOW_EMPTY_BLOCK_SCAN=$(remote_quote "$ALLOW_EMPTY_BLOCK_SCAN")
export ALLOW_UNRESOLVED_NAME_HASHES=$(remote_quote "$ALLOW_UNRESOLVED_NAME_HASHES")
export INCREMENTAL_MAX_BLOCKS=$(remote_quote "$INCREMENTAL_MAX_BLOCKS")
export INCREMENTAL_TO_HEIGHT=$(remote_quote "$INCREMENTAL_TO_HEIGHT")
export JSONL_PATH=$(remote_quote "$JSONL_PATH")
export EXPORT_LIMIT=$(remote_quote "$EXPORT_LIMIT")
export EXPORT_FORMAT=$(remote_quote "$EXPORT_FORMAT")
export JSONL_BOOTSTRAP_BATCH_SIZE=$(remote_quote "$JSONL_BOOTSTRAP_BATCH_SIZE")
export STOP_HSD_FOR_EXPORT=$(remote_quote "$STOP_HSD_FOR_EXPORT")
export RESTART_HSD_AFTER_EXPORT=$(remote_quote "$RESTART_HSD_AFTER_EXPORT")
export ALLOW_RUNNING_HSD_EXPORT=$(remote_quote "$ALLOW_RUNNING_HSD_EXPORT")
export HSD_NETWORK=$(remote_quote "$HSD_NETWORK")
export HSD_MODULE_ROOT=$(remote_quote "$HSD_MODULE_ROOT")
export INDEXER_GIT_PULL=$(remote_quote "$INDEXER_GIT_PULL")
export GCP_PROJECT=$(remote_quote "$GCP_PROJECT")
export GCP_ZONE=$(remote_quote "$GCP_ZONE")
export DENUO_WEB_VM=$(remote_quote "$DENUO_WEB_VM")
export DENUO_WEB_PATH=$(remote_quote "$DENUO_WEB_PATH")
export DENUO_WEB_TARGET_TAGS=$(remote_quote "$DENUO_WEB_TARGET_TAGS")
export PROD_ARTIFACT_MOUNT=$(remote_quote "$PROD_ARTIFACT_MOUNT")
export PROD_LOOKUP_DB=$(remote_quote "$PROD_LOOKUP_DB")
export PUBLISH_LOOKUP_DB=$(remote_quote "$PUBLISH_LOOKUP_DB")
export ALLOW_BOOT_DISK_PUBLISH=$(remote_quote "$ALLOW_BOOT_DISK_PUBLISH")
exec scripts/run-indexer-pipeline-local.sh"
}

start_systemd_runner() {
  local local_env_file
  local remote_env_dir="$INDEXER_MOUNT/run"
  local remote_env_file="$remote_env_dir/$INDEXER_PIPELINE_UNIT.env"
  local remote_tmp_file="/tmp/$INDEXER_PIPELINE_UNIT.env.$$"
  local start_command

  local_env_file="$(mktemp)"
  trap "rm -f $(remote_quote "$local_env_file")" EXIT

  {
    write_env_var INDEXER_REPO_DIR "$INDEXER_REPO_DIR"
    write_env_var INDEXER_MOUNT "$INDEXER_MOUNT"
    write_env_var INDEXER_HSD_PREFIX "$INDEXER_HSD_PREFIX"
    write_env_var TOPOLOGY_DB "$TOPOLOGY_DB"
    write_env_var PUBLIC_DIR "$PUBLIC_DIR"
    write_env_var PROVIDER_RULES "$PROVIDER_RULES"
    write_env_var PIPELINE_MODE "$PIPELINE_MODE"
    write_env_var CHECK_HSD_READY "$CHECK_HSD_READY"
    write_env_var RUN_ARCHIVE "$RUN_ARCHIVE"
    write_env_var RUN_PUBLISH_FROM_INDEXER "$RUN_PUBLISH_FROM_INDEXER"
    write_env_var ARCHIVE_DIR "$ARCHIVE_DIR"
    write_env_var ARCHIVE_KEEP "$ARCHIVE_KEEP"
    write_env_var BACKUP_BUCKET_URI "$BACKUP_BUCKET_URI"
    write_env_var NAMES_LIMIT "$NAMES_LIMIT"
    write_env_var START_HSD_FOR_UPDATES "$START_HSD_FOR_UPDATES"
    write_env_var STOP_HSD_AFTER_UPDATES "$STOP_HSD_AFTER_UPDATES"
    write_env_var HSD_MAX_BLOCK_LAG "$HSD_MAX_BLOCK_LAG"
    write_env_var HSD_MIN_BLOCK_HEIGHT "$HSD_MIN_BLOCK_HEIGHT"
    write_env_var HSD_START_READY_ATTEMPTS "$HSD_START_READY_ATTEMPTS"
    write_env_var HSD_START_READY_INTERVAL_SECONDS "$HSD_START_READY_INTERVAL_SECONDS"
    write_env_var MIN_INDEXED_HEIGHT "$MIN_INDEXED_HEIGHT"
    write_env_var HSD_ALLOW_REMOTE_RPC "$HSD_ALLOW_REMOTE_RPC"
    write_env_var BOOTSTRAP_LIMIT "$BOOTSTRAP_LIMIT"
    write_env_var ALLOW_UNPAGINATED_GETNAMES "$ALLOW_UNPAGINATED_GETNAMES"
    write_env_var ALLOW_EMPTY_BLOCK_SCAN "$ALLOW_EMPTY_BLOCK_SCAN"
    write_env_var ALLOW_UNRESOLVED_NAME_HASHES "$ALLOW_UNRESOLVED_NAME_HASHES"
    write_env_var INCREMENTAL_MAX_BLOCKS "$INCREMENTAL_MAX_BLOCKS"
    write_env_var INCREMENTAL_TO_HEIGHT "$INCREMENTAL_TO_HEIGHT"
    write_env_var JSONL_PATH "$JSONL_PATH"
    write_env_var EXPORT_LIMIT "$EXPORT_LIMIT"
    write_env_var EXPORT_FORMAT "$EXPORT_FORMAT"
    write_env_var JSONL_BOOTSTRAP_BATCH_SIZE "$JSONL_BOOTSTRAP_BATCH_SIZE"
    write_env_var STOP_HSD_FOR_EXPORT "$STOP_HSD_FOR_EXPORT"
    write_env_var RESTART_HSD_AFTER_EXPORT "$RESTART_HSD_AFTER_EXPORT"
    write_env_var ALLOW_RUNNING_HSD_EXPORT "$ALLOW_RUNNING_HSD_EXPORT"
    write_env_var HSD_NETWORK "$HSD_NETWORK"
    write_env_var HSD_MODULE_ROOT "$HSD_MODULE_ROOT"
    write_env_var INDEXER_GIT_PULL "$INDEXER_GIT_PULL"
    write_env_var GCP_PROJECT "$GCP_PROJECT"
    write_env_var GCP_ZONE "$GCP_ZONE"
    write_env_var DENUO_WEB_VM "$DENUO_WEB_VM"
    write_env_var DENUO_WEB_PATH "$DENUO_WEB_PATH"
    write_env_var DENUO_WEB_TARGET_TAGS "$DENUO_WEB_TARGET_TAGS"
    write_env_var PROD_ARTIFACT_MOUNT "$PROD_ARTIFACT_MOUNT"
    write_env_var PROD_LOOKUP_DB "$PROD_LOOKUP_DB"
    write_env_var PUBLISH_LOOKUP_DB "$PUBLISH_LOOKUP_DB"
    write_env_var ALLOW_BOOT_DISK_PUBLISH "$ALLOW_BOOT_DISK_PUBLISH"
  } > "$local_env_file"

  gcloud_compute_ssh "$INDEXER_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --quiet \
    --command "set -euo pipefail
mountpoint -q $(remote_quote "$INDEXER_MOUNT") || { echo $(remote_quote "$INDEXER_MOUNT is not mounted") >&2; exit 2; }
mkdir -p $(remote_quote "$remote_env_dir") $(remote_quote "$(dirname "$INDEXER_PIPELINE_LOG")")"

  gcloud_compute_scp \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --quiet \
    "$local_env_file" \
    "$INDEXER_VM:$remote_tmp_file"

  gcloud_compute_ssh "$INDEXER_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --quiet \
    --command "set -euo pipefail
mv $(remote_quote "$remote_tmp_file") $(remote_quote "$remote_env_file")
chmod 600 $(remote_quote "$remote_env_file")
: > $(remote_quote "$INDEXER_PIPELINE_LOG")
chmod 644 $(remote_quote "$INDEXER_PIPELINE_LOG")"

  start_command="set -euo pipefail; set -a; . $(remote_quote "$remote_env_file"); set +a; exec $(remote_quote "$INDEXER_REPO_DIR/scripts/run-indexer-pipeline-local.sh")"

  gcloud_compute_ssh "$INDEXER_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --quiet \
    --command "set -euo pipefail
sudo systemctl reset-failed $(remote_quote "$INDEXER_PIPELINE_UNIT.service") >/dev/null 2>&1 || true
sudo systemd-run \
  --unit=$(remote_quote "$INDEXER_PIPELINE_UNIT") \
  --uid=$(remote_quote "$INDEXER_USER") \
  --gid=$(remote_quote "$INDEXER_USER") \
  --property=WorkingDirectory=$(remote_quote "$INDEXER_REPO_DIR") \
  --property=StandardOutput=append:$(remote_quote "$INDEXER_PIPELINE_LOG") \
  --property=StandardError=append:$(remote_quote "$INDEXER_PIPELINE_LOG") \
  /usr/bin/bash -lc $(remote_quote "$start_command")
echo $(remote_quote "started $INDEXER_PIPELINE_UNIT.service log=$INDEXER_PIPELINE_LOG")"
}

wait_systemd_runner() {
  local status

  if [ "$INDEXER_PIPELINE_WAIT" != "1" ]; then
    return 0
  fi

  while true; do
    set +e
    gcloud_compute_ssh "$INDEXER_VM" \
      --project "$GCP_PROJECT" \
      --zone "$GCP_ZONE" \
      --quiet \
      --command "set -uo pipefail
unit=$(remote_quote "$INDEXER_PIPELINE_UNIT.service")
log=$(remote_quote "$INDEXER_PIPELINE_LOG")
active=\$(sudo systemctl show \"\$unit\" --property=ActiveState --value 2>/dev/null || true)
load=\$(sudo systemctl show \"\$unit\" --property=LoadState --value 2>/dev/null || true)
sub=\$(sudo systemctl show \"\$unit\" --property=SubState --value 2>/dev/null || true)
result=\$(sudo systemctl show \"\$unit\" --property=Result --value 2>/dev/null || true)
main_status=\$(sudo systemctl show \"\$unit\" --property=ExecMainStatus --value 2>/dev/null || true)
printf '[pipeline-status] %s load=%s active=%s sub=%s result=%s exit=%s log=%s\n' \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\" \"\$load\" \"\$active\" \"\$sub\" \"\$result\" \"\$main_status\" \"\$log\"
if [ -f \"\$log\" ]; then
  tail -n $(remote_quote "$INDEXER_PIPELINE_TAIL_LINES") \"\$log\"
fi
if [ \"\$load\" = 'not-found' ] || [ -z \"\$active\" ]; then
  if [ -f \"\$log\" ] && grep -q '\\[pipeline\\].* done$' \"\$log\"; then
    exit 0
  fi
  exit 20
fi
case \"\$active:\$result:\$main_status\" in
  active:*) exit 10 ;;
  inactive:success:0) exit 0 ;;
  inactive::0) exit 0 ;;
  inactive:success:) exit 0 ;;
  *) exit 20 ;;
esac"
    status=$?
    set -e

    case "$status" in
      0)
        return 0
        ;;
      10)
        sleep "$INDEXER_PIPELINE_STATUS_INTERVAL_SECONDS"
        ;;
      *)
        return "$status"
        ;;
    esac
  done
}

case "$INDEXER_PIPELINE_RUNNER" in
  ssh)
    run_ssh_runner
    ;;
  systemd)
    start_systemd_runner
    wait_systemd_runner
    ;;
esac

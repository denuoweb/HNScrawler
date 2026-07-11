#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="${PRODUCTION_CYCLE_LOG_DIR:-$REPO_DIR/logs/production-cycle}"
RUN_LABEL="${1:-${PRODUCTION_RUN_LABEL:-production}}"
SAFE_LABEL="$(printf '%s' "$RUN_LABEL" | tr -c 'A-Za-z0-9_.-' '-')"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_PATH="$LOG_DIR/$TIMESTAMP-$SAFE_LABEL.log"
LOCK_PATH="${PRODUCTION_CYCLE_LOCK:-$LOG_DIR/production-cycle.lock}"

mkdir -p "$LOG_DIR"
ln -sfn "$(basename "$LOG_PATH")" "$LOG_DIR/latest.log"

exec 9>"$LOCK_PATH"
if ! flock -n 9; then
  {
    printf '[production-cycle] %s another run is already active\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '[production-cycle] log=%s\n' "$LOG_PATH"
  } | tee -a "$LOG_PATH"
  exit 75
fi

exec > >(tee -a "$LOG_PATH") 2>&1

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SECONDS=0

echo "[production-cycle] started_at=$STARTED_AT"
echo "[production-cycle] label=$RUN_LABEL"
echo "[production-cycle] repo=$REPO_DIR"
echo "[production-cycle] log=$LOG_PATH"

export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"
export CONFIRM_PRODUCTION_RUN="${CONFIRM_PRODUCTION_RUN:-1}"
export PIPELINE_MODE="${PIPELINE_MODE:-incremental}"
export START_HSD="${START_HSD:-0}"
export WAIT_FOR_HSD_READY="${WAIT_FOR_HSD_READY:-0}"
export RUN_PREFLIGHT="${RUN_PREFLIGHT:-1}"
export PROVISION_INDEXER="${PROVISION_INDEXER:-1}"
export SETUP_INDEXER="${SETUP_INDEXER:-1}"
export SETUP_HSD="${SETUP_HSD:-1}"
export RUN_PIPELINE="${RUN_PIPELINE:-1}"
export RUN_PUBLISH="${RUN_PUBLISH:-1}"
export RUN_PUBLISH_FROM_INDEXER="${RUN_PUBLISH_FROM_INDEXER:-1}"
export INDEXER_PIPELINE_RUNNER="${INDEXER_PIPELINE_RUNNER:-systemd}"
export INDEXER_PIPELINE_WAIT="${INDEXER_PIPELINE_WAIT:-1}"
export HSD_START_READY_ATTEMPTS="${HSD_START_READY_ATTEMPTS:-720}"
export HSD_START_READY_INTERVAL_SECONDS="${HSD_START_READY_INTERVAL_SECONDS:-60}"
export INCREMENTAL_MAX_BLOCKS="${INCREMENTAL_MAX_BLOCKS:-1500}"
export INDEXER_SSH_TUNNEL_THROUGH_IAP="${INDEXER_SSH_TUNNEL_THROUGH_IAP:-1}"
export INDEXER_FINAL_ACTION="${INDEXER_FINAL_ACTION:-stop}"
export INDEXER_FAILURE_ACTION="${INDEXER_FAILURE_ACTION:-stop}"

cd "$REPO_DIR"

status=0
"$SCRIPT_DIR/gcloud-production-cycle.sh" || status=$?

FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[production-cycle] finished_at=$FINISHED_AT"
echo "[production-cycle] duration_seconds=$SECONDS"
echo "[production-cycle] exit_status=$status"
exit "$status"

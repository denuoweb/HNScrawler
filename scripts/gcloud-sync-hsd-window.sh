#!/usr/bin/env bash
set -euo pipefail

CONFIRM_HSD_SYNC_WINDOW="${CONFIRM_HSD_SYNC_WINDOW:-0}"
DRY_RUN="${DRY_RUN:-0}"
HSD_SYNC_WINDOW_MINUTES="${HSD_SYNC_WINDOW_MINUTES:-30}"
INDEXER_FINAL_ACTION="${INDEXER_FINAL_ACTION:-stop}"
INDEXER_FAILURE_ACTION="${INDEXER_FAILURE_ACTION:-stop}"

case "$INDEXER_FINAL_ACTION" in
  stop|delete-vm|keep) ;;
  *) echo "INDEXER_FINAL_ACTION must be stop, delete-vm, or keep" >&2; exit 2 ;;
esac

case "$INDEXER_FAILURE_ACTION" in
  stop|delete-vm|keep) ;;
  *) echo "INDEXER_FAILURE_ACTION must be stop, delete-vm, or keep" >&2; exit 2 ;;
esac

if ! [[ "$HSD_SYNC_WINDOW_MINUTES" =~ ^[0-9]+$ ]] || [ "$HSD_SYNC_WINDOW_MINUTES" -lt 1 ]; then
  echo "HSD_SYNC_WINDOW_MINUTES must be a positive integer" >&2
  exit 2
fi

if [ "$CONFIRM_HSD_SYNC_WINDOW" != "1" ] && [ "$DRY_RUN" != "1" ]; then
  cat >&2 <<EOF
Refusing to start a bounded HSD sync window without CONFIRM_HSD_SYNC_WINDOW=1.

Review the plan first:
  DRY_RUN=1 $0

Then run explicitly:
  CONFIRM_HSD_SYNC_WINDOW=1 HSD_SYNC_WINDOW_MINUTES=$HSD_SYNC_WINDOW_MINUTES $0

EOF
  exit 2
fi

run_cmd() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  if [ "$DRY_RUN" != "1" ]; then
    "$@"
  fi
}

cleanup_indexer() {
  if [ "$DRY_RUN" = "1" ]; then
    return
  fi
  case "$INDEXER_FINAL_ACTION" in
    stop)
      run_cmd scripts/gcloud-stop-indexer.sh
      ;;
    delete-vm)
      run_cmd scripts/gcloud-delete-indexer-vm.sh
      ;;
    keep)
      ;;
  esac
}

on_exit() {
  local status=$?
  if [ "$status" != "0" ] && [ "$DRY_RUN" != "1" ]; then
    case "$INDEXER_FAILURE_ACTION" in
      stop)
        scripts/gcloud-stop-indexer.sh || true
        ;;
      delete-vm)
        scripts/gcloud-delete-indexer-vm.sh || true
        ;;
      keep)
        ;;
    esac
  fi
  exit "$status"
}
trap on_exit EXIT

echo "bounded HSD sync window: ${HSD_SYNC_WINDOW_MINUTES}m"

start_cycle=(
  env
  CONFIRM_PRODUCTION_RUN=1
  DRY_RUN="$DRY_RUN"
  WAIT_FOR_HSD_READY=0
  RUN_PIPELINE=0
  RUN_PUBLISH=0
  INDEXER_FINAL_ACTION=keep
  INDEXER_FAILURE_ACTION="$INDEXER_FAILURE_ACTION"
  scripts/gcloud-production-cycle.sh
)
printf '+'
printf ' %q' "${start_cycle[@]}"
printf '\n'
"${start_cycle[@]}"

echo
echo "status before sync window"
run_cmd scripts/indexer-status.sh

run_cmd sleep "$((HSD_SYNC_WINDOW_MINUTES * 60))"

echo
echo "status after sync window"
run_cmd scripts/indexer-status.sh

cleanup_indexer

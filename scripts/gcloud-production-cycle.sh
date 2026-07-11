#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_REPO_DIR="${INDEXER_REPO_DIR:-/mnt/hnscrawler/HNScrawler}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/gcloud-ssh-lib.sh"

CONFIRM_PRODUCTION_RUN="${CONFIRM_PRODUCTION_RUN:-0}"
DRY_RUN="${DRY_RUN:-0}"
RUN_PREFLIGHT="${RUN_PREFLIGHT:-1}"
PROVISION_INDEXER="${PROVISION_INDEXER:-1}"
SETUP_INDEXER="${SETUP_INDEXER:-1}"
SETUP_HSD="${SETUP_HSD:-1}"
START_HSD="${START_HSD:-0}"
WAIT_FOR_HSD_READY="${WAIT_FOR_HSD_READY:-0}"
HSD_READY_ATTEMPTS="${HSD_READY_ATTEMPTS:-720}"
HSD_READY_INTERVAL_SECONDS="${HSD_READY_INTERVAL_SECONDS:-60}"
RUN_PIPELINE="${RUN_PIPELINE:-1}"
RUN_PUBLISH="${RUN_PUBLISH:-1}"
RUN_PUBLISH_FROM_INDEXER="${RUN_PUBLISH_FROM_INDEXER:-0}"
INDEXER_PIPELINE_RUNNER="${INDEXER_PIPELINE_RUNNER:-systemd}"
INDEXER_PIPELINE_WAIT="${INDEXER_PIPELINE_WAIT:-1}"
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

case "$INDEXER_PIPELINE_RUNNER" in
  systemd|ssh) ;;
  *) echo "INDEXER_PIPELINE_RUNNER must be systemd or ssh" >&2; exit 2 ;;
esac

if [ "$RUN_PIPELINE" = "1" ] && [ "$INDEXER_PIPELINE_RUNNER" = "systemd" ] && [ "$INDEXER_PIPELINE_WAIT" != "1" ]; then
  if [ "$INDEXER_FINAL_ACTION" != "keep" ] || [ "$INDEXER_FAILURE_ACTION" != "keep" ]; then
    cat >&2 <<EOF
Refusing to launch a detached remote pipeline with VM cleanup enabled.

Set INDEXER_PIPELINE_WAIT=1 so this wrapper waits for the VM-owned unit before
stopping the indexer, or set both INDEXER_FINAL_ACTION=keep and
INDEXER_FAILURE_ACTION=keep for an intentionally detached run.
EOF
    exit 2
  fi
fi

if [ "$CONFIRM_PRODUCTION_RUN" != "1" ] && [ "$DRY_RUN" != "1" ]; then
  cat >&2 <<EOF
Refusing to run a cost-bearing production cycle without CONFIRM_PRODUCTION_RUN=1.

Review the plan first:
  DRY_RUN=1 $0

Then run explicitly, for example:
  CONFIRM_PRODUCTION_RUN=1 PIPELINE_MODE=bootstrap WAIT_FOR_HSD_READY=1 $0

EOF
  exit 2
fi

RUN_FINISHED=0
CLEANUP_DONE=0

run_cmd() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  if [ "$DRY_RUN" != "1" ]; then
    "$@"
  fi
}

wait_for_hsd_ready() {
  if [ "$DRY_RUN" = "1" ]; then
    echo "would poll HSD readiness with a fresh SSH connection per attempt"
    return 0
  fi

  for attempt in $(seq 1 "$HSD_READY_ATTEMPTS"); do
    if run_cmd gcloud_compute_ssh "$INDEXER_VM" \
      --project "$GCP_PROJECT" \
      --zone "$GCP_ZONE" \
      --quiet \
      --command "cd '$INDEXER_REPO_DIR' && scripts/check-hsd-ready.sh"; then
      return 0
    fi
    echo "HSD not ready or SSH check failed; attempt $attempt/$HSD_READY_ATTEMPTS, sleeping $HSD_READY_INTERVAL_SECONDS seconds"
    sleep "$HSD_READY_INTERVAL_SECONDS"
  done
  return 1
}

instance_exists() {
  gcloud compute instances describe "$INDEXER_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" >/dev/null 2>&1
}

cleanup_indexer() {
  local action="$1"
  if [ "$CLEANUP_DONE" = "1" ] || [ "$DRY_RUN" = "1" ]; then
    return
  fi
  case "$action" in
    stop)
      if instance_exists; then
        run_cmd scripts/gcloud-stop-indexer.sh
      fi
      ;;
    delete-vm)
      if instance_exists; then
        run_cmd scripts/gcloud-delete-indexer-vm.sh
      fi
      ;;
    keep)
      ;;
  esac
  CLEANUP_DONE=1
}

on_exit() {
  local status=$?
  if [ "$RUN_FINISHED" != "1" ]; then
    cleanup_indexer "$INDEXER_FAILURE_ACTION"
  fi
  exit "$status"
}
trap on_exit EXIT

echo "production cycle"
echo "project=$GCP_PROJECT zone=$GCP_ZONE indexer=$INDEXER_VM"
if [ "$RUN_PUBLISH" = "1" ] && [ "$RUN_PUBLISH_FROM_INDEXER" = "1" ]; then
  PUBLISH_MODE="indexer"
else
  PUBLISH_MODE="$RUN_PUBLISH"
fi
echo "pipeline=${PIPELINE_MODE:-incremental} publish=$PUBLISH_MODE final=$INDEXER_FINAL_ACTION failure=$INDEXER_FAILURE_ACTION dry_run=$DRY_RUN"

if [ "$RUN_PREFLIGHT" = "1" ]; then
  run_cmd scripts/gcloud-production-preflight.sh
fi

if [ "$PROVISION_INDEXER" = "1" ]; then
  run_cmd scripts/gcloud-create-indexer.sh
  run_cmd scripts/gcloud-wait-indexer-ssh.sh
  run_cmd scripts/setup-indexer-disk.sh
  run_cmd scripts/gcloud-sync-indexer-code.sh
fi

if [ "$SETUP_INDEXER" = "1" ]; then
  run_cmd gcloud_compute_ssh "$INDEXER_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --quiet \
    --command "cd '$INDEXER_REPO_DIR' && scripts/setup-indexer.sh"
fi

if [ "$SETUP_HSD" = "1" ]; then
  run_cmd scripts/setup-hsd-service.sh
fi

if [ "$START_HSD" = "1" ]; then
  run_cmd gcloud_compute_ssh "$INDEXER_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --quiet \
    --command "sudo systemctl start hsd"
fi

if [ "$WAIT_FOR_HSD_READY" = "1" ]; then
  wait_for_hsd_ready
fi

if [ "$RUN_PIPELINE" = "1" ]; then
  run_cmd scripts/gcloud-run-indexer-pipeline.sh
fi

if [ "$RUN_PUBLISH" = "1" ] && [ "$RUN_PUBLISH_FROM_INDEXER" != "1" ]; then
  run_cmd scripts/publish-indexer-site.sh
fi

cleanup_indexer "$INDEXER_FINAL_ACTION"
RUN_FINISHED=1

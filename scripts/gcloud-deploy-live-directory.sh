#!/usr/bin/env bash
set -euo pipefail

CONFIRM_LIVE_DIRECTORY_DEPLOY="${CONFIRM_LIVE_DIRECTORY_DEPLOY:-0}"
DRY_RUN="${DRY_RUN:-0}"
GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
DENUO_WEB_VM="${DENUO_WEB_VM:-denuoweb-vm}"
LIVE_ROOT="${LIVE_ROOT:-/mnt/hns-topology/live-directory}"
LIVE_REPO_DIR="${LIVE_REPO_DIR:-$LIVE_ROOT/HNScrawler}"
REPO_URL="${REPO_URL:-https://github.com/denuoweb/HNScrawler.git}"
START_LIVE_TIMER="${START_LIVE_TIMER:-1}"
RUN_LIVE_DIRECTORY_NOW="${RUN_LIVE_DIRECTORY_NOW:-0}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/gcloud-ssh-lib.sh"

if [[ "$CONFIRM_LIVE_DIRECTORY_DEPLOY" != "1" && "$DRY_RUN" != "1" ]]; then
  cat >&2 <<EOF
Refusing to deploy the standalone live directory without CONFIRM_LIVE_DIRECTORY_DEPLOY=1.

Review the remote plan first:
  DRY_RUN=1 $0

Deploy and start its daily timer:
  CONFIRM_LIVE_DIRECTORY_DEPLOY=1 $0

Deploy without running an immediate probe batch:
  CONFIRM_LIVE_DIRECTORY_DEPLOY=1 RUN_LIVE_DIRECTORY_NOW=0 $0
EOF
  exit 2
fi

if [[ -z "$LIVE_ROOT" || "$LIVE_ROOT" == "/" ]]; then
  echo "LIVE_ROOT must be a non-root directory" >&2
  exit 2
fi
case "$LIVE_REPO_DIR/" in
  "${LIVE_ROOT%/}/"*) ;;
  *)
    echo "LIVE_REPO_DIR must be below LIVE_ROOT" >&2
    exit 2
    ;;
esac

printf -v q_live_root %q "$LIVE_ROOT"
printf -v q_live_repo %q "$LIVE_REPO_DIR"
printf -v q_live_repo_git %q "$LIVE_REPO_DIR/.git"
printf -v q_repo_url %q "$REPO_URL"
printf -v q_start_timer %q "$START_LIVE_TIMER"
printf -v q_run_now %q "$RUN_LIVE_DIRECTORY_NOW"

remote_command="set -euo pipefail
mountpoint -q /mnt/hns-topology || { echo '/mnt/hns-topology is not mounted' >&2; exit 2; }
if ! command -v git >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y git
fi
sudo mkdir -p $q_live_root
sudo chown den:www-data $q_live_root
sudo chmod 775 $q_live_root
if [ ! -d $q_live_repo_git ]; then
  if [ -e $q_live_repo ]; then
    echo 'refusing to replace a non-repository LIVE_REPO_DIR' >&2
    exit 2
  fi
  git clone $q_repo_url $q_live_repo
else
  git -C $q_live_repo fetch --prune
  git -C $q_live_repo checkout main
  git -C $q_live_repo pull --ff-only
fi
cd $q_live_repo
START_LIVE_TIMER=$q_start_timer RUN_LIVE_DIRECTORY_NOW=$q_run_now scripts/setup-live-directory-service.sh"

if [[ "$DRY_RUN" == "1" ]]; then
  printf 'gcloud compute ssh %q --project %q --zone %q --command %q\n' \
    "$DENUO_WEB_VM" "$GCP_PROJECT" "$GCP_ZONE" "$remote_command"
  exit 0
fi

gcloud_compute_ssh "$DENUO_WEB_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "$remote_command"

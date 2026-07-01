#!/usr/bin/env bash
set -euo pipefail

CONFIRM_PRODUCTION_WEB="${CONFIRM_PRODUCTION_WEB:-0}"
DRY_RUN="${DRY_RUN:-0}"

if [ "$CONFIRM_PRODUCTION_WEB" != "1" ] && [ "$DRY_RUN" != "1" ]; then
  cat >&2 <<EOF
Refusing to prepare the production web VM without CONFIRM_PRODUCTION_WEB=1.

Review the plan first:
  DRY_RUN=1 $0

Then run explicitly:
  CONFIRM_PRODUCTION_WEB=1 $0

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

run_cmd scripts/gcloud-attach-production-disk.sh
run_cmd scripts/setup-production-disk.sh
run_cmd scripts/gcloud-production-preflight.sh

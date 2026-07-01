#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_REPO_DIR="${INDEXER_REPO_DIR:-/mnt/hnscrawler/HNScrawler}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
TOPOLOGY_DB="${TOPOLOGY_DB:-/mnt/hnscrawler/data/topology.sqlite}"
PUBLIC_DIR="${PUBLIC_DIR:-/mnt/hnscrawler/public}"
PROVIDER_RULES="${PROVIDER_RULES:-/mnt/hnscrawler/HNScrawler/configs/provider_rules.json}"
PIPELINE_MODE="${PIPELINE_MODE:-incremental}"
RUN_LIVE_CHECKS="${RUN_LIVE_CHECKS:-1}"
REQUIRE_LIVE_CHECKS="${REQUIRE_LIVE_CHECKS:-$RUN_LIVE_CHECKS}"
LIVE_LIMIT="${LIVE_LIMIT:-1000}"
NAMES_LIMIT="${NAMES_LIMIT:-5000}"
JSONL_PATH="${JSONL_PATH:-}"

case "$PIPELINE_MODE" in
  bootstrap|incremental|jsonl)
    ;;
  *)
    echo "PIPELINE_MODE must be bootstrap, incremental, or jsonl" >&2
    exit 2
    ;;
esac

gcloud compute ssh "$INDEXER_VM" \
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
export LIVE_LIMIT='$LIVE_LIMIT'
export NAMES_LIMIT='$NAMES_LIMIT'
export REQUIRE_LIVE_CHECKS='$REQUIRE_LIVE_CHECKS'
if [ -f '$INDEXER_MOUNT/secrets/hsd.env' ]; then
  set -a
  . '$INDEXER_MOUNT/secrets/hsd.env'
  set +a
fi
case '$PIPELINE_MODE' in
  bootstrap)
    scripts/run-bootstrap.sh
    ;;
  incremental)
    scripts/run-incremental.sh
    ;;
  jsonl)
    [ -n '$JSONL_PATH' ] || { echo 'JSONL_PATH is required for PIPELINE_MODE=jsonl' >&2; exit 2; }
    hns-topology bootstrap-jsonl --jsonl '$JSONL_PATH' --db '$TOPOLOGY_DB' --rules '$PROVIDER_RULES'
    ;;
esac
if [ '$RUN_LIVE_CHECKS' = '1' ]; then
  scripts/run-live-checks.sh
fi
scripts/generate-site.sh
scripts/verify-release.sh
find '$PUBLIC_DIR' -maxdepth 2 -type f | sort | sed -n '1,80p'"

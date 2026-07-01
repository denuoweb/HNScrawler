#!/usr/bin/env bash
set -euo pipefail

PUBLIC_DIR="${PUBLIC_DIR:-public}"
DENUO_WEB_PATH="${DENUO_WEB_PATH:-/var/www/denuoweb/hns-topology}"
PUBLISH_VIA_GCLOUD="${PUBLISH_VIA_GCLOUD:-1}"

if [[ "$PUBLISH_VIA_GCLOUD" == "1" ]]; then
  GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
  GCP_ZONE="${GCP_ZONE:-us-west1-b}"
  DENUO_WEB_VM="${DENUO_WEB_VM:-denuoweb-vm}"
  REMOTE_TMP="/tmp/hns-topology-public"

  gcloud compute ssh "$DENUO_WEB_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --quiet \
    --command "rm -rf '$REMOTE_TMP' && mkdir -p '$REMOTE_TMP'"

  gcloud compute scp \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --quiet \
    --recurse \
    "$PUBLIC_DIR"/* \
    "$DENUO_WEB_VM:$REMOTE_TMP/"

  gcloud compute ssh "$DENUO_WEB_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --quiet \
    --command "sudo mkdir -p '$DENUO_WEB_PATH' && sudo rsync -a --delete '$REMOTE_TMP/' '$DENUO_WEB_PATH/' && sudo chown -R www-data:www-data '$DENUO_WEB_PATH' && rm -rf '$REMOTE_TMP'"
else
  DENUO_WEB_HOST="${DENUO_WEB_HOST:?set DENUO_WEB_HOST}"
  rsync -az --delete "$PUBLIC_DIR"/ "$DENUO_WEB_HOST":"$DENUO_WEB_PATH"/
fi

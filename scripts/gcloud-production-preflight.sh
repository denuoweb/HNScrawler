#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
DENUO_WEB_VM="${DENUO_WEB_VM:-denuoweb-vm}"
DENUO_WEB_PATH="${DENUO_WEB_PATH:-/var/www/denuoweb/hns-topology}"
PROD_ARTIFACT_DISK="${PROD_ARTIFACT_DISK:-hns-topology-data}"
PROD_ARTIFACT_MOUNT="${PROD_ARTIFACT_MOUNT:-/mnt/hns-topology}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_DISK="${INDEXER_DISK:-hns-topology-indexer-disk}"
ALLOW_PROJECT_MISMATCH="${ALLOW_PROJECT_MISMATCH:-0}"

configured_project="$(gcloud config get-value project 2>/dev/null || true)"
if [ "$configured_project" != "$GCP_PROJECT" ] && [ "$ALLOW_PROJECT_MISMATCH" != "1" ]; then
  echo "gcloud project is '$configured_project', expected '$GCP_PROJECT'" >&2
  exit 2
fi

echo "project: $GCP_PROJECT"
echo "zone: $GCP_ZONE"

echo
echo "production website VM:"
gcloud compute instances describe "$DENUO_WEB_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --format='table(name,status,machineType.basename(),disks[].deviceName)'

echo
echo "production artifact disk:"
gcloud compute disks describe "$PROD_ARTIFACT_DISK" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --format='table(name,sizeGb,type.basename(),users.basename(),status)'

echo
echo "production mount/path:"
gcloud compute ssh "$DENUO_WEB_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "set -euo pipefail
mountpoint -q '$PROD_ARTIFACT_MOUNT'
TARGET=\$(readlink -f '$DENUO_WEB_PATH')
case \"\$TARGET/\" in
  '$PROD_ARTIFACT_MOUNT'/*) ;;
  *) echo \"publish target \$TARGET is not under $PROD_ARTIFACT_MOUNT\" >&2; exit 2 ;;
esac
df -h / '$PROD_ARTIFACT_MOUNT'
echo '$DENUO_WEB_PATH -> '\$TARGET"

echo
echo "indexer VM:"
if gcloud compute instances describe "$INDEXER_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" >/dev/null 2>&1; then
  gcloud compute instances describe "$INDEXER_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --format='table(name,status,machineType.basename(),disks[].deviceName)'
else
  echo "not present"
fi

echo
echo "indexer disk:"
if gcloud compute disks describe "$INDEXER_DISK" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" >/dev/null 2>&1; then
  gcloud compute disks describe "$INDEXER_DISK" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --format='table(name,sizeGb,type.basename(),users.basename(),status)'
else
  echo "not present"
fi

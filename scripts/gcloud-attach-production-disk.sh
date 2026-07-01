#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
DENUO_WEB_VM="${DENUO_WEB_VM:-denuoweb-vm}"
PROD_ARTIFACT_DISK="${PROD_ARTIFACT_DISK:-hns-topology-data}"
PROD_ARTIFACT_DISK_SIZE_GB="${PROD_ARTIFACT_DISK_SIZE_GB:-200}"

if ! gcloud compute disks describe "$PROD_ARTIFACT_DISK" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" >/dev/null 2>&1; then
  gcloud compute disks create "$PROD_ARTIFACT_DISK" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --size "${PROD_ARTIFACT_DISK_SIZE_GB}GB" \
    --type pd-standard
fi

if ! gcloud compute instances describe "$DENUO_WEB_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --format='value(disks[].deviceName)' | grep -qw "$PROD_ARTIFACT_DISK"; then
  gcloud compute instances attach-disk "$DENUO_WEB_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --disk "$PROD_ARTIFACT_DISK" \
    --device-name "$PROD_ARTIFACT_DISK"
fi


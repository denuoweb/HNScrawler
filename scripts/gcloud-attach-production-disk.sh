#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
DENUO_WEB_VM="${DENUO_WEB_VM:-denuoweb-vm}"
PROD_ARTIFACT_DISK="${PROD_ARTIFACT_DISK:-hns-topology-data}"
PROD_ARTIFACT_DISK_SIZE_GB="${PROD_ARTIFACT_DISK_SIZE_GB:-200}"
PROD_ARTIFACT_DISK_TYPE="${PROD_ARTIFACT_DISK_TYPE:-pd-standard}"

disk_users() {
  gcloud compute disks describe "$PROD_ARTIFACT_DISK" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --format='value(users)' 2>/dev/null || true
}

instance_disk_names() {
  gcloud compute instances describe "$DENUO_WEB_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --format='value(disks[].deviceName)' 2>/dev/null || true
}

if ! gcloud compute disks describe "$PROD_ARTIFACT_DISK" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" >/dev/null 2>&1; then
  gcloud compute disks create "$PROD_ARTIFACT_DISK" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --size "${PROD_ARTIFACT_DISK_SIZE_GB}GB" \
    --type "$PROD_ARTIFACT_DISK_TYPE"
fi

attached_to="$(disk_users)"
if [[ -n "$attached_to" && "$attached_to" != *"/instances/$DENUO_WEB_VM" ]]; then
  echo "$PROD_ARTIFACT_DISK is already attached to $attached_to; refusing to attach to $DENUO_WEB_VM" >&2
  exit 2
fi

if ! instance_disk_names | tr ';' '\n' | grep -qx "$PROD_ARTIFACT_DISK"; then
  gcloud compute instances attach-disk "$DENUO_WEB_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --disk "$PROD_ARTIFACT_DISK" \
    --device-name "$PROD_ARTIFACT_DISK"
fi

gcloud compute disks describe "$PROD_ARTIFACT_DISK" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --format='table(name,sizeGb,type.basename(),users.basename(),status)'

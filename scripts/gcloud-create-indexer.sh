#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_DISK="${INDEXER_DISK:-hns-topology-indexer-disk}"
INDEXER_DISK_SIZE_GB="${INDEXER_DISK_SIZE_GB:-150}"
INDEXER_DISK_TYPE="${INDEXER_DISK_TYPE:-pd-balanced}"
INDEXER_MACHINE_TYPE="${INDEXER_MACHINE_TYPE:-e2-standard-2}"
INDEXER_IMAGE_FAMILY="${INDEXER_IMAGE_FAMILY:-debian-12}"
INDEXER_IMAGE_PROJECT="${INDEXER_IMAGE_PROJECT:-debian-cloud}"

disk_users() {
  gcloud compute disks describe "$INDEXER_DISK" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --format='value(users)' 2>/dev/null || true
}

instance_disk_names() {
  gcloud compute instances describe "$INDEXER_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --format='value(disks[].deviceName)' 2>/dev/null || true
}

if ! gcloud compute disks describe "$INDEXER_DISK" --project "$GCP_PROJECT" --zone "$GCP_ZONE" >/dev/null 2>&1; then
  gcloud compute disks create "$INDEXER_DISK" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --size "${INDEXER_DISK_SIZE_GB}GB" \
    --type "$INDEXER_DISK_TYPE"
fi

if ! gcloud compute instances describe "$INDEXER_VM" --project "$GCP_PROJECT" --zone "$GCP_ZONE" >/dev/null 2>&1; then
  gcloud compute instances create "$INDEXER_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --machine-type "$INDEXER_MACHINE_TYPE" \
    --image-family "$INDEXER_IMAGE_FAMILY" \
    --image-project "$INDEXER_IMAGE_PROJECT" \
    --boot-disk-size 30GB \
    --disk "name=$INDEXER_DISK,device-name=$INDEXER_DISK,mode=rw,boot=no,auto-delete=no"
else
  attached_to="$(disk_users)"
  if [[ -n "$attached_to" && "$attached_to" != *"/instances/$INDEXER_VM" ]]; then
    echo "$INDEXER_DISK is already attached to $attached_to; refusing to attach to $INDEXER_VM" >&2
    exit 2
  fi

  disk_names="$(instance_disk_names | tr ';' '\n')"
  if [[ -n "$attached_to" && "$attached_to" == *"/instances/$INDEXER_VM" ]] && ! grep -qx "$INDEXER_DISK" <<<"$disk_names"; then
    echo "$INDEXER_DISK is attached to $INDEXER_VM with an unexpected device name; detach and reattach with device-name $INDEXER_DISK" >&2
    exit 2
  fi

  if ! grep -qx "$INDEXER_DISK" <<<"$disk_names"; then
    gcloud compute instances attach-disk "$INDEXER_VM" \
      --project "$GCP_PROJECT" \
      --zone "$GCP_ZONE" \
      --disk "$INDEXER_DISK" \
      --device-name "$INDEXER_DISK"
  fi

  status="$(gcloud compute instances describe "$INDEXER_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --format='value(status)')"
  if [ "$status" != "RUNNING" ]; then
    gcloud compute instances start "$INDEXER_VM" --project "$GCP_PROJECT" --zone "$GCP_ZONE"
  fi
fi

gcloud compute instances describe "$INDEXER_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --format='table(name,status,machineType.basename(),disks[].deviceName)'

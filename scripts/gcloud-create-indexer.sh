#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_DISK="${INDEXER_DISK:-hns-topology-indexer-disk}"
INDEXER_DISK_SIZE_GB="${INDEXER_DISK_SIZE_GB:-200}"
INDEXER_DISK_TYPE="${INDEXER_DISK_TYPE:-pd-balanced}"
INDEXER_MACHINE_TYPE="${INDEXER_MACHINE_TYPE:-e2-standard-2}"
INDEXER_IMAGE_FAMILY="${INDEXER_IMAGE_FAMILY:-debian-12}"
INDEXER_IMAGE_PROJECT="${INDEXER_IMAGE_PROJECT:-debian-cloud}"

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
    --disk "name=$INDEXER_DISK,mode=rw,boot=no,auto-delete=no"
else
  gcloud compute instances start "$INDEXER_VM" --project "$GCP_PROJECT" --zone "$GCP_ZONE"
fi

#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_DISK="${INDEXER_DISK:-hns-topology-indexer-disk}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
INDEXER_REPO_DIR="${INDEXER_REPO_DIR:-/mnt/hnscrawler/HNScrawler}"
INDEXER_HSD_PREFIX="${INDEXER_HSD_PREFIX:-/mnt/hnscrawler/hsd}"
INDEXER_USER="${INDEXER_USER:-den}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/gcloud-ssh-lib.sh"

gcloud_compute_ssh "$INDEXER_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "set -euo pipefail
DEVICE=/dev/disk/by-id/google-$INDEXER_DISK
for i in 1 2 3 4 5; do [ -e \"\$DEVICE\" ] && break || sleep 1; done
[ -e \"\$DEVICE\" ] || { echo \"\$DEVICE does not exist; check the attached disk device-name\" >&2; exit 2; }
DEVICE_TYPE=\$(sudo file -sL \"\$DEVICE\")
echo \"\$DEVICE_TYPE\"
if [[ \"\$DEVICE_TYPE\" == *': data' || \"\$DEVICE_TYPE\" == *': empty' ]]; then
  sudo mkfs.ext4 -F -m 0 \"\$DEVICE\"
fi
if [ -d '$INDEXER_MOUNT' ] && ! mountpoint -q '$INDEXER_MOUNT' && [ -n \"\$(find '$INDEXER_MOUNT' -mindepth 1 -maxdepth 1 -print -quit)\" ]; then
  echo '$INDEXER_MOUNT exists on the boot disk and is not empty; refusing to mount over it' >&2
  exit 2
fi
sudo mkdir -p '$INDEXER_MOUNT'
if ! grep -q \"google-$INDEXER_DISK\" /etc/fstab; then
  echo \"\$DEVICE $INDEXER_MOUNT ext4 defaults,nofail,discard 0 2\" | sudo tee -a /etc/fstab >/dev/null
fi
sudo mount -a
mountpoint -q '$INDEXER_MOUNT' || { echo '$INDEXER_MOUNT is not mounted after mount -a' >&2; exit 2; }
sudo mkdir -p '$INDEXER_REPO_DIR' '$INDEXER_HSD_PREFIX' '$INDEXER_MOUNT/data' '$INDEXER_MOUNT/public' '$INDEXER_MOUNT/logs' '$INDEXER_MOUNT/secrets'
sudo chown -R '$INDEXER_USER:$INDEXER_USER' '$INDEXER_MOUNT'
chmod 700 '$INDEXER_MOUNT/secrets'
df -h / '$INDEXER_MOUNT'
ls -ld '$INDEXER_MOUNT' '$INDEXER_REPO_DIR' '$INDEXER_HSD_PREFIX'"

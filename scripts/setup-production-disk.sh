#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
DENUO_WEB_VM="${DENUO_WEB_VM:-denuoweb-vm}"
PROD_ARTIFACT_DISK="${PROD_ARTIFACT_DISK:-hns-topology-data}"
PROD_ARTIFACT_MOUNT="${PROD_ARTIFACT_MOUNT:-/mnt/hns-topology}"
PROD_ARTIFACT_SITE_DIR="${PROD_ARTIFACT_SITE_DIR:-/mnt/hns-topology/site}"
DENUO_WEB_PATH="${DENUO_WEB_PATH:-/var/www/denuoweb/hns-topology}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/gcloud-ssh-lib.sh"

gcloud_compute_ssh "$DENUO_WEB_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "set -euo pipefail
DEVICE=/dev/disk/by-id/google-$PROD_ARTIFACT_DISK
for i in 1 2 3 4 5; do [ -e \"\$DEVICE\" ] && break || sleep 1; done
[ -e \"\$DEVICE\" ] || { echo \"\$DEVICE does not exist; check the attached disk device-name\" >&2; exit 2; }
DEVICE_TYPE=\$(sudo file -sL \"\$DEVICE\")
echo \"\$DEVICE_TYPE\"
if [[ \"\$DEVICE_TYPE\" == *': data' || \"\$DEVICE_TYPE\" == *': empty' ]]; then
  sudo mkfs.ext4 -F -m 0 \"\$DEVICE\"
fi
if [ -d '$PROD_ARTIFACT_MOUNT' ] && ! mountpoint -q '$PROD_ARTIFACT_MOUNT' && [ -n \"\$(find '$PROD_ARTIFACT_MOUNT' -mindepth 1 -maxdepth 1 -print -quit)\" ]; then
  echo '$PROD_ARTIFACT_MOUNT exists on the boot disk and is not empty; refusing to mount over it' >&2
  exit 2
fi
sudo mkdir -p '$PROD_ARTIFACT_MOUNT'
if ! grep -q \"google-$PROD_ARTIFACT_DISK\" /etc/fstab; then
  echo \"\$DEVICE $PROD_ARTIFACT_MOUNT ext4 defaults,nofail,discard 0 2\" | sudo tee -a /etc/fstab >/dev/null
fi
sudo mount -a
mountpoint -q '$PROD_ARTIFACT_MOUNT' || { echo '$PROD_ARTIFACT_MOUNT is not mounted after mount -a' >&2; exit 2; }
sudo mkdir -p '$PROD_ARTIFACT_SITE_DIR'
sudo chown -R den:www-data '$PROD_ARTIFACT_MOUNT'
sudo chmod 775 '$PROD_ARTIFACT_MOUNT' '$PROD_ARTIFACT_SITE_DIR'
if [ -e '$DENUO_WEB_PATH' ] && [ ! -L '$DENUO_WEB_PATH' ]; then
  sudo mv '$DENUO_WEB_PATH' '${DENUO_WEB_PATH}.bootdisk-backup.'\$(date +%Y%m%d%H%M%S)
fi
sudo ln -sfn '$PROD_ARTIFACT_SITE_DIR' '$DENUO_WEB_PATH'
ls -ld '$PROD_ARTIFACT_MOUNT' '$PROD_ARTIFACT_SITE_DIR' '$DENUO_WEB_PATH'
df -h / '$PROD_ARTIFACT_MOUNT'"

#!/usr/bin/env bash
set -euo pipefail

PUBLIC_DIR="${PUBLIC_DIR:-public}"
DENUO_WEB_PATH="${DENUO_WEB_PATH:-/var/www/denuoweb/hns-topology}"
PUBLISH_VIA_GCLOUD="${PUBLISH_VIA_GCLOUD:-1}"
PROD_ARTIFACT_MOUNT="${PROD_ARTIFACT_MOUNT:-/mnt/hns-topology}"
ALLOW_BOOT_DISK_PUBLISH="${ALLOW_BOOT_DISK_PUBLISH:-0}"
VALIDATE_BEFORE_PUBLISH="${VALIDATE_BEFORE_PUBLISH:-1}"

test -f "$PUBLIC_DIR/index.html"

if [ "$VALIDATE_BEFORE_PUBLISH" = "1" ]; then
  if [ -x .venv/bin/hns-topology ]; then
    .venv/bin/hns-topology validate-public --public-dir "$PUBLIC_DIR"
  else
    hns-topology validate-public --public-dir "$PUBLIC_DIR"
  fi
fi

if [[ "$PUBLISH_VIA_GCLOUD" == "1" ]]; then
  GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
  GCP_ZONE="${GCP_ZONE:-us-west1-b}"
  DENUO_WEB_VM="${DENUO_WEB_VM:-denuoweb-vm}"
  REMOTE_TMP="${REMOTE_TMP:-$PROD_ARTIFACT_MOUNT/.incoming/hns-topology-public}"

  gcloud compute ssh "$DENUO_WEB_VM" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --quiet \
    --command "set -euo pipefail
mountpoint -q '$PROD_ARTIFACT_MOUNT' || { echo '$PROD_ARTIFACT_MOUNT is not mounted; refusing to stage on boot disk' >&2; exit 2; }
case '$REMOTE_TMP/' in
  '$PROD_ARTIFACT_MOUNT'/*) ;;
  *)
    if [ '$ALLOW_BOOT_DISK_PUBLISH' != '1' ]; then
      echo 'refusing to stage at $REMOTE_TMP; expected a path under $PROD_ARTIFACT_MOUNT' >&2
      exit 2
    fi
    ;;
esac
REMOTE_USER=\$(id -un)
sudo rm -rf '$REMOTE_TMP'
sudo mkdir -p '$REMOTE_TMP'
sudo chown \"\$REMOTE_USER:\$REMOTE_USER\" '$REMOTE_TMP'"

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
    --command "set -euo pipefail
mountpoint -q '$PROD_ARTIFACT_MOUNT' || { echo '$PROD_ARTIFACT_MOUNT is not mounted; refusing to publish to boot disk' >&2; exit 2; }
if [ -L '$DENUO_WEB_PATH' ]; then
  PUBLISH_TARGET=\$(readlink -f '$DENUO_WEB_PATH')
else
  PUBLISH_TARGET='$DENUO_WEB_PATH'
fi
case \"\$PUBLISH_TARGET/\" in
  '$PROD_ARTIFACT_MOUNT'/*) ;;
  *)
    if [ '$ALLOW_BOOT_DISK_PUBLISH' != '1' ]; then
      echo \"refusing to publish to \$PUBLISH_TARGET; expected a path under $PROD_ARTIFACT_MOUNT\" >&2
      exit 2
    fi
    ;;
esac
sudo mkdir -p \"\$PUBLISH_TARGET\"
sudo rsync -a --delete '$REMOTE_TMP/' \"\$PUBLISH_TARGET/\"
sudo chown -R www-data:www-data \"\$PUBLISH_TARGET\"
rm -rf '$REMOTE_TMP'"
else
  DENUO_WEB_HOST="${DENUO_WEB_HOST:?set DENUO_WEB_HOST}"
  rsync -az --delete "$PUBLIC_DIR"/ "$DENUO_WEB_HOST":"$DENUO_WEB_PATH"/
fi

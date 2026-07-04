#!/usr/bin/env bash
set -euo pipefail

PUBLIC_DIR="${PUBLIC_DIR:-public}"
DENUO_WEB_PATH="${DENUO_WEB_PATH:-/var/www/denuoweb/hns-topology}"
PUBLISH_VIA_GCLOUD="${PUBLISH_VIA_GCLOUD:-1}"
PROD_ARTIFACT_MOUNT="${PROD_ARTIFACT_MOUNT:-/mnt/hns-topology}"
ALLOW_BOOT_DISK_PUBLISH="${ALLOW_BOOT_DISK_PUBLISH:-0}"
VALIDATE_BEFORE_PUBLISH="${VALIDATE_BEFORE_PUBLISH:-1}"
MIN_INDEXED_HEIGHT="${MIN_INDEXED_HEIGHT:-0}"
PUBLISH_ARCHIVE="${PUBLISH_ARCHIVE:-}"

log() {
  printf '[publish] %s\n' "$*" >&2
}

if [[ -z "$PUBLISH_ARCHIVE" ]]; then
  test -f "$PUBLIC_DIR/index.html"
fi

if [ "$VALIDATE_BEFORE_PUBLISH" = "1" ]; then
  test -f "$PUBLIC_DIR/index.html"
  log "validating public site at $PUBLIC_DIR"
  validate_args=(validate-public --public-dir "$PUBLIC_DIR")
  if [ "$MIN_INDEXED_HEIGHT" != "0" ]; then
    validate_args+=(--min-indexed-height "$MIN_INDEXED_HEIGHT")
  fi
  if [ -x .venv/bin/hns-topology ]; then
    .venv/bin/hns-topology "${validate_args[@]}"
  else
    hns-topology "${validate_args[@]}"
  fi
fi

if [[ "$PUBLISH_VIA_GCLOUD" == "1" ]]; then
  GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
  GCP_ZONE="${GCP_ZONE:-us-west1-b}"
  DENUO_WEB_VM="${DENUO_WEB_VM:-denuoweb-vm}"
  REMOTE_TMP="${REMOTE_TMP:-$PROD_ARTIFACT_MOUNT/.incoming/hns-topology-public}"
  REMOTE_ARCHIVE="${REMOTE_ARCHIVE:-$PROD_ARTIFACT_MOUNT/.incoming/hns-topology-public.tar.gz}"
  REMOTE_ARCHIVE_DIR="${REMOTE_ARCHIVE%/*}"

  if [[ -n "$PUBLISH_ARCHIVE" ]]; then
    test -f "$PUBLISH_ARCHIVE"
    ARCHIVE_PATH="$PUBLISH_ARCHIVE"
    CLEAN_ARCHIVE=0
    log "using existing public archive $ARCHIVE_PATH"
  else
    ARCHIVE_PATH="$(mktemp "${TMPDIR:-/tmp}/hns-topology-public.XXXXXX.tar.gz")"
    CLEAN_ARCHIVE=1
    log "creating compressed public archive $ARCHIVE_PATH"
    tar -C "$PUBLIC_DIR" -czf "$ARCHIVE_PATH" .
  fi
  cleanup_archive() {
    if [[ "${CLEAN_ARCHIVE:-0}" == "1" ]]; then
      rm -f "$ARCHIVE_PATH"
    fi
  }
  trap cleanup_archive EXIT

  log "preparing remote staging directory $REMOTE_TMP"
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
case '$REMOTE_ARCHIVE/' in
  '$PROD_ARTIFACT_MOUNT'/*) ;;
  *)
    if [ '$ALLOW_BOOT_DISK_PUBLISH' != '1' ]; then
      echo 'refusing to stage archive at $REMOTE_ARCHIVE; expected a path under $PROD_ARTIFACT_MOUNT' >&2
      exit 2
    fi
    ;;
esac
REMOTE_USER=\$(id -un)
sudo rm -rf '$REMOTE_TMP' '$REMOTE_ARCHIVE'
sudo mkdir -p '$REMOTE_TMP' '$REMOTE_ARCHIVE_DIR'
sudo chown \"\$REMOTE_USER:\$REMOTE_USER\" '$REMOTE_TMP' '$REMOTE_ARCHIVE_DIR'"

  log "uploading compressed archive to $DENUO_WEB_VM:$REMOTE_ARCHIVE"
  gcloud compute scp \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --quiet \
    "$ARCHIVE_PATH" \
    "$DENUO_WEB_VM:$REMOTE_ARCHIVE"

  log "extracting archive and syncing live site"
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
tar -C '$REMOTE_TMP' -xzf '$REMOTE_ARCHIVE'
sudo mkdir -p \"\$PUBLISH_TARGET\"
sudo rsync -a --delete --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r '$REMOTE_TMP/' \"\$PUBLISH_TARGET/\"
sudo chown -R www-data:www-data \"\$PUBLISH_TARGET\"
rm -rf '$REMOTE_TMP' '$REMOTE_ARCHIVE'
echo '[publish] remote sync complete'"
else
  DENUO_WEB_HOST="${DENUO_WEB_HOST:?set DENUO_WEB_HOST}"
  log "syncing site to $DENUO_WEB_HOST:$DENUO_WEB_PATH"
  rsync -az --delete --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r "$PUBLIC_DIR"/ "$DENUO_WEB_HOST":"$DENUO_WEB_PATH"/
fi

log "publish complete"

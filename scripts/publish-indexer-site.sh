#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_REPO_DIR="${INDEXER_REPO_DIR:-/mnt/hnscrawler/HNScrawler}"
INDEXER_PUBLIC_DIR="${INDEXER_PUBLIC_DIR:-/mnt/hnscrawler/public}"
INDEXER_DB="${INDEXER_DB:-/mnt/hnscrawler/data/topology.sqlite}"
MIN_INDEXED_HEIGHT="${MIN_INDEXED_HEIGHT:-${HSD_MIN_BLOCK_HEIGHT:-300000}}"
DENUO_WEB_VM="${DENUO_WEB_VM:-denuoweb-vm}"
DENUO_WEB_PATH="${DENUO_WEB_PATH:-/var/www/denuoweb/hns-topology}"
DENUO_WEB_TARGET_TAGS="${DENUO_WEB_TARGET_TAGS:-denuoweb}"
PROD_ARTIFACT_MOUNT="${PROD_ARTIFACT_MOUNT:-/mnt/hns-topology}"
PROD_LOOKUP_DB="${PROD_LOOKUP_DB:-$PROD_ARTIFACT_MOUNT/topology.sqlite}"
PUBLISH_LOOKUP_DB="${PUBLISH_LOOKUP_DB:-1}"
ALLOW_BOOT_DISK_PUBLISH="${ALLOW_BOOT_DISK_PUBLISH:-0}"
PUBLISH_FIREWALL_PRIORITY="${PUBLISH_FIREWALL_PRIORITY:-850}"
PUBLISH_FIREWALL_RULE="${PUBLISH_FIREWALL_RULE:-hns-topology-publish-ssh-$(date +%s)-$$}"
PUBLISH_SSH_ATTEMPTS="${PUBLISH_SSH_ATTEMPTS:-18}"
PUBLISH_SSH_WAIT_SECONDS="${PUBLISH_SSH_WAIT_SECONDS:-5}"
PUBLISH_DB_RSYNC_INFO="${PUBLISH_DB_RSYNC_INFO:-progress2}"
INDEXER_PUBLISH_KEY="${INDEXER_PUBLISH_KEY:-/home/den/.ssh/hns_topology_publish_tmp}"
INDEXER_PUBLISH_KNOWN_HOSTS="${INDEXER_PUBLISH_KNOWN_HOSTS:-/home/den/.ssh/hns_topology_publish_known_hosts}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/gcloud-ssh-lib.sh"

log() {
  printf '[publish-indexer] %s\n' "$*" >&2
}

gce_ssh() {
  local vm="$1"
  local command="$2"
  gcloud_compute_ssh "$vm" \
    --project "$GCP_PROJECT" \
    --zone "$GCP_ZONE" \
    --quiet \
    --command "$command"
}

metadata_file="$(mktemp)"
new_metadata_file="$(mktemp)"
metadata_changed=0
firewall_created=0

cleanup() {
  local status=$?
  set +e
  gce_ssh "$INDEXER_VM" "rm -f '$INDEXER_PUBLISH_KEY' '$INDEXER_PUBLISH_KEY.pub' '$INDEXER_PUBLISH_KNOWN_HOSTS'" >/dev/null 2>&1
  if [[ "$metadata_changed" == "1" ]]; then
    if [[ -s "$metadata_file" ]]; then
      gcloud compute instances add-metadata "$DENUO_WEB_VM" \
        --project "$GCP_PROJECT" \
        --zone "$GCP_ZONE" \
        --metadata-from-file ssh-keys="$metadata_file" \
        --quiet >/dev/null 2>&1
    else
      gcloud compute instances remove-metadata "$DENUO_WEB_VM" \
        --project "$GCP_PROJECT" \
        --zone "$GCP_ZONE" \
        --keys ssh-keys \
        --quiet >/dev/null 2>&1
    fi
  fi
  if [[ "$firewall_created" == "1" ]]; then
    gcloud compute firewall-rules delete "$PUBLISH_FIREWALL_RULE" \
      --project "$GCP_PROJECT" \
      --quiet >/dev/null 2>&1
  fi
  rm -f "$metadata_file" "$new_metadata_file"
  exit "$status"
}
trap cleanup EXIT INT TERM

log "validating public site on $INDEXER_VM"
gce_ssh "$INDEXER_VM" "set -euo pipefail
cd '$INDEXER_REPO_DIR'
. .venv/bin/activate
validate_args=(validate-public --public-dir '$INDEXER_PUBLIC_DIR')
if [ '$MIN_INDEXED_HEIGHT' != '0' ]; then
  validate_args+=(--min-indexed-height '$MIN_INDEXED_HEIGHT')
fi
hns-topology \"\${validate_args[@]}\""

indexer_private_ip="${INDEXER_PRIVATE_IP:-$(gcloud compute instances describe "$INDEXER_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --format='value(networkInterfaces[0].networkIP)')}"
web_private_ip="${DENUO_WEB_PRIVATE_IP:-$(gcloud compute instances describe "$DENUO_WEB_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --format='value(networkInterfaces[0].networkIP)')}"

if [[ -z "$indexer_private_ip" || -z "$web_private_ip" ]]; then
  echo "could not resolve private IPs for $INDEXER_VM and $DENUO_WEB_VM" >&2
  exit 2
fi

log "resolving publish target on $DENUO_WEB_VM"
publish_target="$(gce_ssh "$DENUO_WEB_VM" "set -euo pipefail
mountpoint -q '$PROD_ARTIFACT_MOUNT' || { echo '$PROD_ARTIFACT_MOUNT is not mounted; refusing to publish to boot disk' >&2; exit 2; }
if [ -L '$DENUO_WEB_PATH' ]; then
  target=\$(readlink -f '$DENUO_WEB_PATH')
else
  target='$DENUO_WEB_PATH'
fi
case \"\$target/\" in
  '$PROD_ARTIFACT_MOUNT'/*) ;;
  *)
    if [ '$ALLOW_BOOT_DISK_PUBLISH' != '1' ]; then
      echo \"refusing to publish to \$target; expected a path under $PROD_ARTIFACT_MOUNT\" >&2
      exit 2
    fi
    ;;
esac
sudo mkdir -p \"\$target\"
printf '%s\n' \"\$target\"" | tail -n1)"

if [[ -z "$publish_target" ]]; then
  echo "could not resolve publish target on $DENUO_WEB_VM" >&2
  exit 2
fi

if [[ "$PUBLISH_LOOKUP_DB" == "1" ]]; then
  case "$PROD_LOOKUP_DB" in
    "$PROD_ARTIFACT_MOUNT"/*) ;;
    *)
      echo "refusing lookup DB outside $PROD_ARTIFACT_MOUNT: $PROD_LOOKUP_DB" >&2
      exit 2
      ;;
  esac
fi

log "generating temporary SSH key on $INDEXER_VM"
publish_key_dir="$(dirname "$INDEXER_PUBLISH_KEY")"
publish_public_key="$(gce_ssh "$INDEXER_VM" "set -euo pipefail
mkdir -p '$publish_key_dir'
chmod 700 '$publish_key_dir'
rm -f '$INDEXER_PUBLISH_KEY' '$INDEXER_PUBLISH_KEY.pub' '$INDEXER_PUBLISH_KNOWN_HOSTS'
ssh-keygen -q -t ed25519 -N '' -C 'hns-topology-publish-temp' -f '$INDEXER_PUBLISH_KEY'
chmod 600 '$INDEXER_PUBLISH_KEY'
cat '$INDEXER_PUBLISH_KEY.pub'" | tail -n1)"

if [[ -z "$publish_public_key" ]]; then
  echo "failed to create temporary publish key on $INDEXER_VM" >&2
  exit 2
fi

gcloud compute instances describe "$DENUO_WEB_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --format='get(metadata.items.ssh-keys)' | sed '/^[[:space:]]*$/d' > "$metadata_file"

if [[ -s "$metadata_file" ]]; then
  cat "$metadata_file" > "$new_metadata_file"
  printf '\n' >> "$new_metadata_file"
fi
printf 'den:%s\n' "$publish_public_key" >> "$new_metadata_file"

log "adding temporary SSH metadata to $DENUO_WEB_VM"
gcloud compute instances add-metadata "$DENUO_WEB_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --metadata-from-file ssh-keys="$new_metadata_file" \
  --quiet >/dev/null
metadata_changed=1

log "opening temporary VPC SSH from $INDEXER_VM ($indexer_private_ip) to $DENUO_WEB_VM"
gcloud compute firewall-rules create "$PUBLISH_FIREWALL_RULE" \
  --project "$GCP_PROJECT" \
  --network default \
  --direction INGRESS \
  --priority "$PUBLISH_FIREWALL_PRIORITY" \
  --action ALLOW \
  --rules tcp:22 \
  --source-ranges "$indexer_private_ip/32" \
  --target-tags "$DENUO_WEB_TARGET_TAGS" \
  --quiet >/dev/null
firewall_created=1

log "waiting for direct SSH to $DENUO_WEB_VM ($web_private_ip)"
gce_ssh "$INDEXER_VM" "set -euo pipefail
for attempt in \$(seq 1 '$PUBLISH_SSH_ATTEMPTS'); do
  if ssh -i '$INDEXER_PUBLISH_KEY' \
      -o BatchMode=yes \
      -o ConnectTimeout=5 \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile='$INDEXER_PUBLISH_KNOWN_HOSTS' \
      den@$web_private_ip true; then
    echo direct_ssh_ready
    exit 0
  fi
  sleep '$PUBLISH_SSH_WAIT_SECONDS'
done
echo 'direct SSH did not become ready' >&2
exit 2"

log "rsyncing $INDEXER_PUBLIC_DIR directly to $DENUO_WEB_VM:$publish_target"
gce_ssh "$INDEXER_VM" "set -euo pipefail
rsync -a \
  --delete-delay \
  --delay-updates \
  --whole-file \
  --stats \
  --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r \
  --chown=www-data:www-data \
  --rsync-path='sudo rsync' \
  -e \"ssh -i '$INDEXER_PUBLISH_KEY' -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile='$INDEXER_PUBLISH_KNOWN_HOSTS'\" \
  '$INDEXER_PUBLIC_DIR/' \
  den@$web_private_ip:'$publish_target'/"

if [[ "$PUBLISH_LOOKUP_DB" == "1" ]]; then
  lookup_tmp="$PROD_LOOKUP_DB.new"
  log "rsyncing lookup database $INDEXER_DB to $DENUO_WEB_VM:$PROD_LOOKUP_DB"
  gce_ssh "$INDEXER_VM" "set -euo pipefail
  test -f '$INDEXER_DB'
  rsync -a \
    --whole-file \
    --info='$PUBLISH_DB_RSYNC_INFO' \
    --chmod=Fu=rw,Fgo=r \
    --chown=www-data:www-data \
    --rsync-path='sudo rsync' \
    -e \"ssh -i '$INDEXER_PUBLISH_KEY' -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile='$INDEXER_PUBLISH_KNOWN_HOSTS'\" \
    '$INDEXER_DB' \
    den@$web_private_ip:'$lookup_tmp'"

  log "restarting lookup service on $DENUO_WEB_VM"
  gce_ssh "$DENUO_WEB_VM" "set -euo pipefail
  case '$PROD_LOOKUP_DB' in
    '$PROD_ARTIFACT_MOUNT'/*) ;;
    *) echo 'refusing lookup DB outside $PROD_ARTIFACT_MOUNT: $PROD_LOOKUP_DB' >&2; exit 2 ;;
  esac
  sudo systemctl stop hns-topology-lookup
  sudo mv '$lookup_tmp' '$PROD_LOOKUP_DB'
  sudo chown www-data:www-data '$PROD_LOOKUP_DB'
  sudo chmod 640 '$PROD_LOOKUP_DB'
  sudo rm -f '$PROD_LOOKUP_DB-shm' '$PROD_LOOKUP_DB-wal'
  sudo systemctl start hns-topology-lookup"
fi

log "finalizing ownership on $DENUO_WEB_VM"
gce_ssh "$DENUO_WEB_VM" "set -euo pipefail
sudo chown www-data:www-data '$publish_target'
sudo chmod 755 '$publish_target'
echo '[publish] remote sync complete'"

log "publish complete"

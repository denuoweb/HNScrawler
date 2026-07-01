#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
INDEXER_HSD_PREFIX="${INDEXER_HSD_PREFIX:-/mnt/hnscrawler/hsd}"
INDEXER_USER="${INDEXER_USER:-den}"

gcloud compute ssh "$INDEXER_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "set -euo pipefail
mountpoint -q '$INDEXER_MOUNT' || { echo '$INDEXER_MOUNT is not mounted; run scripts/setup-indexer-disk.sh first' >&2; exit 2; }
sudo apt-get update
sudo apt-get install -y curl git jq nodejs npm rsync python3 python3-venv python3-pip
if ! command -v hsd >/dev/null 2>&1; then
  sudo npm install -g hsd hs-client
fi
HSD_BIN=\$(command -v hsd)
mkdir -p '$INDEXER_MOUNT/secrets' '$INDEXER_HSD_PREFIX'
chmod 700 '$INDEXER_MOUNT/secrets'
if [ ! -f '$INDEXER_MOUNT/secrets/hsd.env' ]; then
  API_KEY=\$(openssl rand -hex 32)
  printf 'HSD_API_KEY=%s\nHSD_RPC_URL=http://127.0.0.1:12037\n' \"\$API_KEY\" > '$INDEXER_MOUNT/secrets/hsd.env'
  chmod 600 '$INDEXER_MOUNT/secrets/hsd.env'
fi
sudo tee /etc/systemd/system/hsd.service >/dev/null <<EOF
[Unit]
Description=Handshake hsd full node for Denuo HNS topology indexing
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$INDEXER_USER
Group=$INDEXER_USER
WorkingDirectory=$INDEXER_MOUNT
EnvironmentFile=$INDEXER_MOUNT/secrets/hsd.env
ExecStart=\$HSD_BIN --prefix $INDEXER_HSD_PREFIX --network main --api-key \\\$HSD_API_KEY --http-host 127.0.0.1 --no-wallet
Restart=always
RestartSec=15
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable hsd
systemctl status hsd --no-pager || true
echo 'HSD env written to $INDEXER_MOUNT/secrets/hsd.env'"

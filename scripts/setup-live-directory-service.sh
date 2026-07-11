#!/usr/bin/env bash
set -euo pipefail

LIVE_ROOT="${LIVE_ROOT:-/mnt/hns-topology/live-directory}"
LIVE_REPO_DIR="${LIVE_REPO_DIR:-$LIVE_ROOT/HNScrawler}"
LIVE_DB="${LIVE_DB:-$LIVE_ROOT/data/live.sqlite}"
LIVE_PUBLIC_DIR="${LIVE_PUBLIC_DIR:-$LIVE_ROOT/public}"
LIVE_WEB_PATH="${LIVE_WEB_PATH:-/var/www/denuoweb/hns-live}"
TOPOLOGY_DB="${TOPOLOGY_DB:-/mnt/hns-topology/topology.sqlite}"
LIVE_SERVICE_USER="${LIVE_SERVICE_USER:-den}"
LIVE_SERVICE_GROUP="${LIVE_SERVICE_GROUP:-www-data}"
LIVE_LIMIT="${LIVE_LIMIT:-100}"
LIVE_CONCURRENCY="${LIVE_CONCURRENCY:-4}"
LIVE_MIN_DELAY_MS="${LIVE_MIN_DELAY_MS:-250}"
LIVE_TIMEOUT="${LIVE_TIMEOUT:-5}"
LIVE_FALLBACK_RESOLVER="${LIVE_FALLBACK_RESOLVER:-}"
START_LIVE_TIMER="${START_LIVE_TIMER:-1}"
RUN_LIVE_DIRECTORY_NOW="${RUN_LIVE_DIRECTORY_NOW:-0}"

mountpoint -q /mnt/hns-topology || {
  echo "/mnt/hns-topology is not mounted; refusing to install live data on the boot disk" >&2
  exit 2
}
test -f "$LIVE_REPO_DIR/pyproject.toml" || {
  echo "repository is not present at $LIVE_REPO_DIR" >&2
  exit 2
}

sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip util-linux
sudo mkdir -p "$LIVE_ROOT/data" "$LIVE_ROOT/run" "$LIVE_PUBLIC_DIR"
sudo chown -R "$LIVE_SERVICE_USER:$LIVE_SERVICE_GROUP" "$LIVE_ROOT"
sudo chmod 775 "$LIVE_ROOT" "$LIVE_ROOT/data" "$LIVE_ROOT/run" "$LIVE_PUBLIC_DIR"

cd "$LIVE_REPO_DIR"
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e .

sudo tee /etc/default/hns-live-directory >/dev/null <<EOF
LIVE_ROOT=$LIVE_ROOT
LIVE_REPO_DIR=$LIVE_REPO_DIR
TOPOLOGY_DB=$TOPOLOGY_DB
LIVE_DB=$LIVE_DB
LIVE_PUBLIC_DIR=$LIVE_PUBLIC_DIR
LIVE_LIMIT=$LIVE_LIMIT
LIVE_CONCURRENCY=$LIVE_CONCURRENCY
LIVE_MIN_DELAY_MS=$LIVE_MIN_DELAY_MS
LIVE_TIMEOUT=$LIVE_TIMEOUT
LIVE_FALLBACK_RESOLVER=$LIVE_FALLBACK_RESOLVER
EOF

sudo tee /etc/systemd/system/hns-live-directory.service >/dev/null <<EOF
[Unit]
Description=Denuo HNS live website directory probe cycle
After=network-online.target
Wants=network-online.target
ConditionPathExists=$TOPOLOGY_DB

[Service]
Type=oneshot
User=$LIVE_SERVICE_USER
Group=$LIVE_SERVICE_GROUP
WorkingDirectory=$LIVE_REPO_DIR
EnvironmentFile=/etc/default/hns-live-directory
ExecStart=$LIVE_REPO_DIR/scripts/run-live-directory.sh
Nice=10
IOSchedulingClass=idle
CPUQuota=50%
MemoryMax=768M
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$LIVE_ROOT
TimeoutStartSec=6h
EOF

sudo tee /etc/systemd/system/hns-live-directory.timer >/dev/null <<EOF
[Unit]
Description=Run the HNS live website directory daily

[Timer]
OnActiveSec=1h
OnUnitActiveSec=1d
RandomizedDelaySec=30m
AccuracySec=1m
Unit=hns-live-directory.service

[Install]
WantedBy=timers.target
EOF

live_command=(sudo -u "$LIVE_SERVICE_USER" -g "$LIVE_SERVICE_GROUP" .venv/bin/hns-live-directory)
"${live_command[@]}" init --db "$LIVE_DB"
if sudo -u "$LIVE_SERVICE_USER" -g "$LIVE_SERVICE_GROUP" test -r "$TOPOLOGY_DB"; then
  "${live_command[@]}" sync --topology-db "$TOPOLOGY_DB" --db "$LIVE_DB"
fi
"${live_command[@]}" export --db "$LIVE_DB" --out "$LIVE_PUBLIC_DIR"
"${live_command[@]}" validate --public-dir "$LIVE_PUBLIC_DIR"

sudo mkdir -p "$(dirname "$LIVE_WEB_PATH")"
if [[ -e "$LIVE_WEB_PATH" && ! -L "$LIVE_WEB_PATH" ]]; then
  echo "$LIVE_WEB_PATH exists and is not a symlink" >&2
  exit 2
fi
sudo ln -sfn "$LIVE_PUBLIC_DIR" "$LIVE_WEB_PATH"
sudo chown -h "$LIVE_SERVICE_USER:$LIVE_SERVICE_GROUP" "$LIVE_WEB_PATH"

sudo systemctl daemon-reload
sudo systemctl enable hns-live-directory.timer
if [[ "$START_LIVE_TIMER" == "1" ]]; then
  sudo systemctl restart hns-live-directory.timer
fi
if [[ "$RUN_LIVE_DIRECTORY_NOW" == "1" ]]; then
  sudo systemctl start hns-live-directory.service
fi

systemctl status hns-live-directory.timer --no-pager || true
ls -ld "$LIVE_ROOT" "$LIVE_PUBLIC_DIR" "$LIVE_WEB_PATH"

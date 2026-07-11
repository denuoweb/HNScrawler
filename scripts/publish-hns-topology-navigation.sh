#!/usr/bin/env bash
set -euo pipefail

LIVE_REPO_DIR="${LIVE_REPO_DIR:-/mnt/hns-topology/live-directory/HNScrawler}"
TOPOLOGY_SITE_DIR="${TOPOLOGY_SITE_DIR:-/mnt/hns-topology/site}"
TOPOLOGY_WEB_OWNER="${TOPOLOGY_WEB_OWNER:-www-data}"
TOPOLOGY_WEB_GROUP="${TOPOLOGY_WEB_GROUP:-www-data}"

mountpoint -q /mnt/hns-topology || {
  echo "/mnt/hns-topology is not mounted; refusing to publish the directory navigation" >&2
  exit 2
}
test -x "$LIVE_REPO_DIR/.venv/bin/python" || {
  echo "live-directory virtualenv is not installed at $LIVE_REPO_DIR/.venv" >&2
  exit 2
}
test -d "$TOPOLOGY_SITE_DIR" || {
  echo "topology site directory is missing at $TOPOLOGY_SITE_DIR" >&2
  exit 2
}
test -f "$LIVE_REPO_DIR/src/hns_topology/site_assets/app.js" || {
  echo "topology application asset is missing from $LIVE_REPO_DIR" >&2
  exit 2
}

temporary_index="$(sudo mktemp "$TOPOLOGY_SITE_DIR/.index.html.live-nav.XXXXXX")"
temporary_names="$(sudo mktemp "$TOPOLOGY_SITE_DIR/.names.html.live-nav.XXXXXX")"
temporary_app="$(sudo mktemp "$TOPOLOGY_SITE_DIR/.app.js.live-nav.XXXXXX")"
cleanup() {
  sudo rm -f "$temporary_index"
  sudo rm -f "$temporary_names"
  sudo rm -f "$temporary_app"
}
trap cleanup EXIT

sudo "$LIVE_REPO_DIR/.venv/bin/python" - "$temporary_index" "$temporary_names" <<'PY'
from pathlib import Path
import sys

from hns_topology.site_generator import _html

Path(sys.argv[1]).write_text(
    _html(page="overview", title="HNS Domain Directory"),
    encoding="utf-8",
)
Path(sys.argv[2]).write_text(
    _html(page="names", title="HNS Root Diagnostics"),
    encoding="utf-8",
)
PY
sudo chown "$TOPOLOGY_WEB_OWNER:$TOPOLOGY_WEB_GROUP" "$temporary_index"
sudo chmod 0644 "$temporary_index"
sudo chown "$TOPOLOGY_WEB_OWNER:$TOPOLOGY_WEB_GROUP" "$temporary_names"
sudo chmod 0644 "$temporary_names"
sudo install -o "$TOPOLOGY_WEB_OWNER" -g "$TOPOLOGY_WEB_GROUP" -m 0644 \
  "$LIVE_REPO_DIR/src/hns_topology/site_assets/app.js" "$temporary_app"
sudo mv -f "$temporary_index" "$TOPOLOGY_SITE_DIR/index.html"
sudo mv -f "$temporary_names" "$TOPOLOGY_SITE_DIR/names.html"
sudo mv -f "$temporary_app" "$TOPOLOGY_SITE_DIR/app.js"

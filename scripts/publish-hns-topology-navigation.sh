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

temporary_index="$(sudo mktemp "$TOPOLOGY_SITE_DIR/.index.html.live-nav.XXXXXX")"
cleanup() {
  sudo rm -f "$temporary_index"
}
trap cleanup EXIT

sudo "$LIVE_REPO_DIR/.venv/bin/python" - "$temporary_index" <<'PY'
from pathlib import Path
import sys

from hns_topology.site_generator import _html

Path(sys.argv[1]).write_text(
    _html(page="overview", title="HNS Domain Directory"),
    encoding="utf-8",
)
PY
sudo chown "$TOPOLOGY_WEB_OWNER:$TOPOLOGY_WEB_GROUP" "$temporary_index"
sudo chmod 0644 "$temporary_index"
sudo mv -f "$temporary_index" "$TOPOLOGY_SITE_DIR/index.html"

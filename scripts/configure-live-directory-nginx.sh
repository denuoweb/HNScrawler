#!/usr/bin/env bash
set -euo pipefail

LIVE_REPO_DIR="${LIVE_REPO_DIR:-/mnt/hns-topology/live-directory/HNScrawler}"
NGINX_SITE_PATH="${NGINX_SITE_PATH:-/etc/nginx/sites-enabled/denuoweb}"
NGINX_SNIPPET_PATH="${NGINX_SNIPPET_PATH:-/etc/nginx/snippets/hns-live-directory.conf}"
NGINX_SERVER_NAME="${NGINX_SERVER_NAME:-hns.denuoweb.com}"

test -f "$LIVE_REPO_DIR/deploy/nginx/hns-live-directory.conf" || {
  echo "live-directory nginx snippet is missing from $LIVE_REPO_DIR" >&2
  exit 2
}
test -f "$NGINX_SITE_PATH" || {
  echo "nginx site configuration is missing at $NGINX_SITE_PATH" >&2
  exit 2
}

sudo install -D -m 0644 \
  "$LIVE_REPO_DIR/deploy/nginx/hns-live-directory.conf" \
  "$NGINX_SNIPPET_PATH"

backup="$(mktemp)"
sudo cp "$NGINX_SITE_PATH" "$backup"
cleanup() {
  rm -f "$backup"
}
trap cleanup EXIT

if ! sudo python3 - "$NGINX_SITE_PATH" "$NGINX_SNIPPET_PATH" "$NGINX_SERVER_NAME" <<'PY'
from pathlib import Path
import sys

site_path = Path(sys.argv[1])
snippet_path = sys.argv[2]
server_name = sys.argv[3]
text = site_path.read_text(encoding="utf-8")
server_marker = f"    server_name {server_name};"
start = text.find(server_marker)
if start < 0:
    raise SystemExit(f"nginx server block for {server_name} was not found")
end = text.find("\nserver {", start + len(server_marker))
if end < 0:
    end = len(text)
block = text[start:end]
include_line = f"    include {snippet_path};\n\n"
if include_line not in block:
    anchor = "    location = /hns-topology/data/topology.sqlite.gz {"
    offset = block.find(anchor)
    if offset < 0:
        raise SystemExit("expected HNS topology location was not found in the nginx server block")
    absolute_offset = start + offset
    text = text[:absolute_offset] + include_line + text[absolute_offset:]
    site_path.write_text(text, encoding="utf-8")
PY
then
  sudo cp "$backup" "$NGINX_SITE_PATH"
  exit 1
fi

if ! sudo nginx -t; then
  sudo cp "$backup" "$NGINX_SITE_PATH"
  exit 1
fi
sudo systemctl reload nginx

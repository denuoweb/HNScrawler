#!/usr/bin/env bash
set -euo pipefail

PUBLIC_DIR="${PUBLIC_DIR:-public}"
DENUO_WEB_HOST="${DENUO_WEB_HOST:?set DENUO_WEB_HOST}"
DENUO_WEB_PATH="${DENUO_WEB_PATH:?set DENUO_WEB_PATH}"

rsync -az --delete "$PUBLIC_DIR"/ "$DENUO_WEB_HOST":"$DENUO_WEB_PATH"/


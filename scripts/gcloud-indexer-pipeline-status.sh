#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"
INDEXER_MOUNT="${INDEXER_MOUNT:-/mnt/hnscrawler}"
INDEXER_PIPELINE_UNIT="${INDEXER_PIPELINE_UNIT:-hns-topology-indexer-pipeline}"
INDEXER_PIPELINE_LOG="${INDEXER_PIPELINE_LOG:-$INDEXER_MOUNT/logs/$INDEXER_PIPELINE_UNIT.log}"
INDEXER_PIPELINE_TAIL_LINES="${INDEXER_PIPELINE_TAIL_LINES:-120}"
INDEXER_STATUS_SCAN_STAGING="${INDEXER_STATUS_SCAN_STAGING:-0}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/gcloud-ssh-lib.sh"

remote_quote() {
  printf "%q" "$1"
}

gcloud_compute_ssh "$INDEXER_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "set -uo pipefail
unit=$(remote_quote "$INDEXER_PIPELINE_UNIT.service")
log=$(remote_quote "$INDEXER_PIPELINE_LOG")
echo \"remote date: \$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
echo
echo \"unit:\"
sudo systemctl --no-pager status \"\$unit\" || true
echo
echo \"unit properties:\"
sudo systemctl show \"\$unit\" \
  --property=ActiveState \
  --property=SubState \
  --property=Result \
  --property=ExecMainStatus \
  --property=ExecMainStartTimestamp \
  --property=ExecMainExitTimestamp \
  --property=CPUUsageNSec || true
echo
echo \"pipeline processes:\"
ps -eo pid,ppid,etime,pcpu,pmem,stat,cmd | grep -E 'PID|[h]ns-topology generate-site|[g]enerate-site.sh|[v]erify-release|[p]ublish-indexer|[r]sync|[r]un-incremental|[r]un-indexer-pipeline-local' || true
echo
echo \"staging dirs:\"
find $(remote_quote "$INDEXER_MOUNT") -maxdepth 1 -type d -name '.public.tmp-*' -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort || true
tmp=\$(find $(remote_quote "$INDEXER_MOUNT") -maxdepth 1 -type d -name '.public.tmp-*' -print -quit 2>/dev/null || true)
if [ -n \"\$tmp\" ]; then
  echo
  echo \"active staging: \$tmp\"
  stat -c 'mtime=%y' \"\$tmp\" 2>/dev/null || true
  echo \"top-level entries:\"
  find \"\$tmp\" -mindepth 1 -maxdepth 2 -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort | tail -n 30 || true
  if [ $(remote_quote "$INDEXER_STATUS_SCAN_STAGING") = '1' ]; then
    echo
    echo \"deep staging scan requested; this can be slow on multi-million-file exports\"
    du -sh \"\$tmp\" 2>/dev/null || true
    echo \"file count:\"
    find \"\$tmp\" -type f 2>/dev/null | wc -l
  fi
fi
echo
echo \"public dir:\"
stat -c '%y %n' $(remote_quote "$INDEXER_MOUNT/public") 2>/dev/null || true
echo
echo \"log tail: \$log\"
if [ -f \"\$log\" ]; then
  echo \"recent progress:\"
  tail -n 500 \"\$log\" | grep -E '\\[pipeline\\]|\\[export\\].*(progress=|writing|wrote|finished|start)' | tail -n $(remote_quote "$INDEXER_PIPELINE_TAIL_LINES") || true
  echo
  echo \"raw tail:\"
  tail -n $(remote_quote "$INDEXER_PIPELINE_TAIL_LINES") \"\$log\"
else
  echo \"no log file yet\"
fi"

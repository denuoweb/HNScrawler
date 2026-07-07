#!/usr/bin/env bash

gcloud_bool_is_true() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

gcloud_ssh_uses_iap() {
  local vm="$1"
  local use_iap="${GCLOUD_SSH_TUNNEL_THROUGH_IAP:-0}"

  if [ -n "${INDEXER_VM:-}" ] && [ "$vm" = "$INDEXER_VM" ]; then
    use_iap="${INDEXER_SSH_TUNNEL_THROUGH_IAP:-$use_iap}"
  fi
  if [ -n "${DENUO_WEB_VM:-}" ] && [ "$vm" = "$DENUO_WEB_VM" ]; then
    use_iap="${DENUO_WEB_SSH_TUNNEL_THROUGH_IAP:-$use_iap}"
  fi

  gcloud_bool_is_true "$use_iap"
}

gcloud_compute_ssh() {
  local vm="$1"
  shift

  if gcloud_ssh_uses_iap "$vm"; then
    gcloud compute ssh "$vm" --tunnel-through-iap "$@"
  else
    gcloud compute ssh "$vm" "$@"
  fi
}

gcloud_scp_uses_iap() {
  local use_iap="${GCLOUD_SCP_TUNNEL_THROUGH_IAP:-${GCLOUD_SSH_TUNNEL_THROUGH_IAP:-0}}"
  local arg

  for arg in "$@"; do
    if [ -n "${INDEXER_VM:-}" ]; then
      case "$arg" in
        "$INDEXER_VM:"*|*"$INDEXER_VM:"*) use_iap="${INDEXER_SSH_TUNNEL_THROUGH_IAP:-$use_iap}" ;;
      esac
    fi
    if [ -n "${DENUO_WEB_VM:-}" ]; then
      case "$arg" in
        "$DENUO_WEB_VM:"*|*"$DENUO_WEB_VM:"*) use_iap="${DENUO_WEB_SSH_TUNNEL_THROUGH_IAP:-$use_iap}" ;;
      esac
    fi
  done

  gcloud_bool_is_true "$use_iap"
}

gcloud_compute_scp() {
  if gcloud_scp_uses_iap "$@"; then
    gcloud compute scp --tunnel-through-iap "$@"
  else
    gcloud compute scp "$@"
  fi
}

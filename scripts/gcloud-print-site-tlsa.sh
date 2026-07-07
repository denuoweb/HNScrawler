#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-denuo-web-site}"
GCP_ZONE="${GCP_ZONE:-us-west1-b}"
DENUO_WEB_VM="${DENUO_WEB_VM:-denuoweb-vm}"
DANE_SITE_NAME="${DANE_SITE_NAME:-denuoweb}"
DANE_CERT_PATH="${DANE_CERT_PATH:-/etc/ssl/denuoweb/denuoweb.crt}"
DANE_TLSA_TTL="${DANE_TLSA_TTL:-300}"
DANE_INCLUDE_WWW="${DANE_INCLUDE_WWW:-1}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/gcloud-ssh-lib.sh"

SITE_FQDN="${DANE_SITE_NAME%.}."

gcloud_compute_ssh "$DENUO_WEB_VM" \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --quiet \
  --command "set -euo pipefail
test -r '$DANE_CERT_PATH' || sudo test -r '$DANE_CERT_PATH'
ASSOCIATION=\$(sudo openssl x509 -in '$DANE_CERT_PATH' -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | od -An -tx1 -v \
  | tr -d ' \n')
echo '; TLSA 3 1 1 from $DANE_CERT_PATH on '\$(hostname)' at '\$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo '_443._tcp.$SITE_FQDN $DANE_TLSA_TTL IN TLSA 3 1 1 '\$ASSOCIATION
if [ '$DANE_INCLUDE_WWW' = '1' ]; then
  echo '_443._tcp.www.$SITE_FQDN $DANE_TLSA_TTL IN TLSA 3 1 1 '\$ASSOCIATION
fi"

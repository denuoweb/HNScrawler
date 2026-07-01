#!/usr/bin/env bash
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:?set GCP_PROJECT}"
GCP_ZONE="${GCP_ZONE:?set GCP_ZONE}"
INDEXER_VM="${INDEXER_VM:-hns-topology-indexer}"

gcloud compute instances delete "$INDEXER_VM" --project "$GCP_PROJECT" --zone "$GCP_ZONE" --quiet


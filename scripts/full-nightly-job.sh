#!/usr/bin/env bash
set -euo pipefail

scripts/run-incremental.sh
scripts/run-live-checks.sh
scripts/generate-site.sh
scripts/publish-site.sh


# Deployment

The cheapest sustainable deployment is an ephemeral indexer VM plus the existing small website VM.

## Environment

Copy `scripts/env.example` to `.env` on the operator machine or export the variables directly.

See `docs/CLOUD_AUDIT.md` for the current local `gcloud` context observed when the repository was bootstrapped.

Required for HSD indexing:

- `HSD_RPC_URL`
- `HSD_API_KEY`

Required for GCP provisioning:

- `GCP_PROJECT`
- `GCP_ZONE`
- `INDEXER_VM`
- `INDEXER_DISK`

Required for publishing:

- `DENUO_WEB_HOST`
- `DENUO_WEB_PATH`

## Bootstrap

```bash
scripts/gcloud-create-indexer.sh
gcloud compute ssh "$INDEXER_VM" --zone "$GCP_ZONE" --project "$GCP_PROJECT"
scripts/setup-indexer.sh
scripts/run-bootstrap.sh
scripts/run-live-checks.sh
scripts/generate-site.sh
scripts/publish-site.sh
scripts/gcloud-stop-indexer.sh
```

Keep the persistent indexer disk until production recovery has been proven. Stop or delete the compute VM to avoid ongoing compute cost.

## Nightly Or Weekly Update

```bash
scripts/gcloud-create-indexer.sh
scripts/run-incremental.sh
scripts/run-live-checks.sh
scripts/generate-site.sh
scripts/publish-site.sh
scripts/gcloud-stop-indexer.sh
```

## Storage Rules

- HSD datadir lives on the large indexer disk.
- Compact SQLite and generated artifacts live on the indexer disk while building.
- Website VM receives only `public/`.
- Optional buckets store compressed exports, generated artifact tarballs, and database backups.
- Do not place the live HSD datadir on the website VM.

## Public Repository

The intended public repository is `denuoweb/HNScrawler`. Local changes should be committed in small groups and pushed to `main`.

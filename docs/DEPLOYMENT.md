# Deployment

The cheapest sustainable deployment is an ephemeral indexer VM plus the existing small website VM.

## Environment

Copy `scripts/env.example` to `.env` on the operator machine or export the variables directly.

See `docs/CLOUD_AUDIT.md` for the current local `gcloud` context and the existing website VM inventory.

Required for HSD indexing:

- `HSD_RPC_URL`
- `HSD_API_KEY`

Required for GCP provisioning:

- `GCP_PROJECT` should be `denuo-web-site`
- `GCP_ZONE`
- `INDEXER_VM`
- `INDEXER_DISK`

Required for publishing:

- `DENUO_WEB_VM` should be `denuoweb-vm` for GCE publishing
- `DENUO_WEB_PATH` defaults to `/var/www/denuoweb/hns-topology`
- `PROD_ARTIFACT_DISK` defaults to `hns-topology-data`
- `PROD_ARTIFACT_MOUNT` defaults to `/mnt/hns-topology`

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

## Production Website Disk

The existing web VM has a 30 GB boot disk with about 9.7 GB free. Keep generated report bytes off that boot disk.

The production artifact disk workflow is:

```bash
scripts/gcloud-attach-production-disk.sh
scripts/setup-production-disk.sh
```

Current production shape:

- VM: `denuoweb-vm`
- project: `denuo-web-site`
- zone: `us-west1-b`
- artifact disk: `hns-topology-data`
- artifact mount: `/mnt/hns-topology`
- generated site target: `/mnt/hns-topology/site`
- web path: `/var/www/denuoweb/hns-topology` symlinked to `/mnt/hns-topology/site`

Keep full HSD data off the production web VM unless there is a deliberate later decision to colocate a pruned node. The intended production VM payload is the generated static report and downloadable artifacts.

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

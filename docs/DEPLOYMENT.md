# Deployment

The cheapest sustainable deployment is an ephemeral indexer VM plus the existing small website VM.

## Environment

Copy `scripts/env.example` to `.env` on the operator machine or export the variables directly.

See `docs/CLOUD_AUDIT.md` for the current local `gcloud` context and the existing website VM inventory.

Required for HSD indexing:

- `HSD_RPC_URL`
- `HSD_API_KEY`
- `HSD_MAX_BLOCK_LAG` defaults to `2`
- `HSD_MIN_BLOCK_HEIGHT` defaults to `300000` for production mainnet readiness checks
- `CHECK_HSD_READY` defaults to `1`

Required for GCP provisioning:

- `GCP_PROJECT` should be `denuo-web-site`
- `GCP_ZONE`
- `INDEXER_VM`
- `INDEXER_DISK`
- `INDEXER_MOUNT` defaults to `/mnt/hnscrawler`
- `INDEXER_HSD_PREFIX` defaults to `/mnt/hnscrawler/hsd`

Required for publishing:

- `DENUO_WEB_VM` should be `denuoweb-vm` for GCE publishing
- `DENUO_WEB_PATH` defaults to `/var/www/denuoweb/hns-topology`
- `PROD_ARTIFACT_DISK` defaults to `hns-topology-data`
- `PROD_ARTIFACT_MOUNT` defaults to `/mnt/hns-topology`
- `DENUO_WEB_TARGET_TAGS` defaults to `denuoweb` for the temporary direct-publish firewall rule

Optional for release archives:

- `RUN_ARCHIVE` defaults to `1`
- `MIN_INDEXED_HEIGHT` defaults to `HSD_MIN_BLOCK_HEIGHT` inside the GCE pipeline
- `ARCHIVE_DIR` defaults to `/mnt/hnscrawler/archives`
- `ARCHIVE_KEEP` defaults to `10`
- `BACKUP_BUCKET_URI` may be set to a `gs://...` bucket prefix for compressed release artifacts

## Bootstrap

```bash
scripts/gcloud-create-indexer.sh
scripts/gcloud-wait-indexer-ssh.sh
scripts/setup-indexer-disk.sh
scripts/gcloud-sync-indexer-code.sh
gcloud compute ssh "$INDEXER_VM" --zone "$GCP_ZONE" --project "$GCP_PROJECT" --command "cd /mnt/hnscrawler/HNScrawler && scripts/setup-indexer.sh"
scripts/setup-hsd-service.sh
gcloud compute ssh "$INDEXER_VM" --zone "$GCP_ZONE" --project "$GCP_PROJECT" --command "sudo systemctl start hsd"
scripts/indexer-status.sh
scripts/check-hsd-ready.sh
BOOTSTRAP_LIMIT=100 scripts/run-bootstrap.sh
scripts/generate-site.sh
scripts/verify-release.sh
scripts/archive-release.sh
scripts/publish-indexer-site.sh
scripts/gcloud-stop-indexer.sh
```

Keep the persistent indexer disk until production recovery has been proven. Stop or delete the compute VM to avoid ongoing compute cost.

The indexer disk is for HSD, the compact working database, and generated artifacts while building. The production artifact disk on `denuoweb-vm` is for serving the finished static site and downloads. Do not use the production artifact disk as the HSD datadir.

`scripts/gcloud-create-indexer.sh` is idempotent for interrupted cycles: it creates the persistent disk if missing, creates the VM if missing, reattaches the indexer disk if the VM exists without it, refuses to attach a disk already mounted on a different VM, and only starts the VM when it is not already running.

For the first production cycle, prefer the guarded wrapper:

```bash
scripts/gcloud-production-preflight.sh
DRY_RUN=1 scripts/gcloud-production-cycle.sh
CONFIRM_PRODUCTION_RUN=1 PIPELINE_MODE=bootstrap BOOTSTRAP_LIMIT=100 RUN_PUBLISH=0 WAIT_FOR_HSD_READY=1 scripts/gcloud-production-cycle.sh
```

`scripts/gcloud-production-cycle.sh` runs preflight, provisions or starts the indexer VM, mounts the indexer disk, syncs code, installs dependencies, starts HSD, optionally waits for HSD readiness, runs the pipeline, publishes the generated site, and then applies `INDEXER_FINAL_ACTION`. The default final and failure action is `stop`, not delete. Set `INDEXER_FINAL_ACTION=delete-vm` only when you intentionally want to remove the ephemeral compute VM after the run. The persistent indexer disk is not deleted by this wrapper.

Operational note: production generation is long-running and must be owned by the indexer VM, not by an interactive SSH session or a local Codex/terminal process. `scripts/gcloud-run-indexer-pipeline.sh` defaults to `INDEXER_PIPELINE_RUNNER=systemd`: it writes an env file to `/mnt/hnscrawler/run`, starts `hns-topology-indexer-pipeline.service` on the VM with `systemd-run`, and writes VM-side logs to `/mnt/hnscrawler/logs/hns-topology-indexer-pipeline.log`. The local command may wait and print status, but if the local machine disconnects the VM unit continues. Use `scripts/gcloud-indexer-pipeline-status.sh` for a one-shot status report.

For a fully VM-owned generate/verify/publish run, the indexer VM service account scope must include `https://www.googleapis.com/auth/cloud-platform`. Then run the remote systemd pipeline with `RUN_PUBLISH_FROM_INDEXER=1` and skip the local publish wrapper. `scripts/publish-indexer-site.sh` supports this with `PUBLISH_LOCAL_INDEXER=1`, which runs indexer-side validation, key generation, and rsync locally on the indexer while still using `gcloud` from the VM for temporary web-VM metadata and firewall changes.

The weekly scheduler is `hns-topology-production.timer`, which triggers `hns-topology-production.service`; the service runs `/home/den/HNScrawler/scripts/run-production-cycle-logged.sh weekly` and writes wrapper progress to `logs/production-cycle/latest.log`. The scheduled wrapper defaults to `RUN_PUBLISH_FROM_INDEXER=1`, `INDEXER_PIPELINE_RUNNER=systemd`, and `INDEXER_PIPELINE_WAIT=1`: the VM-owned unit handles generate, verify, and publish; the local wrapper waits for that unit to finish and then applies `INDEXER_FINAL_ACTION=stop`. Do not rely on a foreground terminal or Codex tool session to remain attached through generation, publish, and cleanup.

To resume HSD sync without running or publishing a report, use:

```bash
DRY_RUN=1 scripts/gcloud-sync-hsd-until-ready.sh
CONFIRM_HSD_SYNC=1 scripts/gcloud-sync-hsd-until-ready.sh
```

That wrapper starts or creates the indexer, mounts the indexer disk, syncs code, starts HSD, waits for `scripts/check-hsd-ready.sh`, and then stops the compute VM by default. It never runs the report pipeline or publish step. Increase `HSD_READY_ATTEMPTS` when intentionally allowing a longer sync window.

For a fixed cost-bounded catch-up window, use:

```bash
DRY_RUN=1 scripts/gcloud-sync-hsd-window.sh
CONFIRM_HSD_SYNC_WINDOW=1 HSD_SYNC_WINDOW_MINUTES=30 scripts/gcloud-sync-hsd-window.sh
```

That wrapper starts or creates the indexer, resumes HSD, prints indexer status before and after the window, and stops the compute VM by default. It does not wait for readiness, run the report pipeline, or publish.

Use `BOOTSTRAP_LIMIT` for the first HSD RPC smoke run. Full HSD RPC bootstrap uses HSD `getnames`, which is unpaginated; it is blocked unless `ALLOW_UNPAGINATED_GETNAMES=1` is set. For the first full mainnet bootstrap from the indexer disk, use `PIPELINE_MODE=extract-jsonl EXPORT_FORMAT=compact`. That mode runs `scripts/export-hsd-jsonl.sh`, which checks HSD readiness, stops the `hsd` systemd service by default, streams compact current name state from HSD's name tree to JSONL, restarts `hsd`, and then runs `hns-topology bootstrap-jsonl --batch-size "$JSONL_BOOTSTRAP_BATCH_SIZE"`.

## Production Website Disk

The existing web VM has a 30 GB boot disk with about 9.7 GB free. Keep generated report bytes off that boot disk.

The production artifact disk workflow is:

```bash
DRY_RUN=1 scripts/gcloud-prepare-production-web.sh
CONFIRM_PRODUCTION_WEB=1 scripts/gcloud-prepare-production-web.sh
```

Current production shape:

- VM: `denuoweb-vm`
- project: `denuo-web-site`
- zone: `us-west1-b`
- artifact disk: `hns-topology-data`
- artifact mount: `/mnt/hns-topology`
- generated site target: `/mnt/hns-topology/site`
- web path: `/var/www/denuoweb/hns-topology` symlinked to `/mnt/hns-topology/site`

`scripts/gcloud-prepare-production-web.sh` creates or attaches `PROD_ARTIFACT_DISK`, mounts it, moves an existing non-symlink `DENUO_WEB_PATH` aside with a timestamped boot-disk backup name, creates the symlink to `PROD_ARTIFACT_SITE_DIR`, and then runs the production preflight. It refuses to run unless `CONFIRM_PRODUCTION_WEB=1`, or `DRY_RUN=1` for plan output.

Keep full HSD data off the production web VM unless there is a deliberate later decision to colocate a pruned node. The intended production VM payload is the generated static report and optional downloadable artifacts.

`scripts/publish-indexer-site.sh` is the preferred production publish path. It validates `/mnt/hnscrawler/public` on `hns-topology-indexer`, creates a temporary SSH key on that VM, adds that key only to `denuoweb-vm`, opens a temporary firewall rule from the indexer private IP to TCP 22 on the `denuoweb` target tag, and runs `rsync` directly from the indexer to the resolved production artifact target over the VPC. The script removes the temporary key metadata and firewall rule on exit. This avoids relaying multi-gigabyte static exports through the local workstation and avoids keeping a second full staging tree on the web disk.

`scripts/publish-site.sh` remains available for publishing a local `public/` directory. It refuses to publish through GCE unless `PROD_ARTIFACT_MOUNT` is mounted and the resolved `DENUO_WEB_PATH` is under that mount. It stages incoming files under `REMOTE_TMP` on the artifact disk, not under `/tmp`, so large reports do not temporarily consume the production boot disk. `ALLOW_BOOT_DISK_PUBLISH=1` exists only as an emergency override and should not be used for normal Denuo deployment.

`scripts/publish-site.sh` also runs `hns-topology validate-public --public-dir <public>` by default before upload. That validation checks required public files, export counts, and `public/data/manifest.json` checksums for the generated static data. Set `VALIDATE_BEFORE_PUBLISH=0` only for deliberate debugging.

## HSD Service

`scripts/setup-hsd-service.sh` installs HSD as a systemd service on the indexer VM with:

- `--prefix /mnt/hnscrawler/hsd`
- `--network main`
- `--http-host 127.0.0.1`
- `--no-wallet`
- a generated 32-byte API key in `/mnt/hnscrawler/secrets/hsd.env`

HSD mainnet RPC listens on `127.0.0.1:12037` by default. Bootstrap and incremental scripts source `/mnt/hnscrawler/secrets/hsd.env` when present.

The production HSD service targets `HSD_MAX_OUTBOUND=16` outbound peers and `HSD_LOG_LEVEL=warning` by default. Extra outbound peers improve peer diversity and failover but HSD still uses a single loader peer for historical sync. Warning-level logging avoids per-block debug/info journal writes during bootstrap. The service also raises conservative ChainDB/blockstore cache settings with `HSD_CACHE_SIZE_MB=512`, `HSD_BLOCK_CACHE_SIZE_MB=128`, `HSD_MAX_FILES=256`, and `HSD_ENTRY_CACHE=50000`; these are runtime cache knobs, not consensus changes.

`scripts/check-hsd-ready.sh` runs `hns-topology hsd-status` before HSD-backed bootstrap and incremental indexing. It requires a local RPC URL, reported chain and tip hash, a non-negative block height, `blocks >= HSD_MIN_BLOCK_HEIGHT`, `verificationprogress >= HSD_MIN_VERIFICATION_PROGRESS`, median block time no older than `HSD_MAX_MEDIAN_TIME_AGE_SECONDS`, `initialblockdownload = false` when HSD reports that field, and `headers - blocks <= HSD_MAX_BLOCK_LAG` when headers are reported. Use `CHECK_HSD_READY=0` only for deliberate debugging. Use `HSD_ALLOW_REMOTE_RPC=1` only when intentionally checking a remote RPC endpoint.

## Nightly Or Weekly Update

```bash
scripts/gcloud-create-indexer.sh
scripts/setup-indexer-disk.sh
scripts/gcloud-sync-indexer-code.sh
PIPELINE_MODE=incremental scripts/gcloud-run-indexer-pipeline.sh
scripts/gcloud-indexer-pipeline-status.sh
scripts/publish-indexer-site.sh
scripts/gcloud-stop-indexer.sh
```

Incremental mode reads `last_indexed_height` from the compact DB, scans detailed HSD blocks through the current tip, records empty blocks for reorg safety, and indexes changed names. It refuses to scan more than `INCREMENTAL_MAX_BLOCKS` blocks, default `300`, so a stale database fails closed instead of doing an unexpectedly large block walk. Increase `INCREMENTAL_MAX_BLOCKS` deliberately for a known catch-up window, or run a fresh `PIPELINE_MODE=extract-jsonl` bootstrap when the gap is large.

## Independent Live Website Directory

Website probing is not part of the nightly/weekly update above. `denuoweb-vm` reads the topology snapshot already published at `/mnt/hns-topology/topology.sqlite` and maintains a separate `/mnt/hns-topology/live-directory` database and public tree.

```bash
DRY_RUN=1 scripts/gcloud-deploy-live-directory.sh
CONFIRM_LIVE_DIRECTORY_DEPLOY=1 scripts/gcloud-deploy-live-directory.sh
```

This installs `hns-live-directory.service` and `hns-live-directory.timer` without modifying `hns-topology-production.timer`, the indexer VM pipeline, or either topology publish script. Full behavior and paths are in `docs/LIVE_DIRECTORY.md`.

The obsolete embedded-TLSA columns are absent from newly built databases. Physical removal from an existing production database is a separate maintenance operation because SQLite may rewrite the large resource table; no weekly script runs it automatically:

```bash
hns-topology cleanup-legacy-schema --db /mnt/hnscrawler/data/topology.sqlite --confirm-large-rewrite
```

Run that command only in a planned maintenance window with a current database snapshot and enough free disk for SQLite's rewrite behavior.

For a limited HSD RPC smoke report, use `PIPELINE_MODE=bootstrap BOOTSTRAP_LIMIT=100 scripts/gcloud-run-indexer-pipeline.sh` after HSD is synced. For the initial full report, use `PIPELINE_MODE=extract-jsonl EXPORT_FORMAT=compact JSONL_PATH=/mnt/hnscrawler/data/extracted_names.jsonl scripts/gcloud-run-indexer-pipeline.sh`. If a JSONL file has already been produced, use `PIPELINE_MODE=jsonl JSONL_PATH=/mnt/hnscrawler/data/extracted_names.jsonl scripts/gcloud-run-indexer-pipeline.sh`. If you intentionally accept the risk of HSD's unpaginated `getnames` for a full RPC bootstrap, set `ALLOW_UNPAGINATED_GETNAMES=1 PIPELINE_MODE=bootstrap`.

`scripts/gcloud-run-indexer-pipeline.sh` runs `scripts/verify-release.sh` after static site generation. It defaults to a remote systemd runner so site generation and verification are not killed if the local SSH/IAP tunnel or caller exits. Set `INDEXER_PIPELINE_WAIT=0` only for an intentionally detached run where the VM must be left running; `scripts/gcloud-production-cycle.sh` refuses to combine detached pipeline mode with `INDEXER_FINAL_ACTION=stop` because that would kill the VM-owned work immediately after launch. Set `RUN_PUBLISH_FROM_INDEXER=1` to publish from inside the same VM-owned unit after verification. Set `INDEXER_PIPELINE_RUNNER=ssh` only for emergency debugging of the old foreground behavior. The GCE pipeline defaults `MIN_INDEXED_HEIGHT` to `HSD_MIN_BLOCK_HEIGHT`, so a structurally valid but shallow snapshot cannot pass production release validation or publish validation.

When `RUN_ARCHIVE=1`, the pipeline runs `scripts/archive-release.sh` after validation and before publishing. It writes a generated-site tarball, a consistent `topology.sqlite.gz` database backup, and a JSON manifest with SHA-256 hashes under `ARCHIVE_DIR`, pruning to `ARCHIVE_KEEP` manifests. Use `hns-topology validate-archive --manifest <manifest>` to verify artifact hashes, tarball contents, and SQLite backup integrity before moving archive artifacts to backup storage. Set `BACKUP_BUCKET_URI=gs://bucket/prefix` to copy those compressed release artifacts to bucket storage. Do not point archive tooling at the live HSD datadir.

Single-block `SCAN_BLOCK_HEIGHT` mode requests detailed HSD block JSON and resolves covenant name hashes with `getnamebyhash`. It refuses empty scans and unresolved name hashes by default. Set `ALLOW_EMPTY_BLOCK_SCAN=1` only for a known-empty block, and set `ALLOW_UNRESOLVED_NAME_HASHES=1` only for a deliberate best-effort run.

`scripts/full-nightly-job.sh` is the local wrapper for the same sequence on an already-prepared indexer host: start HSD for the update phase, HSD readiness, reorg check, bounded incremental catch-up, stop HSD, site generation, release validation, archive creation, and optional publishing. It uses `START_HSD_FOR_UPDATES=1` and `STOP_HSD_AFTER_UPDATES=1` by default so HSD is not left running outside update work. The GCE wrapper remains preferred because it also handles VM lifecycle and attached-disk setup.

## Storage Rules

- HSD datadir lives on the large indexer disk.
- Compact SQLite and generated artifacts live on the indexer disk while building.
- Website VM receives only `public/`.
- Full mainnet bootstrap should stream JSONL from the indexer HSD state with `scripts/export-hsd-jsonl.sh`, not through unpaginated `getnames`.
- Optional buckets store compressed exports, generated artifact tarballs, and database backups.
- Do not place the HSD datadir on the website VM.

## Public Repository

The intended public repository is `denuoweb/HNScrawler`. Local changes should be committed in small groups and pushed to `main`.

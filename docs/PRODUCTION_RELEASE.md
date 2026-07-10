# Production Release Checklist

## Local Release Gate

- `pytest`
- `ruff check .`
- fixture bootstrap
- fixture site generation
- `hns-topology validate-release --db data/topology.sqlite --public-dir public`
- inspect `public/data/summary.json` and generated `public/index.html` when definitions or UI behavior changed

## Indexer VM Gate

- Confirm `gcloud config get-value project` matches `GCP_PROJECT`.
- `scripts/gcloud-production-preflight.sh` passes.
- Confirm the large disk is attached and mounted.
- Confirm HSD datadir is on the large disk.
- Confirm HSD is fully synced.
- `scripts/check-hsd-ready.sh` passes.
- `scripts/verify-release.sh` passes with `MIN_INDEXED_HEIGHT` set for production mainnet.
- Confirm HSD RPC credentials are local-only or firewall-restricted.
- Run HSD RPC bootstrap with `BOOTSTRAP_LIMIT` first.
- Run the full bootstrap with `PIPELINE_MODE=extract-jsonl EXPORT_FORMAT=compact` so HSD state streams to compact JSONL before `bootstrap-jsonl`.
- Set `ALLOW_UNPAGINATED_GETNAMES=1` only after explicitly accepting HSD `getnames` scale risk and measuring disk/RAM usage.

## Data Gate

- Snapshot metadata has height, tip hash, generated time, HSD chain, HSD version, crawler version, source hash, and provider rules hash.
- `hns-topology reorg-check --db <db>` passes before incremental updates.
- Incremental catch-up range is within `INCREMENTAL_MAX_BLOCKS`, or a fresh `PIPELINE_MODE=extract-jsonl` bootstrap is used.
- Incremental block scans do not use `ALLOW_EMPTY_BLOCK_SCAN` or `ALLOW_UNRESOLVED_NAME_HASHES` unless the block/run has been inspected.
- Provider rules version is committed.
- Class counts are non-negative and active plus expired equals total.
- Public `data/manifest.json` verifies every generated data artifact by byte size and SHA-256.
- If `topology.sqlite.gz` is included, it opens after decompression.
- `hns-topology validate-release` passes against the DB and generated public directory.
- `hns-topology archive-release` or `scripts/archive-release.sh` writes a manifest, site tarball, and SQLite gzip backup.
- `hns-topology validate-archive --manifest <manifest>` passes before moving archive artifacts to backup storage.
- No HTTP bodies or arbitrary subdomain crawl data are exported.

## Website Gate

- Website VM receives bounded static `public/` artifacts.
- Generated files fit comfortably within available disk.
- HTTPS is configured.
- DANE/HNS deployment checklist in `docs/DANE_SITE.md` is complete before claiming the report site is DANE-compatible.

## Cost Gate

- Run `DRY_RUN=1 scripts/gcloud-production-cycle.sh` before a cost-bearing cycle.
- Stop or delete the indexer compute VM after publishing.
- Keep the persistent indexer disk only while recovery speed is worth the storage cost.
- Do not keep duplicate HSD datadirs.
- Move only compressed exports or tarballs to optional backup storage.

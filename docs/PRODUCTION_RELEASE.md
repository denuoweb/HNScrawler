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
- Confirm the large disk is attached and mounted.
- Confirm HSD datadir is on the large disk.
- Confirm HSD is fully synced.
- Confirm HSD RPC credentials are local-only or firewall-restricted.
- Run bootstrap with a small `--limit` first.
- Run the full bootstrap only after disk usage is measured.

## Data Gate

- Snapshot metadata has height, tip hash, generated time, HSD chain, HSD version, crawler version, source hash, and provider rules hash.
- `hns-topology reorg-check --db <db>` passes before incremental updates.
- Provider rules version is committed.
- Class counts are non-negative and active plus expired equals total.
- Public `topology.sqlite.gz` opens after decompression.
- `hns-topology validate-release` passes against the DB and generated public directory.
- No HTTP bodies or arbitrary subdomain crawl data are exported.

## Live Check Gate

- Live-check concurrency and delay are set conservatively.
- Timeouts are short.
- Only promising names are queued.
- Failure reasons use the stable taxonomy.
- Live-check start and finish timestamps are present.
- Production validation uses `--require-live-checks`.

## Website Gate

- Website VM receives only static `public/` artifacts.
- Generated files fit comfortably within available disk.
- HTTPS is configured.
- DANE/HNS deployment checklist in `docs/DANE_SITE.md` is complete before claiming the report site is DANE-compatible.

## Cost Gate

- Stop or delete the indexer compute VM after publishing.
- Keep the persistent indexer disk only while recovery speed is worth the storage cost.
- Do not keep duplicate HSD datadirs.
- Move only compressed exports or tarballs to optional backup storage.

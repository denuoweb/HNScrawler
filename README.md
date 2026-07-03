# Denuo HNS Topology Report

Generated static reports for the current Handshake namespace topology.

This project is intentionally not a live explorer, a full DNS warehouse, or a web crawler. It builds periodic snapshots from HSD-derived name state, classifies compact on-chain resource summaries, runs rate-limited live checks only for promising names, and publishes the live static report.

## What It Answers

- How many HNS names use `SYNTH4` or `SYNTH6` nameserver bootstrap records?
- How many delegate to nameservers, with or without glue?
- How many use default provider infrastructure?
- How many have DS records and are DNSSEC candidates?
- How many are likely websites?
- How many load in strict HNS mode, require fallback, or have working DANE?
- Which providers dominate HNS?
- Which names are broken by missing glue or stale TLSA?

## Quick Start With Fixture Data

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
hns-topology bootstrap-fixture --fixture tests/fixtures/sample_hsd_names.json --db data/topology.sqlite
hns-topology generate-site --db data/topology.sqlite --out public
python -m http.server 8080 -d public
```

Open `http://127.0.0.1:8080`.

## HSD Bootstrap

HSD exposes `getnameresource <name>` for resource records, and exposes `getnames`, but the official API docs warn that node `getnames` has no pagination and is primarily useful for debugging/regtest/testnet. For production mainnet runs, use the stopped-node compact JSONL exporter so names are streamed from HSD's name tree instead of accumulated through JSON-RPC.

```bash
export HSD_RPC_URL=http://127.0.0.1:12037
export HSD_API_KEY=replace-me
hns-topology bootstrap --db data/topology.sqlite --rules configs/provider_rules.json --limit 100
```

For a full indexer bootstrap, prefer streaming JSONL from the HSD datadir:

```bash
EXPORT_FORMAT=compact JSONL_PATH=/mnt/hnscrawler/data/extracted_names.jsonl scripts/export-hsd-jsonl.sh
hns-topology bootstrap-jsonl --jsonl /mnt/hnscrawler/data/extracted_names.jsonl --db data/topology.sqlite --rules configs/provider_rules.json --batch-size 5000
```

See `docs/PERFORMANCE.md` for the HSD data-structure audit and bootstrap tuning knobs.

## Production Shape

Use a temporary or dedicated indexer VM with a persistent disk for HSD and the working database. Publish only generated `public/` artifacts to the existing production web VM, backed by its attached artifact disk rather than its boot disk. The production defaults keep no release archives or downloadable database backups; validation runs before publish, and only the live site tree remains.

Every generated snapshot includes source provenance, provider-rule provenance, provider/class/failure summaries, and live-check run settings in `data/summary.json`, including source type/hash, crawler version, provider rule version, provider rule hash, live-check rate limits, candidate counts, and checked counts. `data/manifest.json` records the export format version plus SHA-256 and byte-size entries for the public data files.

The Names page is backed by paginated `data/names-pages/` JSON. `--names-limit=0` means the generated browse data covers the full snapshot. Optional download artifacts (`data/names.json`, `data/names.csv`, and `data/topology.sqlite.gz`) can still be generated explicitly with `--include-downloads`, but are not part of the production default.

Generated site files:

- `index.html`
- `names.html`
- `faq.html`
- `data/summary.json`
- `data/manifest.json`
- `data/faq_answers.json`
- `data/names-pages.json`
- `data/names-pages/...`

Default production storage sizes are intentionally modest: 150 GB for the indexer data disk and 50 GB for the web artifact disk. The indexer pipeline starts HSD for update phases and stops it before live checks/site generation by default.

## Commands

```bash
hns-topology init-db --db data/topology.sqlite
hns-topology bootstrap-fixture --fixture tests/fixtures/sample_hsd_names.json --db data/topology.sqlite
hns-topology bootstrap-jsonl --jsonl extracted_names.jsonl --db data/topology.sqlite --height 123456 --tip-hash <hash>
hns-topology hsd-status --max-block-lag 2 --min-block-height 300000
hns-topology bootstrap --db data/topology.sqlite --limit 100
hns-topology incremental --db data/topology.sqlite
hns-topology incremental --db data/topology.sqlite --scan-block-height 123457
hns-topology incremental --db data/topology.sqlite --changed-names-file changed_names.txt
hns-topology reorg-check --db data/topology.sqlite --rollback
hns-topology live-check --db data/topology.sqlite --limit 100 --concurrency 4 --min-delay-ms 250
hns-topology export --db data/topology.sqlite --out public/data
hns-topology generate-site --db data/topology.sqlite --out public
hns-topology validate-release --db data/topology.sqlite --public-dir public --min-indexed-height 300000
hns-topology validate-public --public-dir public --min-indexed-height 300000
hns-topology archive-release --db data/topology.sqlite --public-dir public --out-dir archives
hns-topology validate-archive --manifest archives/hns-topology-height-123456-<timestamp>-manifest.json
hns-topology tlsa-from-cert --cert /etc/ssl/denuoweb/denuoweb.crt --site denuoweb
hns-topology verify-tlsa --cert /etc/ssl/denuoweb/denuoweb.crt --record '_443._tcp.denuoweb. 300 IN TLSA 3 1 1 <hex>'
```

Indexer VM setup scripts:

```bash
scripts/gcloud-create-indexer.sh
scripts/gcloud-wait-indexer-ssh.sh
scripts/setup-indexer-disk.sh
scripts/gcloud-sync-indexer-code.sh
scripts/setup-hsd-service.sh
scripts/indexer-status.sh
scripts/check-hsd-ready.sh
scripts/gcloud-sync-hsd-until-ready.sh
scripts/gcloud-sync-hsd-window.sh
scripts/export-hsd-jsonl.sh
scripts/gcloud-production-preflight.sh
scripts/gcloud-production-cycle.sh
scripts/gcloud-run-indexer-pipeline.sh
scripts/verify-release.sh
scripts/archive-release.sh
scripts/publish-indexer-site.sh
scripts/gcloud-print-site-tlsa.sh
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Data model](docs/DATA_MODEL.md)
- [Failure taxonomy](docs/FAILURE_TAXONOMY.md)
- [Deployment](docs/DEPLOYMENT.md)
- [DANE site deployment](docs/DANE_SITE.md)

## Validation

```bash
pytest
ruff check .
make fixture-site verify-release
```

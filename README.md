# Denuo HNS Topology Report

Generated static reports for the current Handshake namespace topology.

This project is intentionally not a live explorer, a full DNS warehouse, or a web crawler. It builds periodic snapshots from HSD-derived name state, classifies compact on-chain resource summaries, runs rate-limited live checks only for promising names, and publishes static JSON/CSV/SQLite artifacts plus a report dashboard.

## What It Answers

- How many HNS names have direct `SYNTH4` or `SYNTH6` IP records?
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

HSD exposes `getnameresource <name>` for resource records, and exposes `getnames`, but the official API docs warn that node `getnames` has no pagination and is primarily useful for debugging/regtest/testnet. For production mainnet runs, keep this interface isolated behind the indexer and be prepared to replace the name-source step with a direct HSD state export or chunked extractor.

```bash
export HSD_RPC_URL=http://127.0.0.1:14037
export HSD_API_KEY=replace-me
hns-topology bootstrap --db data/topology.sqlite --rules configs/provider_rules.json
```

## Production Shape

Use a temporary or dedicated indexer VM with a large persistent disk for HSD and the working database. Publish only generated static files to the small `denuowebsite-vm`.

Every generated snapshot includes source provenance and provider-rule provenance in `data/summary.json`, including source type/hash, crawler version, provider rule version, and provider rule hash.

Generated site files:

- `index.html`
- `faq.html`
- `providers.html`
- `classes.html`
- `names.html`
- `broken.html`
- `dane.html`
- `data/summary.json`
- `data/faq_answers.json`
- `data/classes.json`
- `data/providers.json`
- `data/broken.json`
- `data/dane.json`
- `data/names.json`
- `data/names.csv`
- `data/topology.sqlite.gz`

## Commands

```bash
hns-topology init-db --db data/topology.sqlite
hns-topology bootstrap-fixture --fixture tests/fixtures/sample_hsd_names.json --db data/topology.sqlite
hns-topology bootstrap-jsonl --jsonl extracted_names.jsonl --db data/topology.sqlite --height 123456 --tip-hash <hash>
hns-topology bootstrap --db data/topology.sqlite
hns-topology incremental --db data/topology.sqlite --changed-names-file changed_names.txt
hns-topology reorg-check --db data/topology.sqlite --rollback
hns-topology live-check --db data/topology.sqlite --limit 100 --concurrency 4 --min-delay-ms 250
hns-topology export --db data/topology.sqlite --out public/data
hns-topology generate-site --db data/topology.sqlite --out public
hns-topology validate-release --db data/topology.sqlite --public-dir public
```

Indexer VM setup scripts:

```bash
scripts/gcloud-create-indexer.sh
scripts/setup-indexer-disk.sh
scripts/gcloud-sync-indexer-code.sh
scripts/setup-hsd-service.sh
scripts/indexer-status.sh
scripts/gcloud-run-indexer-pipeline.sh
scripts/verify-release.sh
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

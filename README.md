# HNScrawler

Static topology and DANE-readiness snapshots for the current Handshake namespace.

HNScrawler builds a compact SQLite database from HSD-derived root state, classifies current on-chain resource summaries, derives static compliance stages, and publishes a paginated static report. It does not run website liveness checks, device/browser checks, or host-candidate discovery.

The current analysis answers:

- Which active names publish SYNTH or delegated nameserver bootstrap material?
- Which delegated names are missing parent-side GLUE?
- Which active names publish DS records?
- Which DS names already include TLSA material, and which need TLSA?
- Which names are parked/default/resolver infrastructure and should stay out of action queues?

## Compliance Stages

- `tlsa_present`: current HNS resource data has DS and TLSA material.
- `tlsa_gap`: current HNS resource data has DS but no static TLSA material.
- `missing_glue`: delegation exists but parent-side GLUE bootstrap is missing.
- `bootstrap_ready`: SYNTH or delegated GLUE bootstrap exists; the next step is DNSSEC, DS, and TLSA.
- `non_actionable`: expired, parked/default, resolver infrastructure, empty, or unsupported resources.

## Quick Start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'

hns-topology bootstrap-fixture --fixture tests/fixtures/sample_hsd_names.json --db data/topology.sqlite
hns-topology generate-site --db data/topology.sqlite --out public
hns-topology validate-release --db data/topology.sqlite --public-dir public
```

Open `public/index.html` or serve `public/` with any static web server.

## HSD Indexing

Bootstrap from HSD RPC:

```bash
hns-topology bootstrap-hsd --db data/topology.sqlite --rules configs/provider_rules.json
```

Incremental updates:

```bash
hns-topology incremental --db data/topology.sqlite --scan-block-height 337000
hns-topology reorg-check --db data/topology.sqlite --rollback
```

JSONL bootstrap:

```bash
hns-topology bootstrap-jsonl --jsonl data/names.jsonl --db data/topology.sqlite --rules configs/provider_rules.json
```

Provider-rule changes can be applied without rerunning HSD extraction:

```bash
hns-topology reclassify --db data/topology.sqlite --rules configs/provider_rules.json
```

## Evidence Imports

DNS observations remain supported as static evidence sidecars:

```bash
hns-topology import-dns-evidence --db data/topology.sqlite --file dns-evidence.json --source crowd --source-id worker-1
```

Imported DNS observations are exported under `data/dns-evidence/<name>.json` and linked from matching name rows.

## Published Artifacts

Default production artifacts:

- `index.html`
- `names.html`
- `styles.css`
- `app.js`
- `generator_handoff.js`
- `data/summary.json`
- `data/manifest.json`
- `data/names-pages.json`
- `data/names-pages/**`
- `data/ip-addresses/**`
- `data/dns-evidence/**` when imported DNS evidence exists

Optional downloads with `--include-downloads`:

- `data/names.json`
- `data/names.csv`
- `data/verification.csv`
- `data/topology.sqlite.gz`

## Performance Model

Indexing is O(N) in exported names plus resource records. Export uses one canonical sorted row store and compact posting lists for filters, so publishing is O(E + P + I), where `E` is exported names, `P` is nonzero posting entries, and `I` is resource-IP index rows. The static site only fetches the current page and selected posting list, avoiding full-snapshot browser loads.

## Development

```bash
make test
make lint
make fixture-site
```

Production wrappers live under `scripts/`. They start HSD only for update phases, generate the static site, validate the release, optionally archive, and publish generated `public/` artifacts.

# HNScrawler

Static topology and DANE-readiness snapshots for the current Handshake namespace.

HNScrawler builds a compact SQLite database from HSD-derived root state, classifies current on-chain resource summaries, combines them with imported delegated-DNS evidence, derives compliance stages, and publishes a paginated static report. The topology build does not run website liveness checks. A separate `hns-live-directory` service can consume the published snapshot on the web VM without extending the HSD build or deploy cycle.

The current analysis answers:

- Which active names publish SYNTH or delegated nameserver bootstrap material?
- Which delegated names have no direct GLUE, and which instead have an indexed HNS nameserver handoff?
- Which active names publish DS records?
- Which roots have an authoritative or authenticated HTTPS TLSA answer in stored DNS evidence?
- Which DS names still lack stored TLSA proof and need verification before generator handoff?
- Which names are parked/default/resolver infrastructure and should stay out of action queues?

## Compliance Stages

- `tlsa_present`: parent DS is present and stored delegated-DNS evidence contains an authoritative or authenticated HTTPS TLSA answer.
- `tlsa_gap`: parent DS is present, but stored DNS evidence does not prove TLSA presence.
- `indirect_ns_handoff`: direct GLUE is absent, but an active HNS root can bootstrap a delegated nameserver host; the handoff still needs authority verification.
- `missing_glue`: delegation has neither direct GLUE nor an indexed HNS nameserver handoff.
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

TLSA is not part of Handshake's on-chain Resource format. HTTPS TLSA presence is therefore derived only from the latest stored observation per query/server/source identity. A qualifying record must be an exact `_443._tcp.<host>` answer below the indexed root and carry authoritative (`AA`) or authenticated-data (`AD`) evidence. The headline is labeled **TLSA observed** because imports are not an exhaustive live scan; `tlsa_evidence_names` in `summary.json` reports the number of roots with stored TLSA probes.

## Live Website Directory

The independent live scanner has its own database, CLI, static output, runner, and web-VM timer. Its detailed evidence queue checks apex hosts and DNS-evidenced subdomains, while a separate cursor-based broad sweep covers DS and delegated roots without materializing millions of candidates. It separates authenticated HTTPS endpoints from HTTP-only endpoints. See `docs/LIVE_DIRECTORY.md`.

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

# Architecture

HNScrawler is a static topology indexer for Handshake names. It indexes HSD-derived root state, classifies compact resource summaries, derives static DANE-readiness queues, and publishes a static site.

It intentionally does not perform website liveness checks, host discovery, device/browser checks, or active HTTPS/DANE verification.

## Pipeline

```text
HSD RPC / JSONL / fixture
  -> normalized names
  -> resource summaries
  -> provider classification
  -> resource-IP index
  -> static compliance stages
  -> static site export
  -> release validation
```

## Indexing

Bootstrap commands create the canonical SQLite database:

- `bootstrap-hsd`
- `bootstrap-jsonl`
- `bootstrap-fixture`

Incremental indexing records block history and rollback snapshots:

- `incremental`
- `reorg-check --rollback`

Provider-rule updates can be applied with `reclassify` without re-extracting all HSD resources.

## Classification

Resource classification is based on current HNS resource records:

- SYNTH bootstrap
- NS delegation
- GLUE bootstrap
- DS records
- TLSA records
- TXT presence
- provider/default/resolver infrastructure rules

Known default parking and resolver infrastructure stay out of actionable queues.

## Compliance Workflow

The canonical workflow state is the derived `compliance_stage`:

- `tlsa_present`: DS and TLSA material are present in current HNS resource data.
- `tlsa_gap`: DS is present but TLSA material is missing.
- `missing_glue`: NS delegation exists but GLUE bootstrap is missing.
- `bootstrap_ready`: SYNTH or delegated GLUE bootstrap exists; DNSSEC/DS/TLSA planning is next.
- `non_actionable`: expired, parked/default, resolver infrastructure, empty, or unsupported resources.

Generator handoffs are produced from those stages:

- `generate_tlsa`
- `missing_glue`
- `dnssec_dane`

## Export Design

The exporter writes one sorted canonical row store under `names-pages/all`. Filter views are compact posting lists of row ordinals into that store. This avoids duplicating high-cardinality row payloads for every filter and lets the static UI fetch only the active page.

Default public data:

- summary and manifest
- paginated names row store
- nonzero filter postings
- IP drill-down indexes
- DNS evidence sidecars

Optional downloads:

- full names JSON/CSV
- verification command CSV
- gzipped SQLite snapshot

## Validation

`validate-release` checks:

- SQLite integrity and required tables
- snapshot metadata provenance
- required public files
- manifest checksums and byte counts
- exported name counts
- optional download row counts
- DNS evidence sidecar paths
- absence of private key artifacts

Production wrappers run validation before archive or publish.

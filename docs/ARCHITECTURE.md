# Architecture

HNScrawler is a static topology indexer for Handshake names. It indexes HSD-derived root state, classifies compact resource summaries, combines them with imported delegated-DNS observations, derives DANE-readiness queues, and publishes a static site.

The topology pipeline intentionally does not perform website liveness checks, host discovery, device/browser checks, or active HTTPS/DANE verification. The standalone live-directory process runs separately on the web VM and consumes a published topology snapshot read-only.

## Pipeline

```text
HSD RPC / JSONL / fixture -> resource + provider summaries
imported DNS evidence     -> authoritative/authenticated TLSA summary
both summaries            -> compliance stages -> static site -> validation
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
- TXT presence
- provider/default/resolver infrastructure rules

Handshake Resource data is referral data and cannot contain TLSA. HTTPS TLSA records live in the delegated zone at `_443._tcp.<host>`. `dns_evidence` is the source of TLSA observations; the derived `tlsa_evidence_summary` table keeps the latest observation per query/server/source identity, rejects malformed or wrong-owner data, and deduplicates apex, `www`, and evidence-backed subdomain owners to one root-level presence count.

Known default parking and resolver infrastructure stay out of actionable queues.

## Compliance Workflow

The canonical workflow state is the derived `compliance_stage`:

- `tlsa_present`: parent DS and stored authoritative/authenticated TLSA evidence are both present. This does not prove a certificate match.
- `tlsa_gap`: parent DS is present, but stored DNS evidence does not prove TLSA presence.
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
- paginated overview aggregate tables
- paginated names row store
- nonzero filter postings
- IP drill-down indexes
- nameserver drill-down indexes
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

## Standalone Live Directory

`hns-live-directory` owns a separate SQLite database and static tree under `/mnt/hns-topology/live-directory` on `denuoweb-vm`. It is scheduled independently and is never called by the indexer pipeline. Its candidate, DNS, HTTP/HTTPS, DANE, retry, and export model is documented in `docs/LIVE_DIRECTORY.md`.

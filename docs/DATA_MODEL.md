# Data Model

HNScrawler stores root-level Handshake topology and imported DNS/DANE readiness evidence. The database no longer stores live website checks, host candidates, host live status, or browser/device observations.

## Core Tables

### `snapshot_meta`

Key/value provenance and run metadata:

- source type, source file hash, HSD RPC URL when applicable
- HSD chain/version, indexed height, indexed tip hash
- crawler version
- provider-rule version, path, and hash
- resource-IP and TLSA-evidence summary versions

### `names`

One row per root name:

- normalized `name`
- `name_hash`
- chain `state`, `renewal_height`, `expired`
- raw resource hash
- JSON `record_types`
- `onchain_class`
- `provider_guess`
- `last_seen_height`, `updated_at`

### `resource_summary`

Compact parsed HNS resource state per name:

- JSON arrays: `ns_names`, `glue4`, `glue6`, `synth4`, `synth6`, `ds_records`
- flags: `has_ds`, `has_ns`, `has_glue`, `has_synth`, `has_txt`
- `raw_size`, `resource_version`, `resource_hash`

Legacy `tlsa_records` and static certificate-expiry columns remain in the schema for database compatibility, but HSD Resource does not encode TLSA and those columns are not the source of the public TLSA presence metric.

### `resource_ip`

Derived lookup table for GLUE/SYNTH addresses:

- `name`
- `ip`
- `field`: `GLUE4`, `GLUE6`, `SYNTH4`, or `SYNTH6`

The table backs IP drill-down pages and is rebuilt with `hns-topology rebuild-resource-ip` when needed.

### `provider_summary`

Provider-rule rollup keyed by `provider_key`:

- `provider_type`
- matched nameserver/IP patterns
- `names_count`
- `likely_website_count`
- `updated_at`

### `dns_evidence`

Imported static DNS observations:

- `name`, `qname`, `rrtype`, `server`
- `source`, `source_id`
- status fields: `status`, `rcode`, `flags`, `elapsed_ms`, `error`
- JSON arrays: `answer_json`, `authority_json`, `additional_json`
- `captured_at`

These rows export to `data/dns-evidence/<name>.json` when present.

### `tlsa_evidence_summary`

Derived root-level TLSA observation state:

- `has_tlsa`: at least one latest authoritative (`AA`) or authenticated (`AD`) HTTPS TLSA answer exists
- JSON arrays: normalized `tlsa_records`, deduplicated `tlsa_owners`
- `observed_at`: latest qualifying positive observation
- `checked_at`: latest stored TLSA observation, including negative/error results

The summary uses only exact `_443._tcp.<host>` owners at or below the indexed HNS root. For each `(qname, rrtype, server, source, source_id)` identity, a newer negative observation supersedes an older positive. The table is rebuilt for existing databases and refreshed whenever evidence is imported.

### `block_history`

Incremental indexing history:

- block `height`
- `block_hash`
- JSON `changed_names`
- `indexed_at`

### `changed_name_rollbacks`

Reorg rollback snapshots:

- `height`, `name`
- previous name row JSON
- previous resource summary JSON
- previous resource hash/classification
- `block_hash_at_height`, `captured_at`

## Derived Compliance

`compliance_stage` is computed during export and lookup from static state:

- `tlsa_present`
- `tlsa_gap`
- `missing_glue`
- `bootstrap_ready`
- `non_actionable`

The stage is not stored as source data; it is derived from expiration state, provider type, resource bootstrap flags, DS, and normalized TLSA evidence.

## Public Export

Default export:

- `summary.json`
- `manifest.json`
- `overview-pages.json`
- `overview-pages/**`
- `names-pages.json`
- `names-pages/**`
- `ip-addresses/**`
- `nameservers/**`
- `dns-evidence/**` when imported DNS evidence exists

Optional with `--include-downloads`:

- `names.json`
- `names.csv`
- `verification.csv`
- `topology.sqlite.gz`

`names-pages/all` is the canonical sorted row store. Filter collections are ordinal postings into that row store, which keeps export and browser load cost bounded.

# Data Model

HNScrawler stores root-level Handshake topology and static DNS/DANE readiness evidence. The database no longer stores live website checks, host candidates, host live status, or browser/device observations.

## Core Tables

### `snapshot_meta`

Key/value provenance and run metadata:

- source type, source file hash, HSD RPC URL when applicable
- HSD chain/version, indexed height, indexed tip hash
- crawler version
- provider-rule version, path, and hash
- resource-IP index version

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

- JSON arrays: `ns_names`, `glue4`, `glue6`, `synth4`, `synth6`, `ds_records`, `tlsa_records`
- static TLSA certificate fields: `tlsa_cert_not_valid_after`, `tlsa_cert_expired`
- flags: `has_ds`, `has_ns`, `has_glue`, `has_synth`, `has_txt`
- `raw_size`, `resource_version`, `resource_hash`

Static TLSA certificate expiry is only inferred for embedded full-certificate TLSA records (`selector = 0`, `matchingType = 0`). SPKI-hash TLSA records do not contain certificate validity windows.

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

The stage is not stored as source data; it is derived from expiration state, provider type, resource bootstrap flags, DS, and TLSA presence.

## Public Export

Default export:

- `summary.json`
- `manifest.json`
- `names-pages.json`
- `names-pages/**`
- `ip-addresses/**`
- `dns-evidence/**` when imported DNS evidence exists

Optional with `--include-downloads`:

- `names.json`
- `names.csv`
- `verification.csv`
- `topology.sqlite.gz`

`names-pages/all` is the canonical sorted row store. Filter collections are ordinal postings into that row store, which keeps export and browser load cost bounded.

# Data Model

The working database is SQLite. SQLite is enough for the first production release because the public output is static and the working set stores summaries rather than full DNS or web crawl data.

## `snapshot_meta`

Key-value snapshot metadata.

- `last_indexed_height`
- `last_indexed_tip_hash`
- `generated_at`
- `hsd_chain`
- `hsd_version`
- `crawler_version`
- `live_check_started_at`
- `live_check_finished_at`
- `source_type`
- `source_file`
- `source_file_hash`
- `source_rpc_url`
- `provider_rules_version`
- `provider_rules_hash`
- `provider_rules_path`

## `names`

One row per HNS name.

- `name`: normalized lowercase HNS name
- `name_hash`: HSD name hash if available
- `state`: HSD name state
- `renewal_height`: renewal block height
- `expired`: boolean integer
- `resource_hash`: SHA-256 of canonical resource JSON
- `record_types`: JSON array
- `onchain_class`: stable on-chain class
- `provider_guess`: provider rule key
- `last_seen_height`: indexed height
- `updated_at`: crawler timestamp

## `resource_summary`

Compact decoded resource summary.

- `ns_names`: JSON array
- `glue4`: JSON array
- `glue6`: JSON array
- `synth4`: JSON array
- `synth6`: JSON array
- `ds_records`: JSON array containing compact `keyTag`, `algorithm`, `digestType`, and normalized digest values
- `has_ds`: boolean integer
- `has_txt`: boolean integer
- `raw_size`: canonical resource byte size
- `resource_hash`: duplicated for convenient joins and verification

## `live_status`

Latest live-check result per name.

- `dns_reachable`
- `dnssec_status`
- `tlsa_status`
- `dane_status`
- `https_status`
- `strict_hns_status`
- `doh_fallback_status`
- `failure_reason`
- `checked_at`
- `next_check_at`

`https_status = tls_unverified` means the TLS connection completed only when WebPKI verification was disabled for certificate capture. It is not automatically a failure if `dane_status = valid`.

`dnssec_status = valid` means the live checker found delegated DNSKEY data matching the on-chain DS record and, when present, a valid DNSKEY RRSIG. DNSSEC failure statuses map to the stable failure taxonomy.

`strict_hns_status = working` means address discovery and HTTPS loading succeeded without using the fallback resolver. Direct `SYNTH4`/`SYNTH6` records count as strict website addresses. `GLUE4`/`GLUE6` records are used only as nameserver bootstrap addresses for delegated resolution.

`doh_fallback_status = required` means strict HNS address discovery failed and the checker found an address only through the configured fallback resolver path. The field name is retained for export stability; the value records fallback dependency, not a guaranteed DoH transport.

## `provider_summary`

Materialized provider counts for site generation.

- `provider_key`
- `provider_type`
- `ns_pattern`: machine-readable rule criteria such as `suffix:namebase.io`, `regex:<pattern>`, or `self_hosted`
- `ip_pattern`: machine-readable CIDR criteria such as `cidr:192.168.0.0/16`
- `names_count`
- `likely_website_count`
- `working_count`
- `dane_count`
- `updated_at`

## Reorg Tables

`block_history` records the recent indexed block hash and changed names by height.

`changed_name_rollbacks` records enough prior state to undo recent compact-index changes before replaying canonical blocks.

It stores both human-auditable fields and full compact row snapshots:

- `previous_resource_hash`
- `previous_classification`
- `previous_live_status`
- `previous_name_row`
- `previous_resource_summary`
- `block_hash_at_height`

The full row snapshots are required because restoring only a resource hash and class is not enough to recover NS, GLUE, SYNTH, DS, provider, and live-check fields after a reorg.

## Export Files

Public exports are generated from SQLite:

- `summary.json`
- `manifest.json`
- `faq_answers.json`
- `classes.json`
- `providers.json`
- `broken.json`
- `dane.json`
- `names.json`
- `names.csv`
- `topology.sqlite.gz`

`manifest.json` is the export contract for the static data directory. It records:

- `manifest_version`
- crawler version
- snapshot height, tip hash, source provenance, and provider-rule provenance
- summary counts copied from `summary.json`
- byte size and SHA-256 for each generated data artifact except the manifest itself

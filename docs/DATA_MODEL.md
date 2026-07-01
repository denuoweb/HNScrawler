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

## `provider_summary`

Materialized provider counts for site generation.

- `provider_key`
- `provider_type`
- `names_count`
- `likely_website_count`
- `working_count`
- `dane_count`
- `updated_at`

## Reorg Tables

`block_history` records the recent indexed block hash and changed names by height.

`changed_name_rollbacks` records enough prior state to undo recent compact-index changes before replaying canonical blocks.

## Export Files

Public exports are generated from SQLite:

- `summary.json`
- `faq_answers.json`
- `classes.json`
- `providers.json`
- `broken.json`
- `dane.json`
- `names.json`
- `names.csv`
- `topology.sqlite.gz`


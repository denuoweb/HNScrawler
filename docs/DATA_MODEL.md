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
- `live_check_limit`
- `live_check_candidate_count`
- `live_check_checked_count`
- `live_check_concurrency`
- `live_check_min_delay_ms`
- `live_check_timeout_seconds`
- `live_check_recheck_seconds`
- `live_check_resolver`
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
- `raw_size`: HSD resource byte size from compact imports, or canonical JSON byte size for decoded RPC/fixture resources
- `resource_version`: HSD resource version when present
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

`strict_hns_status = working` means address discovery and HTTPS loading succeeded without using the fallback resolver. `SYNTH4`/`SYNTH6` and `GLUE4`/`GLUE6` records are used as nameserver bootstrap addresses for strict resolution; website `A`, `AAAA`, and `TLSA` records still come from authoritative DNS.

`doh_fallback_status = required` means strict HNS address discovery failed and the checker found an address only through the configured fallback resolver path. The field name is retained for export stability; the value records resolver fallback dependency, not a guaranteed DoH transport.

## `dns_evidence`

Append-only DNS observations from the crawler or external workers.

- `name`: normalized HNS name
- `qname`: fully-qualified queried owner
- `rrtype`: DNS type such as `A`, `AAAA`, `TLSA`, or `DNSKEY`
- `server`: nameserver IP queried directly
- `source`: observation source such as `scanner` or `crowd`
- `source_id`: optional worker or submitter identifier
- `status`: `ok`, `rcode`, `timeout`, or `error`
- `rcode`: DNS response code when a response was received
- `flags`: response flags as dnspython text
- `answer_json`: JSON array of answer RRset lines
- `authority_json`: JSON array of authority RRset lines
- `additional_json`: JSON array of additional RRset lines
- `elapsed_ms`: query duration
- `error`: exception class for failed probes
- `captured_at`: observation timestamp

The report exports the latest observation per `(qname, rrtype, server, source, source_id)` into `data/dns-evidence/<name>.json`.

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
- `names-pages.json`
- `names-pages/<collection>/page-<n>.json`
- `ip-addresses/<ip>.json` for GLUE and SYNTH address lookups
- `dns-evidence/<name>.json` when scanner or crowd evidence exists

The default public export does not write standalone Providers, Classes, Broken, DANE, CSV, SQLite, or full `names.json` artifacts. Provider, class, failure, and DANE summaries live in `summary.json`; rows are searched and filtered through the Names collections. `names.json`, `names.csv`, and `topology.sqlite.gz` are written only when `--include-downloads` is explicitly requested.

There is no standalone DANE row exporter in the production path. DANE-specific views such as DS records, needs DANE, stale TLSA, and valid DANE are Names filters.

`summary.broken` contains failure reason counts for the Names filter dropdown, not duplicated example rows. Example names for a failure reason come from the filtered Names collection.

Names collections are ordered by normalized name. The browser uses that invariant for static exact-name lookup: if `/api/name` is unavailable, it binary-searches the sorted `all` collection by fetching only a small number of page files. Compact row arrays still include first NS/GLUE/SYNTH scalar fields plus resource hash, size, version, index height, and a DNS evidence path for DANE generator handoff links and diagnostics.

IP address artifacts are keyed by URL-encoded address, for example `ip-addresses/44.231.6.183.json` or an encoded IPv6 literal. Each file contains the canonical query IP, `row_count`, and full Names rows for exported names whose `GLUE4`, `GLUE6`, `SYNTH4`, or `SYNTH6` values contain that address.

`summary.json` includes `next_actions`, a small derived list for the Overview action panel and filtered Names queue context. Each item contains a count, a primary Names filter, a filter link, and the DANE generator intent to use for matching row-level handoffs. The list is deliberately derived from existing counters and filters so it does not create new row artifacts.

`manifest.json` is the export contract for the static data directory. It records:

- `manifest_version`
- crawler version
- snapshot height, tip hash, source provenance, and provider-rule provenance
- summary counts copied from `summary.json`
- browser table export limits, total name count, exported name row count, and truncation status
- byte size and SHA-256 for each generated data artifact except the manifest itself

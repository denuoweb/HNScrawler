# Data Model

The working database is SQLite. SQLite is enough for the first production release because the working set stores summaries rather than full DNS or web crawl data, and high-cardinality lookups can be exported as compact static indexes instead of duplicated full row sets.

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
- `host_live_check_started_at`
- `host_live_check_finished_at`
- `host_live_check_limit`
- `host_live_check_candidate_count`
- `host_live_check_checked_count`
- `host_live_check_concurrency`
- `host_live_check_min_delay_ms`
- `host_live_check_timeout_seconds`
- `host_live_check_recheck_seconds`
- `host_live_check_resolver`
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
- `authoritative_doh`: compatibility JSON field retained for export stability; current live checks discover authoritative DoH through RFC 9461 `_dns.<nameserver>` SVCB records instead of HNS TXT declarations
- `tlsa_records`: JSON array of static TLSA records seen directly in the HNS resource, including decoded certificate metadata only when the TLSA association embeds a full DER certificate
- `tlsa_cert_not_valid_after`: earliest embedded TLSA certificate expiration timestamp, when statically knowable
- `tlsa_cert_expired`: boolean integer set when an embedded full-certificate TLSA association is already expired
- `has_ds`: boolean integer
- `has_txt`: boolean integer
- `raw_size`: HSD resource byte size from compact imports, or canonical JSON byte size for decoded RPC/fixture resources
- `resource_version`: HSD resource version when present
- `resource_hash`: duplicated for convenient joins and verification

## `resource_ip`

Normalized reverse index for GLUE and SYNTH address lookup.

- `name`
- `ip`
- `field`: one of `GLUE4`, `GLUE6`, `SYNTH4`, `SYNTH6`

The primary key is `(name, ip, field)`. `idx_resource_ip_ip_name` supports paginated lookup of names by IP address without expanding JSON arrays from `resource_summary`.

## `live_status`

Latest legacy apex live-check result per name. New host checks write `host_live_status`; `live_status` remains for compatibility with older databases and the `live-check` apex wrapper.

- `dns_reachable`
- `dnssec_status`
- `tlsa_status`
- `dane_status`
- `https_status`
- `strict_hns_status`
- `doh_fallback_status`
- `failure_reason`
- `https_cert_sha256`: SHA-256 of the captured HTTPS end-entity certificate DER, when reachable
- `https_spki_sha256`: SHA-256 of the captured HTTPS end-entity SubjectPublicKeyInfo DER, when reachable
- `https_cert_not_valid_after`: captured HTTPS end-entity certificate expiration timestamp, when reachable
- `checked_at`
- `next_check_at`

`https_status = tls_unverified` means the TLS connection completed only when WebPKI verification was disabled for certificate capture. It is not automatically a failure if `dane_status = valid`.

`dnssec_status = valid` means the live checker found delegated DNSKEY data matching the on-chain DS record and, when present, a valid DNSKEY RRSIG. DNSSEC failure statuses map to the stable failure taxonomy.

`strict_hns_status = working` means address discovery and HTTPS loading succeeded without using the fallback resolver. `SYNTH4`/`SYNTH6` and `GLUE4`/`GLUE6` records are used as nameserver bootstrap addresses for strict resolution; when direct UDP/TCP 53 cannot complete, live checks can use RFC 9461 `_dns.<nameserver>` SVCB records to discover an RFC 8484 retry transport to the same delegated nameserver. Website `A`, `AAAA`, and `TLSA` records still come from authoritative DNS and DNSSEC validation.

`doh_fallback_status = required` means strict HNS address discovery failed and the checker found an address only through the configured fallback resolver path. The field name is retained for export stability; the value records resolver fallback dependency, not a guaranteed DoH transport.

## `host_candidates`

Bounded queue of hosts worth checking under indexed HNS roots.

- `root_name`: indexed HNS root that supplies authority/bootstrap
- `host`: website/service hostname to check
- `source`: stable source identifier such as `default_apex`, `default_www`, `browser_evidence`, `resource_tlsa_owner`, `dns_evidence_tlsa_owner`, `previous_live_host`, `operator_import`, or `link_evidence`
- `source_detail`: short source context
- `confidence`: integer ranking hint
- `first_seen_at`
- `last_seen_at`
- `next_check_at`
- `suppressed`: boolean integer; discovery upserts preserve suppression

The primary key is `(root_name, host, source)`. Default apex and `www.<root>` candidates are created only for active roots with actionable bootstrap material. Browser evidence, TLSA owner evidence, and previous live host status can add subdomain hosts. The crawler does not expand arbitrary subdomains without evidence.

## `host_live_status`

Latest live-check result per `(root_name, host)`.

- `root_name`: HNS authority/root container
- `host`: checked website/service host
- `url`: canonical `https://<host>/` directory URL
- `address_status`
- `dns_reachable`
- `dnssec_status`
- `tlsa_status`
- `dane_status`
- `https_status`
- `strict_hns_status`
- `authoritative_udp_status`
- `authoritative_tcp_status`
- `authoritative_doh_status`
- `fallback_status`
- `failure_reason`
- `certificate_sha256`
- `spki_sha256`
- `certificate_not_valid_after`
- `checked_at`
- `next_check_at`

For host checks, A/AAAA RRset owners are the host, TLSA owner is `_443._tcp.<host>`, HTTPS SNI is the host, and DNSSEC validation uses the root/zone key owner. This lets `jaron.crewball` or `impervious.forever` be live directory entries even if `crewball` or `forever` apex is not live.

`ns_handoff_*` export and lookup fields are derived from current HNS resources. They appear when a name has NS delegation without direct GLUE/SYNTH, and the rightmost HNS root of a nameserver hostname has its own bootstrap material. For example, `mercenary/` with `NS ns1.skyinclude.` can expose `ns_handoff_ns = ns1.skyinclude`, `ns_handoff_root = skyinclude`, and a `ns_handoff_bootstrap_ip` from `skyinclude/`. This is a two-step probe path for resolving the nameserver hostname first; it is not treated as direct parent-side GLUE and does not change `missing_glue` to `bootstrap_ready`.

Static TLSA certificate expiration is intentionally narrow. The crawler can determine expiration offline only for TLSA records with `selector = 0` and `matchingType = 0`, because those records embed the full DER certificate. Normal `3 1 1` SPKI-hash TLSA records do not contain a certificate validity window, so expiration must come from live HTTPS/browser evidence.

## Compliance Stage

`compliance_stage` is a derived export field, not a stored source table column. Export and lookup queries compute it from `names.expired`, provider type, `resource_summary` bootstrap flags, and `live_status` DNSSEC/TLSA/DANE/failure fields. It is the canonical per-name DANE workflow state used by summary cards, action queues, Names filters, and generator handoff labels.

The stable stage vocabulary is:

- `dane_verified`
- `tlsa_gap`
- `stale_tlsa`
- `dnssec_broken`
- `missing_glue`
- `bootstrap_ready`
- `resolver_fallback`
- `service_blocked`
- `non_actionable`

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

## `browser_evidence`

Append-only live device observations imported from the sister HNS Browser resolver trace JSON or `gateway-events.log`.

- `name`: normalized HNS root name used to join current static resources
- `host`: browser host, including subdomains such as `nathan.woodburn`
- `url`: observed URL when present
- `source`: source label such as `hns-browser`
- `source_id`: optional device, worker, or run identifier
- `evidence_type`: `resolver_trace` or `gateway_event`
- `browser_result`: normalized result such as `dane_verified`, `certificate_expired`, `resolver_fallback`, `loaded`, or `failed`
- `status_code`, `stage`, `reason`: gateway event status fields when imported from `gateway-events.log`
- `mode`, `hns_proof`, `resolution_source`: resolver trace context
- `authoritative_udp`, `authoritative_tcp`, `authoritative_doh`: browser-observed authoritative transport outcomes
- `fallback_used`, `fallback_reason`: browser fallback context; network-level port 53 blocking is evidence context, not automatically a domain-side compliance failure
- `dnssec_status`, `tlsa_owner`, `tlsa_status`, `tlsa_source`, `dane_status`: resolver/TLSA trace fields
- `certificate_sha256`, `spki_sha256`: browser-captured certificate hashes when present
- `certificate_not_valid_after`, `certificate_expired`: browser-captured certificate expiration metadata when the resolver trace includes it; fallback or port-53 blocking remains separate context
- `final_error`: raw resolver or transport error text when present
- `raw_json`: raw imported event or trace payload
- `captured_at`: observation timestamp

The report exports imported browser observations per name into `data/browser-evidence/<name>.json`. These observations are displayed beside crawler DNS evidence so static analysis, crawler live checks, and Android/browser behavior can be compared without overwriting each other.

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
- `names-pages.json`
- `host-directory.json`
- `names-pages/<collection>/page-<n>.json`
- compact `ip-addresses/<ip>.json` and `ip-addresses/<ip>/page-<n>.json` postings for GLUE and SYNTH address lookups
- `dns-evidence/<name>.json` when scanner or crowd evidence exists
- `browser-evidence/<name>.json` when imported browser/device evidence exists

The default public export does not write standalone Providers, Classes, Broken, DANE, CSV, SQLite, verification-command CSV, browser-target CSV, live-site directory CSV, or full `names.json` artifacts. Provider, class, failure, and DANE summaries live in `summary.json`; rows are searched and filtered through the Names collections. The default host-level live directory is `host-directory.json`; `names.json`, `names.csv`, `verification.csv`, `browser-targets.csv`, `site-directory.csv`, and `topology.sqlite.gz` are written only when `--include-downloads` is explicitly requested.

`verification.csv` contains directory-ready `dig` probes for exported names with direct bootstrap material or indirect NS handoff evidence. Each row carries `purpose`, `qname`, `rrtype`, `transport`, and `command`. Direct rows query the HNS-proven GLUE/SYNTH address. Indirect handoff rows first resolve the nameserver hostname through its HNS root, then use `<resolved-ns-ip>` placeholders for target-zone A, AAAA, TLSA, and DNSKEY probes. Commands include UDP 53 and TCP 53 variants. When a nameserver hostname is known, `_dns.<nameserver>` SVCB probes are included to discover RFC 9461/RFC 8484 authoritative DoH alternatives. The file is generated from the same canonical exported name set as `names-pages/all`, so truncated exports do not mix rows from different name windows. Command failures from a client network that blocks UDP/TCP 53 should be interpreted alongside browser evidence and resolver fallback observations.

`host-directory.json` and the optional `site-directory.csv` contain one row per live host with crawler or imported browser evidence that the host loaded, HTTPS was reachable, or DANE verified. They include `root_name`, `host`, canonical HTTPS URL, normalized `directory_status`, evidence source/confidence, transport note, DANE/TLS/certificate fields, browser context, and a static diagnostic path back into the Names page. The static `live_site_names` collection is root-level for navigation, so release validation compares distinct directory roots rather than raw host row count. Static-only candidates and expired roots are excluded.

`browser-targets.csv` contains a ranked browser-testing queue for the same exported root window. Each row includes `root_name`, `host`, `url`, `priority`, `category`, `reason`, current static/live/browser evidence fields, a `diagnostic_path`, and an `adb_command` that force-stops `com.denuoweb.hnsdane` and reloads the URL through `com.denuoweb.hnsdane/.ui.MainActivity` using the browser's `com.denuoweb.hnsdane.LOAD_URL` extra. This is the bridge between static analysis and device/browser reverse engineering: use high-priority rows to collect resolver trace or gateway evidence, then import the resulting trace/log files with `hns-topology import-browser-evidence`.

There is no standalone DANE row exporter in the production path. The first-class DANE workflow state is `compliance_stage`, with nonzero `stage:<stage>` Names postings generated from the canonical row store. Older DANE-specific facets such as DS records, needs DANE, stale TLSA, and DANE verified remain Names filters for compatibility and investigation.

`summary.broken` contains failure reason counts for the Names filter dropdown, not duplicated example rows. Example names for a failure reason come from the filtered Names collection.

`summary.top_resource_ips`, `summary.top_nameservers`, and `summary.known_hns_resolvers` are bounded diagnostic aggregates for the Compliance page. They expose shared nameserver IP evidence, delegation hosts, and public resolver inventory without creating additional static row collections.

Names collections are ordered by normalized name. The `all` collection is the canonical sorted row store. Nonzero visible Names filters, provider queues, and nonzero failure queues are compact ordinal postings into that row store rather than duplicate row payloads. Provider-type queues and zero-row filters are not exported; stale or zero-count filter URLs render as empty result sets in the browser. Static exact-name lookup binary-searches the sorted `all` collection by fetching only a small number of page files when `/api/name` is unavailable.

Compact canonical row arrays still include `expired`, `compliance_stage`, first NS/GLUE/SYNTH scalar fields, indirect `ns_handoff_*` bootstrap fields, DNSSEC/TLSA/DANE/HTTPS/strict-HNS/fallback status fields, resource hash, size, version, index height, and DNS/browser evidence paths for DANE generator handoff links and row-level compliance checklist diagnostics. Full resource arrays are embedded only when the collection is small enough to use full rows.

Name rows also expose the latest imported browser observation with `browser_*` fields. These are evidence summaries, not live-check replacements. In particular, `browser_fallback_reason = network_blocks_53` records device/client-network context and does not by itself move a name into the `resolver_fallback` compliance stage.

The row-level browser promotion policy is explicit. `browser_evidence_effect`, `browser_evidence_severity`, and `browser_action*` describe whether the latest browser observation is contextual, positive evidence to review, superseded by a newer live DANE check, or actionable. Browser port-53 blocking is always context-only. Browser-observed certificate expiry can produce `browser_action = renew_certificate` unless a newer live DANE-valid check supersedes it. Browser DANE verification without live crawler DANE verification produces a review action, not a compliance-stage change.

`summary.json` includes `static_tlsa_certificate_expired_names`, `browser_target_names`, and latest-browser-observation counts for `browser_evidence_names`, `browser_dane_verified_names`, `browser_network_blocks_53_names`, and `browser_certificate_expired_names` alongside the raw `browser_evidence_observations` count. The latest-observation counts are per name, so repeated device imports do not inflate the directory overview. Nonzero browser count keys and static TLSA certificate-expiry keys are also exported as Names filters.

IP address artifacts are keyed by URL-encoded address, for example `ip-addresses/44.231.6.183.json` or an encoded IPv6 literal. The index file contains the canonical query IP, `row_count`, `page_count`, `page_size`, row detail, field counts, columns, field-mask metadata, and a page path template. Page files contain compact postings for exported names whose `GLUE4`, `GLUE6`, `SYNTH4`, or `SYNTH6` values contain that address. When every row on a page has the same field mask, `row_encoding = name` stores only a JSON array of names. Mixed-field pages use `row_encoding = name_field_mask` with `[name, field_mask]` rows. They intentionally do not duplicate full or compact Names rows.

The `resource_ip` table is a derived index. Bootstrap and incremental indexing keep it current, but older or manually repaired databases must run `hns-topology rebuild-resource-ip --db <path>` before export. Export fails fast when this derived index is missing, stale, or missing its `(ip, name)` lookup index. Full rebuilds scan `resource_summary` once, bulk-load `resource_ip`, then create the lookup index after loading.

Provider-rule changes that only affect classification can be applied to an existing database with `hns-topology reclassify --db <path>`. That command scans stored compact `resource_summary` rows, recomputes `names.provider_guess` and `names.onchain_class`, updates provider-rule provenance, and refreshes `provider_summary` without re-fetching HSD resources or rebuilding `resource_ip`.

`summary.json` includes `compliance_stages`, `compliance_stage_counts`, and `next_actions` for the Compliance generator-handoff panel and filtered Name Audit queue context. Each action item contains a stage, count, primary `stage:<stage>` Names filter, filter link, and the DANE generator intent to use for matching row-level handoffs. The list is deliberately derived from stage counts and compact postings so it does not create duplicate row artifacts.

`summary.overview_explainers` carries metric definitions for downstream consumers and future UI surfaces. It replaces the former standalone FAQ data artifact and intentionally omits example rows; use the linked Names filters for examples.

`manifest.json` is the export contract for the static data directory. It records:

- `manifest_version`
- crawler version
- snapshot height, tip hash, source provenance, and provider-rule provenance
- summary counts copied from `summary.json`
- browser table export limits, total name count, exported name row count, and truncation status
- byte size and SHA-256 for each generated data artifact except the manifest itself

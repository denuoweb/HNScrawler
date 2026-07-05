# Architecture

Denuo HNS DANE Compliance is a periodic snapshot system for finding, triaging, and verifying Handshake names on the DNSSEC + TLSA path.

It has two deployment surfaces:

- Indexer VM: temporary or dedicated VM with a large disk for HSD, the compact working database, live checks, and static site generation.
- Website VM: small public web server that serves generated static files.

The website VM does not need HSD or the HSD datadir. High-cardinality lookup paths should use compact static indexes instead of duplicated full row sets.

## Data Flow

```text
HSD node
  -> current name state
  -> stopped-node JSONL state export
  -> compact SQLite compliance DB
  -> optional live DNS/DNSSEC/TLSA/HTTPS checks for promising names
  -> static JSON exports
  -> static compliance site
  -> release archive manifest, site tarball, and SQLite backup
  -> rsync to denuowebsite-vm
```

## Boundary

The crawler stores:

- current name state fields
- resource hashes
- record type summaries
- NS, GLUE4, GLUE6, SYNTH4, SYNTH6 summaries
- DS/TXT presence
- provider guesses from versioned rules
- provider rule patterns used for each materialized provider bucket
- compact live-check status
- explicit failure reasons
- recent reorg metadata

The crawler does not store:

- full HTTP response bodies
- arbitrary subdomain results
- full delegated zone contents
- complete DNS history
- private keys or account state

## HSD RPC Notes

HSD documents `getnameresource <name>` as the way to inspect resource records for a name. HSD also documents node `getnames`, but warns that it has no pagination and is mainly for debugging on regtest or testnet. The current code keeps HSD RPC access behind `HsdRpcClient` for smoke runs and incremental checks, and uses a stopped-node JSONL exporter for production-scale bootstrap so classification, exports, and site generation do not depend on unpaginated RPC.

Production-scale bootstrap should use `EXPORT_FORMAT=compact scripts/export-hsd-jsonl.sh` followed by `hns-topology bootstrap-jsonl`, or the combined remote `PIPELINE_MODE=extract-jsonl` mode. Each production JSONL line contains either `{"snapshot_meta": {...}}` or `{"compact_name": {...}}`, where the compact row already contains the resource summary fields needed by the report. `EXPORT_FORMAT=full` is kept for debugging and emits `name_info` plus full decoded `resource` JSON.

## Reorg Handling

The compact DB keeps recent rollback metadata:

- `block_history.height`
- `block_history.block_hash`
- `block_history.changed_names`
- `changed_name_rollbacks.previous_resource_hash`
- `changed_name_rollbacks.previous_classification`
- `changed_name_rollbacks.previous_live_status`
- `changed_name_rollbacks.previous_name_row`
- `changed_name_rollbacks.previous_resource_summary`
- `changed_name_rollbacks.block_hash_at_height`

For nightly or weekly reports, keeping the last few hundred blocks is enough practical safety. If a stored height hash no longer matches HSD, `hns-topology reorg-check --rollback` restores changed names from the highest affected height downward, removes affected block metadata, and leaves the index ready to replay names changed in the new canonical blocks.

## Live Checks

Live checks are intentionally limited to promising names:

- `DIRECT_SYNTH`
- `DELEGATED_WITH_GLUE`
- `DNSSEC_CANDIDATE`
- `DANE_CANDIDATE`
- recently updated names
- previously working names
- user-submitted names, once that queue exists

Checks are rate-limited and store status metadata plus DNS evidence observations. Each live-check run records its candidate count, checked count, concurrency, minimum inter-check delay, timeout, recheck window, resolver setting, and start/finish timestamps in `snapshot_meta`. For names with strict-HNS bootstrap addresses, the scanner also performs direct DNSSEC-enabled, non-recursive probes against the bootstrap nameserver for A, AAAA, TLSA, and DNSKEY data. These observations are append-only and are exported as per-name evidence JSON.

External workers can submit the same evidence JSON through `hns-topology import-dns-evidence`. This gives the project a crowd-sourced path: independent scanners can publish actual RRset observations with `source` and `source_id`, while the public report shows the latest observation per query/source.

## DANE Compliance Pipeline

The public site is organized around DANE progress and generator handoff, not just raw classification. On-chain data and live-check results collapse into one exported `compliance_stage` per active name. Legacy counters such as DS records, DNSSEC candidates, strict HNS working, and needs DANE remain as search and summary facets, but the stage is the canonical workflow state.

The stage vocabulary is deliberately mutually exclusive:

- `dane_verified`: DNSSEC, TLSA, and HTTPS certificate/SPKI matched.
- `tlsa_gap`: DNSSEC is present or live-valid, but matching TLSA is missing or unproven.
- `stale_tlsa`: TLSA exists but no longer matches the served certificate/public key.
- `dnssec_broken`: parent DS, delegated DNSKEY, or signatures need repair.
- `missing_glue`: delegation lacks parent-side nameserver bootstrap addresses.
- `bootstrap_ready`: HNS bootstrap exists; sign DNSSEC, publish DS, and add TLSA.
- `resolver_fallback`: strict HNS bootstrap failed and fallback resolver data was required.
- `service_blocked`: HTTPS or another live-check condition blocked DANE proof.
- `non_actionable`: expired, parked/default, resolver infrastructure, empty, or unsupported resources.

Name Audit is the canonical search surface. Rows carry that stage plus enough status to derive one next step:

- `tlsa_gap`: generate TLSA.
- `missing_glue`: create or review NS/GLUE setup.
- `dnssec_broken`: regenerate/check DS.
- `stale_tlsa`: replace TLSA from the served certificate/public key.
- `bootstrap_ready`: plan DNSSEC and DANE setup.
- `dane_verified`: show the DANE compliance badge.

Expanded rows lead with a Compliance Checklist: parent delegation, HNS bootstrap, DNSSEC chain, TLSA owner, HTTPS SPKI match, and resolver fallback. The checklist reuses exported row fields instead of adding a second audit artifact, so each name reads as a DANE audit result while the static data model stays compact.

The DANE Record Generator is the record-production surface. Report action links are built only through `generator_handoff.js`, which defines the supported `/dane-generator/` query contract. The stable fields are `domain`, `domain_type`, `intent`, `mode`, `nameserver`, `ns4`, and `ns6`; evidence-backed fields `a`, `aaaa`, `port`, `dnskey`, `pem`, and `cert` are included when present on the row or supplied by the caller.

Large Names collections use compact row arrays to keep the public artifact set small. Compact rows still include `compliance_stage` plus first NS/GLUE/SYNTH scalar fields so generator handoff links can prefill the authoritative nameserver path without reintroducing separate Providers, DANE, or Broken-pages exports.

## Provider Rules

Provider classification is intentionally rule-based for the first production release. The committed JSON rules are sorted by priority and can match:

- nameserver suffixes
- nameserver regular expressions
- direct or glue IP CIDR ranges
- self-hosted delegation, where an NS name is equal to or below the HNS name

Generated `provider_summary` rows expose the matching criteria as stable strings such as `suffix:namebase.io`, `regex:<pattern>`, `cidr:192.168.0.0/16`, and `self_hosted`. The summary is still a best-effort provider guess, not proof of ownership or service relationship.

Strict HNS address discovery uses only addresses that can be bootstrapped from the HNS resource:

- `SYNTH4` / `SYNTH6` are treated as compact authoritative nameserver bootstrap addresses, not website addresses.
- `GLUE4` / `GLUE6` are treated as authoritative nameserver bootstrap addresses, not website addresses.
- Delegated names without GLUE or SYNTH bootstrap cannot pass strict HNS address discovery unless a future resolver path can prove in-bailiwick glue another way.

The `doh_fallback_status` field records whether the checker had to use the configured fallback resolver path after strict HNS discovery failed. The historical field name is retained for export stability; the status means resolver fallback was required and is not proof of a specific DoH transport by itself.

HTTPS certificate capture is independent from WebPKI validation. The checker first tries a normal verified TLS connection. If WebPKI validation fails, it retries with certificate verification disabled only to capture the peer certificate/SPKI for TLSA matching. A matching TLSA record can therefore produce `dane_status = valid` even when `https_status = tls_unverified`.

For names with on-chain DS records, live checks compare the HNS resource DS data to delegated DNSKEY records and validate the DNSKEY RRset signature when an RRSIG is present. DANE is only marked valid when DNSSEC status is valid and the exact TLSA association matches the HTTPS certificate/SPKI from the indexer vantage. That exported status is a direct indexer DANE result, not a browser compatibility proof.

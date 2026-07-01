# Architecture

Denuo HNS Topology Report is a periodic snapshot system.

It has two deployment surfaces:

- Indexer VM: temporary or dedicated VM with a large disk for HSD, the compact working database, live checks, and static site generation.
- Website VM: small public web server that serves generated static files and compressed downloads.

The website VM does not need HSD, does not need the HSD datadir, and does not serve a live API.

## Data Flow

```text
HSD node
  -> current name state
  -> current resource JSON per name
  -> compact SQLite topology DB
  -> optional live DNS/DNSSEC/TLSA/HTTPS checks for promising names
  -> static JSON/CSV/SQLite.gz exports
  -> static report site
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

HSD documents `getnameresource <name>` as the way to inspect resource records for a name. HSD also documents node `getnames`, but warns that it has no pagination and is mainly for debugging on regtest or testnet. The current code keeps HSD access behind `HsdRpcClient` and supports streaming JSONL pre-extracted input so the production name-source step can be replaced without changing classification, exports, or site generation.

Production-scale bootstrap should prefer `hns-topology bootstrap-jsonl` once a direct or chunked HSD state extractor is available. Each JSONL line contains either `{"snapshot_meta": {...}}` or one name object with `name_info` and `resource`.

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

Checks are rate-limited and store only status metadata.

Strict HNS address discovery uses only addresses that can be bootstrapped from the HNS resource:

- `SYNTH4` / `SYNTH6` are treated as website addresses.
- `GLUE4` / `GLUE6` are treated as authoritative nameserver bootstrap addresses, not website addresses.
- Delegated names without GLUE cannot pass strict HNS address discovery unless a future resolver path can prove in-bailiwick glue another way.

The `doh_fallback_status` field records whether the checker had to use the configured fallback resolver path after strict HNS discovery failed. In production that resolver can be DoH-backed, but the status means fallback resolution was required; it is not proof of a specific transport by itself.

HTTPS certificate capture is independent from WebPKI validation. The checker first tries a normal verified TLS connection. If WebPKI validation fails, it retries with certificate verification disabled only to capture the peer certificate/SPKI for TLSA matching. A matching TLSA record can therefore produce `dane_status = valid` even when `https_status = tls_unverified`.

For names with on-chain DS records, live checks compare the HNS resource DS data to delegated DNSKEY records and validate the DNSKEY RRset signature when an RRSIG is present. DANE is only marked valid when DNSSEC status is valid and the TLSA association matches the HTTPS certificate/SPKI.

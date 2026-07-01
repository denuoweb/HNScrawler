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

HSD documents `getnameresource <name>` as the way to inspect resource records for a name. HSD also documents node `getnames`, but warns that it has no pagination and is mainly for debugging on regtest or testnet. The current code keeps HSD access behind `HsdRpcClient` and also supports fixture/pre-extracted input so the production name-source step can be replaced without changing classification, exports, or site generation.

## Reorg Handling

The compact DB keeps recent rollback metadata:

- `block_history.height`
- `block_history.block_hash`
- `block_history.changed_names`
- `changed_name_rollbacks.previous_resource_hash`
- `changed_name_rollbacks.previous_classification`
- `changed_name_rollbacks.previous_live_status`
- `changed_name_rollbacks.block_hash_at_height`

For nightly or weekly reports, keeping the last few hundred blocks is enough practical safety. If a stored height hash no longer matches HSD, roll back changed names from the highest affected height downward, then replay names changed in the new canonical blocks.

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


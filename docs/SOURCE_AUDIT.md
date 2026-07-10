# Source Audit

This project currently depends on these protocol and implementation assumptions.

## HSD

- HSD is the authoritative local source for current Handshake name state in this pipeline.
- `getnameresource <name>` is documented for viewing resource records for a name.
- HSD resource record types used by this project are `DS`, `NS`, `GLUE4`, `GLUE6`, `SYNTH4`, `SYNTH6`, and `TXT`.
- Node `getnames` exists, but the official API docs warn that it has no pagination and is mainly useful for debugging on regtest/testnet. Production mainnet bootstrapping must keep the name-source step replaceable.
- `scripts/hsd-export-names-jsonl.js` is a production bootstrap extractor that opens HSD's chain/tree state and streams `NameState` rows to JSONL. Its production default is `EXPORT_FORMAT=compact`, which emits pre-summarized `compact_name` rows for this report instead of full HSD name/resource JSON. Run it through `scripts/export-hsd-jsonl.sh`, which stops the local `hsd` service by default before reading the datadir.
- HSD `prefix` determines the datadir. The indexer service pins it to `/mnt/hnscrawler/hsd` so chain data lands on the attached indexer disk.
- HSD mainnet RPC defaults to port `12037`; regtest uses `14037`.

Sources:

- https://hsd-dev.org/guides/resource-records.html
- https://hsd-dev.org/api-docs/
- https://github.com/handshake-org/hsd

## DANE/TLSA

- RFC 6698 defines TLSA RDATA as certificate usage, selector, matching type, and certificate association data.
- RFC 6698 defines matching type `0` as exact selected content, `1` as SHA-256, and `2` as SHA-512.
- RFC 7671 provides operational guidance and symbolic names such as DANE-EE, SPKI, and SHA2-256.
- The first production web-DANE profile should prefer `3 1 1` where the operational environment supports it.

Sources:

- https://datatracker.ietf.org/doc/html/rfc6698
- https://datatracker.ietf.org/doc/html/rfc7671

## Current Implementation Limits

- Static analysis records HNS DS and TLSA material from resource data. It does not store full delegated chains, denial-of-existence proofs, arbitrary zone contents, or HTTPS certificate observations.
- Incremental catch-up reads `last_indexed_height`, scans detailed HSD block JSON through the target height, records empty blocks for reorg safety, and refuses ranges above `INCREMENTAL_MAX_BLOCKS`. Single-block scans decode plaintext names when covenant items include them and resolve name hashes with HSD `getnamebyhash`. Empty single-block scans and unresolved name hashes fail by default; use `ALLOW_EMPTY_BLOCK_SCAN=1` only for known-empty blocks and `ALLOW_UNRESOLVED_NAME_HASHES=1` only for deliberate best-effort runs.
- The JSONL exporter depends on HSD internal module paths and serialized `NameState` / `Resource` formats. Re-run an `EXPORT_LIMIT` smoke export after HSD upgrades before a full production export. Use `EXPORT_FORMAT=full` only when debugging an HSD format mismatch.

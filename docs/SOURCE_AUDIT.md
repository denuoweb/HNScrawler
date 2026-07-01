# Source Audit

This project currently depends on these protocol and implementation assumptions.

## HSD

- HSD is the authoritative local source for current Handshake name state in this pipeline.
- `getnameresource <name>` is documented for viewing resource records for a name.
- HSD resource record types used by this project are `DS`, `NS`, `GLUE4`, `GLUE6`, `SYNTH4`, `SYNTH6`, and `TXT`.
- Node `getnames` exists, but the official API docs warn that it has no pagination and is mainly useful for debugging on regtest/testnet. Production mainnet bootstrapping must keep the name-source step replaceable.
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

- DNSSEC validation is represented as status fields, but full DS-to-DNSKEY validation is not complete in the first code slice.
- Incremental changed-name extraction from decoded blocks is best effort; production should verify the exact HSD verbosity response on the indexer before relying on block scans.
- HSD `getnames` may be unsuitable for a 13-million-name mainnet bootstrap. The code path is isolated so a chunked state extractor can replace it.

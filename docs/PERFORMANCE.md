# HSD Bootstrap Performance

The production bootstrap should read HSD's name tree directly, not JSON-RPC.

Audit target: upstream `handshake-org/hsd` commit `698e252ebc7b5c1dd0a9587e342fdd153d020ae4`.

Relevant HSD structures:

- `ChainDB` owns an Urkel `Tree` and exposes the current transaction as `chain.db.txn`.
- `getnames` iterates `txn.iterator()`, decodes every `NameState`, calls `ns.getJSON(height, network)`, appends each object to an array, then returns the full array through RPC.
- `NameState` stores the name, renewal height, serialized resource data, owner/value fields, and status fields. For this report we only need name, name hash, state, renewal, current expiration, and resource data.
- `Resource.decode(ns.data)` exposes only the records this report summarizes: `DS`, `NS`, `GLUE4`, `GLUE6`, `SYNTH4`, `SYNTH6`, and `TXT`.

The fast path is:

1. Stop `hsd` so the datadir is stable.
2. Run `scripts/export-hsd-jsonl.sh` with `EXPORT_FORMAT=compact`.
3. The Node exporter iterates `chain.db.txn` and writes one `compact_name` JSONL row per `NameState`.
4. Python `bootstrap-jsonl` batches compact rows into SQLite with precomputed resource summaries.

This avoids:

- HSD's unpaginated `getnames` RPC array.
- full `NameState.getJSON()` output for fields the site never uses.
- Python decoding and summarizing every resource from full JSON.
- repeated regex/CIDR compilation during provider classification.
- per-name SQLite insert calls.

Tuning knobs:

- `EXPORT_FORMAT=compact` for production, `full` only for debugging.
- `JSONL_BOOTSTRAP_BATCH_SIZE=5000` by default. Increase on a larger indexer VM if memory is comfortable.
- `EXPORT_LIMIT=<n>` for smoke runs.

Headers are not enough for this report. Block headers prove chain order and work, but HNS name resources are current state in the name tree. The report needs the current resource bytes to classify NS, GLUE, DS, SYNTH, TXT, DANE candidacy, and provider patterns.

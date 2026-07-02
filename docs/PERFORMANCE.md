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
- per-row dataclass construction on compact imports.
- repeated JSON encoding of empty resource-summary arrays.

Tuning knobs:

- `EXPORT_FORMAT=compact` for production, `full` only for debugging.
- `JSONL_BOOTSTRAP_BATCH_SIZE=5000` by default. Increase on a larger indexer VM if memory is comfortable.
- `EXPORT_LIMIT=<n>` for smoke runs.

Synthetic compact import profiling on 100,000 rows dropped from 11.80 seconds to 6.53 seconds after direct tuple batching, sparse JSON array handling, cached provider IP parsing, and provider-rule short-circuiting. Real mainnet speedup depends on HSD tree I/O and the share of names with non-empty resources, but the compact path keeps the Python side close to SQLite write cost.

Headers are not enough for this report. Block headers prove chain order and work, but HNS name resources are current state in the name tree. The report needs the current resource bytes to classify NS, GLUE, DS, SYNTH, TXT, DANE candidacy, and provider patterns.

## Full-Node Sync Bottleneck Audit

The production blocker is not the Python import path. It is initial HSD chain replay before the stopped-node tree export can run.

The relevant HSD hot path is:

- `Chain#updateInputs()` is used below the mainnet checkpoint height. It skips historical script verification, but it still spends inputs, verifies covenants, and adds every transaction output to the UTXO view.
- `CoinView#spendInputs()` reads transaction inputs in fixed batches of four before marking them spent.
- `Chain#verifyCovenants()` mutates `CoinView.names` in transaction order. That order is consensus-sensitive and must remain deterministic.
- `ChainDB#_saveNames()` writes each changed `NameState` independently through `txn.insert(nameHash, ns.encode())` or `txn.remove(nameHash)`.
- Urkel `Transaction#insert()` and `remove()` each perform an independent trie walk, resolving hash nodes and path-copying replacement nodes.
- Urkel only commits the name tree on `network.names.treeInterval` boundaries, which is 36 blocks on mainnet.

Increasing peer count or vCPU count does not remove this bottleneck. HSD chooses loader peers for block sync, but historical block connection is still a serial state transition. A larger VM helps only until the single HSD replay thread, cache behavior, or small async DB read batches become the limiter.

## Largest Practical 10x Target

The fundamental mismatch is using a general full node as the bootstrap engine for a report that only needs current name-resource state.

HSD must maintain the full UTXO set because it is a validating node. The topology report does not need ordinary coin UTXOs, wallet state, mempool policy, historical blocks, or full transaction indexes. It needs:

- accepted block order
- name covenant transitions
- enough covenant-bearing outpoint data to apply name-state transitions
- current `NameState.data` resource bytes
- recent block hashes for reorg detection

A report-specific bootstrapper can therefore track only name covenant outpoints and name states instead of spending every ordinary transaction input. For historical checkpointed blocks, that avoids most UTXO read/write work while preserving the data the report actually consumes.

The safe shape is:

1. Keep the current HSD path as the provenance baseline and production fallback.
2. Build a separate name-only historical replay experiment on a cloned disk or temporary VM.
3. Parse accepted blocks, maintain a compact map of name-covenant outpoints, apply name covenant transitions in block/transaction/output order, and write compact report rows directly.
4. Compare the experiment against HSD exports at fixed heights and at the final tip. For stronger validation, compute or import the Urkel root and compare tree roots on 36-block boundaries.
5. Promote it only after repeated equality checks against HSD on the same chain data.

This is different from patching HSD's live full-node replay. HSD cannot safely skip non-name UTXOs and still remain a general validating node. The speedup comes from changing the bootstrapper's contract, not from making HSD consensus code less complete.

The first sidecar implementation is `scripts/export-hsd-nameonly-jsonl.sh`, backed by `scripts/hsd-nameonly-replay-jsonl.js`. It reads accepted blocks through local HSD RPC so it can run beside a syncing node, reuses HSD `NameState` for state/expiration math, writes compact JSONL rows compatible with `bootstrap-jsonl`, and marks its provenance as `hsd_nameonly_rpc_compact_experimental`.

## Lower-Risk Experiments

These can be benchmarked, but they are not expected to produce a 10x win by themselves:

- Increase `CoinView#spendInputs()` read batch size from 4 to 16 or 32 on a copied datadir and compare connected blocks per hour.
- Add per-block prefetch of initial name states before covenant verification, while preserving ordered mutation.
- Add an Urkel `applyBatch()` / `insertMany()` experiment that sorts changed name hashes and updates touched trie paths with better locality.
- Benchmark Urkel file cache policy under historical replay with larger cache sizes and locality-aware eviction.

Any HSD or Urkel change that affects name-state writes must be validated mechanically by comparing resulting tree roots against unmodified HSD. That validation can be automated; it does not require manual bit-by-bit code auditing, but it does require exact root equality before trusting the optimized path.

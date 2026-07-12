# Live Website Directory

The live website directory is an independent, low-cost service on `denuoweb-vm`. It is not part of HSD indexing, static topology generation, the weekly production cycle, or either topology publish script.

## Separation

The weekly indexer publishes its read-only topology snapshot to:

```text
/mnt/hns-topology/topology.sqlite
```

The live service reads that snapshot and owns separate state:

```text
/mnt/hns-topology/live-directory/data/live.sqlite
/mnt/hns-topology/live-directory/public/
/var/www/denuoweb/hns-live -> /mnt/hns-topology/live-directory/public
```

Replacing the weekly topology database or `/mnt/hns-topology/site` does not replace live probe history or the `/hns-live/` public tree.

The live-directory deployment also installs an explicit `hns.denuoweb.com` Nginx location for `/hns-live/` and refreshes the topology directory `index.html` plus its application asset. This lets the overview consume current live DNS/TLSA evidence without running the topology build or replacing its data files.

The live database keeps one current status row per discovered root/host pair and upserts it on later checks; it does not retain raw DNS packets, HTTP bodies, certificates, or a row per probe attempt. Name details use compact sharded static lookups regenerated on export from those existing rows, so the detail view adds no SQLite tables or probe-history growth.

The evidence queue compares the topology tip, height, provider-rule hash, and generation timestamp first. Its full candidate refresh is intentionally separate from the continuous probe cycle: `LIVE_SYNC_TOPOLOGY=1` requests it explicitly. This prevents a changed weekly snapshot from delaying shared-delegation and HNS-handoff probes while the multi-gigabyte topology database is traversed.

## Candidate Policy

The scanner imports active, actionable roots with direct HNS nameserver IP evidence from SYNTH or GLUE. It also treats a shared delegation host as a first-tier website signal: a host serving 2–250 current HNS roots contributes its member roots to the broad sweep, with per-host pacing. This catches hosted groups such as `ns1.trapify` without treating the largest generic parking clusters as likely websites. A DNSSEC-signed delegation whose NS host is itself under an HNS root with actionable SYNTH/GLUE is also promoted: the probe first resolves that HNS NS handoff, then queries the delegated zone. This captures managed namespace patterns such as HeadlessDomains without embedding namespace names. DS alone remains too broad to establish likely website service. The scanner creates only the root apex candidate by default.

Within the same due tier, the initial discovery order is:

1. exact-host TLSA evidence, including evidence-backed subdomains;
2. other stored DNS subdomain evidence;
3. DS roots with a global SYNTH/GLUE bootstrap;
4. unsigned roots with a global SYNTH/GLUE bootstrap;
5. recognized external-provider delegations whose NS address must be resolved at probe time.

The delegation index is refreshed independently from the published nameserver shards on `denuoweb-vm`; it does not run in the weekly indexer or deployment path. TLSA-unobserved remains a broad remediation queue rather than a high-confidence liveness signal.

The topology overview's `DS + TLSA observed by live scan` card is sourced from the live-directory export. It counts only active roots whose current live authoritative DNS result has a matching parent DS, valid DNSSEC, and a secure TLSA response. Its coverage is shown alongside the count; it is not a whole-chain TLSA total and does not prove certificate matching.

Subdomain candidates require concrete evidence:

- a stored `_443._tcp.<host>` TLSA owner;
- an A, AAAA, CNAME, HTTPS, or SVCB owner in stored DNS evidence;
- an owner returned in a later authoritative answer.

`www.<root>` is not guessed. It is scanned only if DNS evidence names it. The service does not attempt zone transfers, NSEC walking, word lists, or recursive subdomain crawling.

Known parking infrastructure, public HNS resolvers, expired roots, private nameserver bootstrap addresses, and non-global website addresses are excluded from active probing.

## Broad Sweep

The broad sweep is separate from the evidence queue. It streams roots from the read-only topology snapshot with persistent cursors, so it does not create one `candidates` or `host_status` row for every root. Its priority order is:

1. members of shared delegation hosts with 2–250 roots, especially DNSSEC-signed HNS NS handoffs;
2. DS roots with direct SYNTH or GLUE bootstrap;
3. other direct SYNTH or GLUE bootstrap roots;
4. DS delegations whose nameserver address must be resolved;
5. other delegations whose nameserver address must be resolved.

The sweep records one compact `sweep_coverage` row per root: resource hash, signal tier, checked time, outcome, and next-review time. A root is promoted to the detailed queue and public directory only after an HTTP or authenticated HTTPS endpoint responds. This preserves full liveness coverage without turning the live database or static directory into a second multi-gigabyte topology snapshot.

Broad probes first resolve A/AAAA and try both HTTP and HTTPS. When either endpoint responds, the same probe performs DNSSEC and TLSA collection before storing the result. This keeps unreachable delegated roots inexpensive while ensuring endpoint scans supply current TLSA evidence.

Production uses 50 workers, a global ceiling of ten target starts per second, and per-authority pacing. HTTP 429/503 responses increase per-authority delay; repeated DNS failures place only shared authority groups on a compact cooldown. The delegation-index timer runs independently every hour and reads the published static shard data only when it has changed. The probe service runs another cycle 30 seconds after the prior one completes, independent of the weekly indexer and deploy jobs.

## Probe Semantics

For each due host the service:

1. Uses a global SYNTH/GLUE address directly, or resolves an admitted delegation's NS hostname, then issues authoritative A, AAAA, DNSKEY, and exact-host `_443._tcp` TLSA queries.
2. Validates the root DS/DNSKEY relationship and relevant RRSIGs when DS is present.
3. Tries bounded HTTP requests on port 80 with the correct `Host` header.
4. Tries bounded HTTPS requests on port 443 with the correct SNI.
5. Captures only response metadata and certificate hashes; HTTP bodies are not retained.
6. Treats HTTPS as authenticated when WebPKI validates or a secure supported TLSA record matches the served leaf certificate/SPKI.

Public categories are:

- `https`: an HTTP response was received over authenticated HTTPS;
- `http_only`: HTTP responded but authenticated HTTPS did not;
- `offline`: neither authenticated HTTPS nor HTTP responded, including HTTPS-only responses that could not be authenticated.

`LIVE_FALLBACK_RESOLVER` may name a trusted recursive resolver IP for NS-host and external CNAME resolution. When unset, the VM's system resolver is used. Resolved addresses are still restricted to global unicast before any authoritative DNS or web connection is attempted.

The public directory separates HTTPS endpoints, HTTP endpoints, and no-endpoint targets. A previously listed host remains degraded after one failed cycle and moves to the no-endpoint category after a second consecutive failure. Confirmed offline candidates use increasing retry intervals, while listed sites are checked every seven days. A changed resource and candidates first seen in the newest topology refresh run ahead of routine weekly rechecks and the older discovery backlog.

## Local Commands

These commands never start HSD:

```bash
hns-live-directory init --db data/live.sqlite
hns-live-directory sync --topology-db data/topology.sqlite --db data/live.sqlite
hns-live-directory plan --db data/live.sqlite
hns-live-directory scan --db data/live.sqlite --limit 100
hns-live-directory sweep --topology-db data/topology.sqlite --db data/live.sqlite --limit 500
hns-live-directory index-delegations --db data/live.sqlite --topology-site public
hns-live-directory export --db data/live.sqlite --out public-live
hns-live-directory validate --public-dir public-live
```

The service command combines them:

```bash
scripts/run-live-directory.sh
```

`plan` is the no-network evidence-queue audit. A scan limit of zero is explicitly unlimited; production runs the high-signal shared-delegation sweep before a 20-candidate detailed-evidence tranche. The generic DS/bootstrap sweep is intentionally excluded from the continuous timer because its unindexed snapshot scan can block priority work; it remains available through the explicit `sweep --tiers ...` command while its indexed backlog path is developed. The sweep excludes known parking and public-resolver bootstrap addresses. It samples a new shared authority up to three times, expands immediately when that authority resolves, and places repeatedly unreachable authority groups on a compact cooldown rather than repeatedly probing every root behind them. The cache contains shared authority keys only; unique roots remain compact per-root coverage records.

## Denuoweb VM Deployment

Review without changing the VM:

```bash
DRY_RUN=1 scripts/gcloud-deploy-live-directory.sh
```

Install or update the standalone repository, venv, static path, service, and continuous timer:

```bash
CONFIRM_LIVE_DIRECTORY_DEPLOY=1 scripts/gcloud-deploy-live-directory.sh
```

Deployment only initializes and exports the existing live database; it does not run a topology sync or website probe. The timer's first dedicated cycle begins after two minutes. To start the configured sweep immediately during an intentional rollout:

```bash
CONFIRM_LIVE_DIRECTORY_DEPLOY=1 RUN_LIVE_DIRECTORY_NOW=1 scripts/gcloud-deploy-live-directory.sh
```

Operational status:

```bash
gcloud compute ssh denuoweb-vm --zone us-west1-b --project denuo-web-site --command \
  "systemctl status hns-live-directory.timer --no-pager; sudo journalctl -u hns-live-directory.service -n 100 --no-pager"
```

The service runs as `den:www-data`, uses `Nice=10`, idle I/O scheduling, a 50 percent CPU quota, a 768 MB memory ceiling, and a single-instance file lock.

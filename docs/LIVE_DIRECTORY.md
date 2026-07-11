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

The live-directory deployment also installs an explicit `hns.denuoweb.com` Nginx location for `/hns-live/` and refreshes only the topology directory `index.html` navigation. It does not run the topology build or replace its data files.

Daily cycles compare the topology tip, height, provider-rule hash, and generation timestamp first. Candidate roots are refreshed only when that fingerprint changes; unchanged daily runs do not scan the multi-gigabyte topology database. Full refreshes select indexed promising on-chain classes before joining resource details and stream rows into the live database instead of retaining the topology candidate set in memory.

## Candidate Policy

The scanner imports active, actionable roots with direct HNS nameserver IP evidence from SYNTH or GLUE. It also admits lower-priority no-GLUE delegations when stored TLSA evidence or a recognized external DNS provider makes the root a useful candidate; the probe resolves those individual NS hostnames before issuing authoritative queries. DS raises the priority of a root that has another admission signal, but DS alone is too broad to establish likely website service. An aggregate delegation-host count alone is not treated as website evidence. The scanner creates only the root apex candidate by default.

Within the same due tier, the initial discovery order is:

1. exact-host TLSA evidence, including evidence-backed subdomains;
2. other stored DNS subdomain evidence;
3. DS roots with a global SYNTH/GLUE bootstrap;
4. unsigned roots with a global SYNTH/GLUE bootstrap;
5. recognized external-provider delegations whose NS address must be resolved at probe time.

The overview's aggregated Delegation Hosts table is useful for infrastructure analysis, but it is not itself website evidence. TLSA-unobserved is a broad remediation queue rather than a high-confidence liveness signal.

`DS + TLSA observed` means the topology database has DNSSEC and stored TLSA evidence. It does not prove that an HTTPS server is currently answering, and its absence does not rule out either an HTTP-only site or a WebPKI HTTPS site. Public liveness categories are assigned only by the active probes below.

Subdomain candidates require concrete evidence:

- a stored `_443._tcp.<host>` TLSA owner;
- an A, AAAA, CNAME, HTTPS, or SVCB owner in stored DNS evidence;
- an owner returned in a later authoritative answer.

`www.<root>` is not guessed. It is scanned only if DNS evidence names it. The service does not attempt zone transfers, NSEC walking, word lists, or recursive subdomain crawling.

Known parking infrastructure, public HNS resolvers, expired roots, private nameserver bootstrap addresses, and non-global website addresses are excluded from active probing.

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
- `repair`: HTTPS responded but could not be authenticated and HTTP did not respond.

`LIVE_FALLBACK_RESOLVER` may name a trusted recursive resolver IP for NS-host and external CNAME resolution. When unset, the VM's system resolver is used. Resolved addresses are still restricted to global unicast before any authoritative DNS or web connection is attempted.

Offline hosts are not listed. A previously listed host remains degraded after one failed cycle and is removed after a second consecutive failure. Confirmed offline candidates use increasing retry intervals, while listed sites are checked every seven days. A changed resource and candidates first seen in the newest topology refresh run ahead of routine weekly rechecks and the older discovery backlog.

## Local Commands

These commands never start HSD:

```bash
hns-live-directory init --db data/live.sqlite
hns-live-directory sync --topology-db data/topology.sqlite --db data/live.sqlite
hns-live-directory plan --db data/live.sqlite
hns-live-directory scan --db data/live.sqlite --limit 100
hns-live-directory export --db data/live.sqlite --out public-live
hns-live-directory validate --public-dir public-live
```

The service command combines them:

```bash
scripts/run-live-directory.sh
```

`plan` is the no-network candidate and due-queue audit. A scan limit of zero is explicitly unlimited; production defaults to 100 candidates per daily cycle.

## Denuoweb VM Deployment

Review without changing the VM:

```bash
DRY_RUN=1 scripts/gcloud-deploy-live-directory.sh
```

Install or update the standalone repository, venv, static path, service, and daily timer:

```bash
CONFIRM_LIVE_DIRECTORY_DEPLOY=1 scripts/gcloud-deploy-live-directory.sh
```

Deployment initializes and exports an empty/current directory without issuing website probes. The timer's first probe cycle is delayed by one hour. To run a bounded cycle immediately during an intentional rollout:

```bash
CONFIRM_LIVE_DIRECTORY_DEPLOY=1 RUN_LIVE_DIRECTORY_NOW=1 scripts/gcloud-deploy-live-directory.sh
```

Operational status:

```bash
gcloud compute ssh denuoweb-vm --zone us-west1-b --project denuo-web-site --command \
  "systemctl status hns-live-directory.timer --no-pager; sudo journalctl -u hns-live-directory.service -n 100 --no-pager"
```

The service runs as `den:www-data`, uses `Nice=10`, idle I/O scheduling, a 50 percent CPU quota, a 768 MB memory ceiling, and a single-instance file lock.

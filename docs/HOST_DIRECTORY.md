# Host Directory

HNScrawler publishes a live HNS host directory, not just a root-name list.

## Core Rule

```text
HNS root name != website host
```

A root name is the HNS authority and resource container:

```text
crewball
forever
denuoweb
mercenary
```

A host is the actual website or service target:

```text
crewball
www.crewball
jaron.crewball
impervious.forever
www.denuoweb
```

The public directory is host-level. Root data remains first-class because it supplies HNS authority, provider classification, NS/GLUE/SYNTH/DS/TLSA resource data, DNSSEC bootstrap context, and diagnostics.

## Apex Failure

Apex failure is not root failure. If `crewball` has no proven live HTTPS service, the crawler records that as an apex-host result only. It can still discover and publish `jaron.crewball` when browser evidence or crawler checks prove that host is live.

Registry-style or delegation-style roots work the same way. The [Forever Domains ecosystem](https://foreverdomains.io/about/index.html) describes `.forever` as an HNS-backed root while browser targets can live below it, such as `impervious.forever`. HNScrawler must therefore map hosts to roots by longest known root suffix instead of assuming the root apex is the website.

## Candidate Sources

Host candidates are stored in `host_candidates` and keyed by `(root_name, host, source)`.

Stable sources:

- `default_apex`
- `default_www`
- `browser_evidence`
- `resource_tlsa_owner`
- `dns_evidence_tlsa_owner`
- `previous_live_host`
- `operator_import`
- `link_evidence`

Default apex and `www.<root>` candidates are generated only for active roots with actionable bootstrap material. Browser traces can add arbitrary subdomain hosts, but the host must map to a known root. TLSA owner names such as `_443._tcp.jaron.crewball.` can also create host candidates.

## Live Checks

`hns-topology live-check-hosts` checks hosts, not roots.

For each host:

- A/AAAA owner: `<host>`
- TLSA owner: `_443._tcp.<host>`
- HTTPS SNI: `<host>`
- Directory URL: `https://<host>/`
- DNSSEC key owner: the root/zone name for the first implementation

DANE is valid only when the trust path is valid, the address and TLSA association are secure when DNSSEC is expected, and the live certificate/SPKI matches the TLSA association.

## Directory Inclusion

The default `host-directory.json` and optional `site-directory.csv` include a host when:

- `host_live_status.dane_status = valid`
- or `host_live_status.https_status` is `working` or `tls_unverified`
- or latest browser evidence says the host loaded or DANE verified

Strict-ready roots produce candidates, not live directory entries.

Directory rows include `root_name`, `host`, `url`, `directory_status`, provenance fields (`evidence_source`, `evidence_confidence`, and browser context), live DNS/TLS/DANE status fields, certificate hashes, and a `diagnostic_path` back to the root diagnostics page.

## Commands

```bash
hns-topology discover-hosts --db data/topology.sqlite
hns-topology live-check-hosts --db data/topology.sqlite --limit 1000 --concurrency 4 --min-delay-ms 250
hns-topology import-browser-evidence --db data/topology.sqlite --file browser-traces/
hns-topology generate-site --db data/topology.sqlite --out public
```

The legacy `live-check` command still checks root apexes and mirrors those apex results into host live status. New production runs should use `discover-hosts` and `live-check-hosts`.

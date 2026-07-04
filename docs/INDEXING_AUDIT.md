# Indexing and Export Audit

## Production Size Findings

The July 2026 production snapshot had 12,758,992 names in an 8.3 GB SQLite database.
The generated static JSON was much larger than the source database:

- `data/names-pages`: 56,599 files, 23.6 GiB in manifest bytes.
- `data/ip-addresses`: 17,958 files, 7.18 GiB in manifest bytes before the bounded export change.
- The largest repeated name collections were `all` at 5.17 GiB, `provider_type:self_hosted` at 3.87 GiB, then `delegated_names`, `likely_websites`, `provider:self-hosted`, and `strict_hns_ready` at roughly 2.2 GiB each.
- IP cardinality was heavily skewed: `44.231.6.183` matched 9,063,767 names and `54.214.136.246` matched 7,786,255 names, both as `GLUE4`.

Representative pretty-printed page files became about 60% of their original size when minified. That helps transfer and disk usage, but the larger problem is duplicated row materialization.

## Root Causes

`resource_summary` stores GLUE and SYNTH addresses as JSON arrays. That shape is good for showing one name's latest resource, but it is not an index for reverse lookup. Exporting IP search from it requires expanding JSON arrays and then writing a second static row collection.

The Names view also materializes many overlapping static collections. A row can appear in `all`, provider type, provider, likely website, strict HNS, delegated, DNSSEC, DANE, and failure slices. Those duplicated JSON pages dominate the public artifact size.

The browser is static-first. It loads `names-pages.json` and one page file for the selected filter. That gives cheap static browsing, but it pushes high-cardinality query cost into the export.

## Current Correction

The database now has `resource_ip(name, ip, field)` with an `(ip, name)` index. Indexing keeps this table in sync with `resource_summary`, and old databases are backfilled once during schema migration.

The lookup API now supports paginated IP lookup through `/hns-topology/api/ip?ip=<address>&page=<n>`, returning only `name`, `fields`, and `matched_ip` rows. The browser tries this API first.

Static IP export is now bounded by `MAX_STATIC_IP_LOOKUP_ROWS`. Small IP result sets still get static fallback pages. Provider-scale shared IPs get a small index file with counts and `requires_api: true` instead of thousands of duplicate page files.

Bulk page JSON is written compactly instead of pretty-printed.

## Next Architecture Step

The same pattern should be applied to Names filters:

- Keep SQLite as the source of truth for high-cardinality browse and search.
- Use static JSON for summary data, small bounded views, and API fallback only where the row count is sustainable.
- Add API endpoints for Names filters before removing large duplicated filter pages.
- Add query-specific indexes, for example `(provider_guess, name)` and filter-specific supporting indexes, before serving large filters dynamically.
- If a fully static report must remain available, replace duplicated row pages with compact posting lists that reference one canonical row store.

For production, the web VM should run the lookup API against a read-only SQLite snapshot on the artifact disk. That is more efficient than publishing millions of pre-rendered JSON rows for every reverse lookup.

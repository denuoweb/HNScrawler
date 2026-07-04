# Indexing and Export Audit

## Production Size Findings

The July 2026 production snapshot had 12,758,992 names in an 8.3 GB SQLite database.
The generated static JSON was much larger than the source database:

- `data/names-pages`: 56,599 files, 23.6 GiB in manifest bytes.
- `data/ip-addresses`: 17,958 files, 7.18 GiB in manifest bytes when IP pages duplicated compact Names rows.
- The largest repeated name collections were `all` at 5.17 GiB, `provider_type:self_hosted` at 3.87 GiB, then `delegated_names`, `likely_websites`, `provider:self-hosted`, and `strict_hns_ready` at roughly 2.2 GiB each.
- IP cardinality was heavily skewed: `44.231.6.183` matched 9,063,767 names and `54.214.136.246` matched 7,786,255 names, both as `GLUE4`.

Representative pretty-printed page files became about 60% of their original size when minified. That helps transfer and disk usage, but the larger problem is duplicated row materialization.

## Root Causes

`resource_summary` stores GLUE and SYNTH addresses as JSON arrays. That shape is good for showing one name's latest resource, but it is not an index for reverse lookup. Exporting IP search from it required expanding JSON arrays and initially wrote a second static row collection.

The Names view also materializes many overlapping static collections. A row can appear in `all`, provider type, provider, likely website, strict HNS, delegated, DNSSEC, DANE, and failure slices. Those duplicated JSON pages dominate the public artifact size.

The browser is static-first. It loads `names-pages.json` and one page file for the selected filter. That gives cheap static browsing, but it pushes high-cardinality query cost into the export.

## Current Correction

The database now has `resource_ip(name, ip, field)` with an `(ip, name)` lookup index. Indexing keeps this table in sync with `resource_summary`. Existing databases are backfilled with the explicit `hns-topology rebuild-resource-ip` command; schema migration does not hide that production-scale rewrite inside unrelated commands.

The derived IP index is built like a bulk index job: scan `resource_summary` once in name order, load `resource_ip` without the secondary IP lookup index attached, then create `idx_resource_ip_ip_name` after the load. New full bootstraps follow the same shape by deferring the lookup index until the resource rows are loaded.

IP lookup is now built from a normalized `resource_ip` table into compact static postings consumed by the Names page.

IP page files no longer duplicate Names rows. For the common single-field case, such as provider-scale `GLUE4` addresses, page files store only a JSON array of names plus a field mask in metadata. Mixed-field pages store `[name, field_mask]` pairs.

High-frequency marketplace/default glue IPs from the BNS collision study are provider-rule signals. They now match before the self-hosted rule, so an `ns1.<name>` plus shared default glue pattern does not get mislabeled as self-hosted. Known public HNS resolver IPs are also marked as resolver infrastructure if they appear in resource data. Both default parking and resolver infrastructure are excluded from automatic live-check candidate selection and from actionable website queues.

The Overview top resource-IP and nameserver-host lists are small aggregates in `summary.json`. They intentionally do not create new Names posting collections; IP rows link into the existing `names.html?q=<ip>` static IP search.

Bulk page JSON is written compactly instead of pretty-printed.

Site generation now writes a complete release tree into a staging directory and swaps it into place only after export succeeds. That removes obsolete `.html` and `.json` artifacts by construction and avoids publishing a partially written tree after an interrupted run.

## Current Names Export Shape

- Keep SQLite as the source of truth during indexing and export.
- Use static JSON for summary data and compact postings, not repeated row collections.
- Use one canonical sorted Names row store, with filter/provider/status postings into that store.
- Keep high-cardinality UI views paginated and decode only the current page in the browser.

Names filters now use that row-store pattern: `names-pages/all` is the canonical sorted row store, while visible filter, provider, provider-type, and nonzero failure collections are ordinal postings into that store. The browser resolves only the active postings page back to canonical rows. Hidden legacy filters and zero-row failure-reason postings are not exported.

During export, the generator builds a temporary `export_name_ordinals` table with ordinal, provider, provider type, resource flags, and live-status fields for the exported name set. Posting collections are counted and streamed from that temporary export index, avoiding repeated joins across the production `names`, `resource_summary`, `live_status`, and `provider_summary` tables.

If detailed diagnostics must show every resource record at production scale, store full resource detail once per canonical name row or in sharded on-demand detail files, not once per filter.

For production, the web VM can remain a static file server. Further reductions should target posting compression, such as delta or range encoding for dense ordinal postings, and query-specific SQLite indexes if generation profiles show a remaining DB-side bottleneck.

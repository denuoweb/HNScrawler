const fmt = new Intl.NumberFormat("en-US");
const SITE_BASE_PATH = window.__HNS_TOPOLOGY_BASE__ || "/hns-topology/";
const PAGE_FETCH_MIN_DELAY_MS = 350;
const COLLECTION_FETCH_BATCH_SIZE = 8;
const SEARCH_FULL_SCAN_MAX_ROWS = 5000;
const FAILURE_REASON_FILTER_PREFIX = "failure_reason:";
const PROVIDER_FILTER_PREFIX = "provider:";
const COMPLIANCE_STAGE_FILTER_PREFIX = "stage:";
const DANE_GENERATOR_BASE = window.__DANE_GENERATOR_BASE__ || "/dane-generator/";
const IP_FIELD_MAP = {
  1: "GLUE4",
  2: "GLUE6",
  4: "SYNTH4",
  8: "SYNTH6"
};
let nextPageFetchAt = 0;
const collectionRowsCache = new Map();
const collectionPageRowsCache = new Map();
const ipAddressLookupCache = new Map();

function sitePath(path) {
  if (/^(?:[a-z]+:)?\/\//i.test(path) || path.startsWith("/")) return path;
  return `${SITE_BASE_PATH}${path}`;
}

async function loadJson(path) {
  const response = await fetch(sitePath(path));
  if (!response.ok) throw new Error(`Failed to load ${path}`);
  return response.json();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function loadPageJson(path) {
  const now = Date.now();
  const wait = Math.max(0, nextPageFetchAt - now);
  nextPageFetchAt = Math.max(nextPageFetchAt, now) + PAGE_FETCH_MIN_DELAY_MS;
  if (wait > 0) await sleep(wait);
  return loadJson(path);
}

function pct(value, total) {
  if (!total) return "0%";
  return `${((value / total) * 100).toFixed(2)}%`;
}

function metric(label, value, sub = "", href = "") {
  const content = `<span class="label">${escapeHtml(label)}</span><span class="value">${fmt.format(value ?? 0)}</span><span class="sub">${escapeHtml(sub)}</span>`;
  if (href) return `<a class="metric metric-link" href="${escapeHtml(sitePath(href))}">${content}</a>`;
  return `<article class="metric">${content}</article>`;
}

function activeFilter() {
  return new URLSearchParams(window.location.search).get("filter") || "";
}

function activePage() {
  const page = Number.parseInt(new URLSearchParams(window.location.search).get("page") || "1", 10);
  return Number.isFinite(page) && page > 0 ? page : 1;
}

function activeSearch() {
  return (new URLSearchParams(window.location.search).get("q") || "").trim();
}

function activeSearchMode() {
  return new URLSearchParams(window.location.search).get("search") || "";
}

function textSearchOnly() {
  return activeSearchMode() === "text";
}

function namesSearchHref(query, options = {}) {
  const text = String(query || "").trim();
  if (!text) return "";
  const params = new URLSearchParams();
  const filter = options.filter === undefined ? activeFilter() : options.filter;
  if (filter) params.set("filter", filter);
  if (options.textSearch) params.set("search", "text");
  params.set("q", text);
  return `names.html?${params.toString()}`;
}

function hasDs(row) {
  return row.has_ds === true || Number(row.has_ds || 0) === 1;
}

function recordTypes(row) {
  return Array.isArray(row.record_types) ? row.record_types : [];
}

function hasRecordType(row, type) {
  return recordTypes(row).includes(type);
}

function hasNs(row) {
  return Boolean(firstValue(row.ns_names) || row.first_ns || hasRecordType(row, "NS"));
}

function firstValue(value) {
  if (Array.isArray(value)) return value.find(Boolean) || "";
  return value || "";
}

function hasSynth(row) {
  return Boolean(
    firstValue(row.synth4)
    || firstValue(row.synth6)
    || row.first_synth4
    || row.first_synth6
    || hasRecordType(row, "SYNTH4")
    || hasRecordType(row, "SYNTH6")
  );
}

function hasGlue(row) {
  return Boolean(
    firstValue(row.glue4)
    || firstValue(row.glue6)
    || row.first_glue4
    || row.first_glue6
    || hasRecordType(row, "GLUE4")
    || hasRecordType(row, "GLUE6")
  );
}

function hasNsHandoff(row) {
  return Boolean(row.ns_handoff_ns && row.ns_handoff_root && row.ns_handoff_bootstrap_ip);
}

function filterName(filter) {
  if (filter.startsWith(FAILURE_REASON_FILTER_PREFIX)) return prettyToken(filter.slice(FAILURE_REASON_FILTER_PREFIX.length));
  if (filter.startsWith(PROVIDER_FILTER_PREFIX)) return `provider ${filter.slice(PROVIDER_FILTER_PREFIX.length)}`;
  if (filter.startsWith(COMPLIANCE_STAGE_FILTER_PREFIX)) return stageLabel(filter.slice(COMPLIANCE_STAGE_FILTER_PREFIX.length));
  return ({
    direct_ip_records: "SYNTH nameservers",
    delegated_names: "delegated names",
    default_provider_names: "default providers",
    ds_records: "DS records",
    dnssec_candidates: "DNSSEC candidates",
    static_tlsa_certificate_expired_names: "static TLSA expired certificate",
    strict_hns_ready: "strict HNS ready",
    likely_websites: "likely host roots",
    strict_hns_working: "strict HNS working",
    doh_fallback_required: "resolver fallback required",
    needs_dane: "needs DANE",
    dane_working: "DANE verified",
    needs_fix: "needs fix",
    missing_glue_only: "missing GLUE only",
    stale_tlsa_only: "stale TLSA only",
    live_site_names: "live host evidence",
    browser_target_names: "browser targets",
    browser_evidence_names: "browser evidence",
    browser_dane_verified_names: "browser DANE verified",
    browser_network_blocks_53_names: "browser network blocks 53",
    browser_certificate_expired_names: "browser expired certificate"
  })[filter] || filter;
}

function stageLabel(stage) {
  return ({
    dane_verified: "DANE verified",
    tlsa_gap: "TLSA gap",
    stale_tlsa: "Stale TLSA",
    dnssec_broken: "DNSSEC broken",
    missing_glue: "Missing GLUE",
    bootstrap_ready: "Bootstrap ready",
    resolver_fallback: "Resolver fallback",
    service_blocked: "Service blocked",
    non_actionable: "Non-actionable"
  })[stage] || prettyToken(stage);
}

function stageDefinition(stage) {
  return ({
    dane_verified: "DNSSEC, TLSA, and HTTPS SPKI match.",
    tlsa_gap: "DNSSEC exists; generate or repair TLSA next.",
    stale_tlsa: "TLSA does not match the current HTTPS key.",
    dnssec_broken: "DS, DNSKEY, or signatures need repair.",
    missing_glue: "Parent-side nameserver bootstrap is missing.",
    bootstrap_ready: "HNS bootstrap exists; publish DNSSEC and TLSA.",
    resolver_fallback: "Strict HNS failed; fallback resolver was needed.",
    service_blocked: "Live service check failed before current DANE proof.",
    non_actionable: "Expired, parked, resolver, empty, or unsupported."
  })[stage] || "";
}

function filterNotice(filter, before, after) {
  if (!filter) return "";
  return `<p class="meta">Filter: ${escapeHtml(filterName(filter))}. Showing ${fmt.format(after)} of ${fmt.format(before)} exported rows.</p>`;
}

function bars(rows, labelKey, valueKey, limit = 12, labelFormatter = (value) => value, hrefFormatter = null) {
  const max = Math.max(1, ...rows.map((row) => Number(row[valueKey] || 0)));
  return `<div class="bar-list">${rows.slice(0, limit).map((row) => {
    const value = Number(row[valueKey] || 0);
    const label = labelFormatter(row[labelKey]);
    const rowHtml = `<span class="bar-label" title="${escapeHtml(label)}">${escapeHtml(label)}</span><span class="bar-track"><span class="bar-fill" style="width:${(value / max) * 100}%"></span></span><strong>${fmt.format(value)}</strong>`;
    const href = hrefFormatter ? hrefFormatter(row) : "";
    if (href) return `<a class="bar-row bar-link" href="${escapeHtml(sitePath(href))}">${rowHtml}</a>`;
    return `<div class="bar-row">${rowHtml}</div>`;
  }).join("")}</div>`;
}

function columnClass(column) {
  return column.className || `col-${String(column.key || "value").replace(/[^a-z0-9_-]/gi, "-").toLowerCase()}`;
}

function tableRows(rows, columns, options = {}) {
  return rows.map((row) => {
    const cells = columns.map((column) => `<td class="${escapeHtml(columnClass(column))}">${column.render ? column.render(row) : formatCell(row[column.key])}</td>`).join("");
    const detail = options.detailRender ? options.detailRender(row, columns.length) : "";
    const rowClass = typeof options.rowClass === "function" ? options.rowClass(row) : options.rowClass;
    const rowAttrs = rowClass ? ` class="${escapeHtml(rowClass)}"` : "";
    return `<tr${rowAttrs}>${cells}</tr>${detail}`;
  }).join("");
}

function table(rows, columns, emptyMessage = "No rows in this page.", options = {}) {
  if (!rows.length) return `<p class="empty-state">${escapeHtml(emptyMessage)}</p>`;
  const tbodyId = options.tbodyId ? ` id="${escapeHtml(options.tbodyId)}"` : "";
  const wrapClass = options.wrapClass ? `table-wrap ${escapeHtml(options.wrapClass)}` : "table-wrap";
  const tableClass = options.tableClass ? ` class="${escapeHtml(options.tableClass)}"` : "";
  const colgroup = columns.some((column) => column.width)
    ? `<colgroup>${columns.map((column) => `<col${column.width ? ` style="width:${escapeHtml(column.width)}"` : ""}>`).join("")}</colgroup>`
    : "";
  return `<div class="${wrapClass}"><table${tableClass}>${colgroup}<thead><tr>${columns.map((column) => `<th class="${escapeHtml(columnClass(column))}">${escapeHtml(column.label)}</th>`).join("")}</tr></thead><tbody${tbodyId}>${tableRows(rows, columns, options)}</tbody></table></div>`;
}

function formatCell(value) {
  if (Array.isArray(value)) return escapeHtml(value.join(", "));
  if (value === null || value === undefined) return "";
  if (typeof value === "number") return fmt.format(value);
  return escapeHtml(String(value));
}

function statusPill(value) {
  const token = String(value || "").trim();
  if (!token) return "";
  const className = ["valid", "working", "tls_unverified", "loaded", "verified"].includes(token)
    ? "status-ok"
    : ["failed", "invalid", "expired", "timeout", "unreachable"].includes(token)
      ? "status-bad"
      : "";
  return `<span${className ? ` class="${className}"` : ""}>${escapeHtml(prettyToken(token))}</span>`;
}

function prettyToken(value) {
  return String(value || "").replaceAll("_", " ");
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#039;"
  })[char]);
}

function setActiveNav(page) {
  document.querySelectorAll("nav a").forEach((link) => {
    if (link.dataset.nav === page) link.classList.add("active");
  });
}

function classLabel(value) {
  return ({
    EXPIRED: "Expired",
    EMPTY: "Empty",
    TXT_ONLY: "TXT only",
    DIRECT_SYNTH: "SYNTH nameserver",
    DELEGATED_WITH_GLUE: "Delegated with glue",
    DELEGATED_NO_GLUE: "Delegated missing glue",
    DNSSEC_CANDIDATE: "DNSSEC candidate",
    DANE_CANDIDATE: "DANE candidate",
    PARKED_OR_DEFAULT: "Parked/default",
    MALFORMED_RESOURCE: "Malformed resource",
    UNKNOWN_OTHER: "Unknown other"
  })[value] || prettyToken(value);
}

function classFilterHref(value) {
  return ({
    DIRECT_SYNTH: "names.html?filter=direct_ip_records",
    DELEGATED_WITH_GLUE: "names.html?filter=strict_hns_ready",
    DELEGATED_NO_GLUE: "names.html?filter=missing_glue_only",
    DNSSEC_CANDIDATE: "names.html?filter=dnssec_candidates",
    DANE_CANDIDATE: "names.html?filter=dnssec_candidates",
    PARKED_OR_DEFAULT: "names.html?filter=default_provider_names"
  })[value] || "";
}

function providerFilterHref(row) {
  return row.provider_key ? `names.html?filter=${encodeURIComponent(`${PROVIDER_FILTER_PREFIX}${row.provider_key}`)}` : "";
}

function aggregateSearchLink(value, href = "") {
  const label = String(value || "");
  const target = href || namesSearchHref(label, {filter: ""});
  if (!target) return escapeHtml(label);
  return `<a href="${escapeHtml(sitePath(target))}" title="${escapeHtml(label)}">${escapeHtml(label)}</a>`;
}

function topIpCell(row) {
  return aggregateSearchLink(row.ip, row.filter_link);
}

function nameserverCell(row) {
  const nameserver = String(row.nameserver || "").trim();
  return aggregateSearchLink(
    nameserver,
    row.filter_link || namesSearchHref(nameserver, {filter: "delegated_names", textSearch: true})
  );
}

function resolverIpCell(row) {
  return aggregateSearchLink(row.ip, row.filter_link);
}

function ipFieldCountsCell(row) {
  const counts = row.field_counts || {};
  const parts = Object.entries(counts)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([field, count]) => `${field} ${fmt.format(count || 0)}`);
  return escapeHtml(parts.join(", "));
}

function ipRoleCell(row) {
  const label = row.label || prettyToken(row.role || "unknown");
  return `<span title="${escapeHtml(row.source || "")}">${escapeHtml(label)}</span>`;
}

function resolverSoftwareCell(row) {
  return row.hnsdoh_software ? "HNSDoH" : "plain DNS";
}

function topologySignals(summary) {
  const topIps = summary.top_resource_ips || [];
  const topNameservers = summary.top_nameservers || [];
  const resolvers = summary.known_hns_resolvers || [];
  return `
    <article class="panel"><h2>Nameserver IP Evidence</h2>${table(topIps, [
      {key: "ip", label: "IP", render: topIpCell, width: "30%"},
      {key: "names_count", label: "Names", width: "18%"},
      {key: "field_counts", label: "Fields", render: ipFieldCountsCell, width: "27%"},
      {key: "role", label: "Role", render: ipRoleCell, width: "25%"}
    ], "No resource IPs in this snapshot.", {wrapClass: "compact-table-wrap"})}</article>
    <article class="panel"><h2>Delegation Hosts</h2>${table(topNameservers, [
      {key: "nameserver", label: "Nameserver", render: nameserverCell, width: "70%"},
      {key: "names_count", label: "Names", width: "30%"}
    ], "No nameservers in this snapshot.", {wrapClass: "compact-table-wrap"})}</article>
    <article class="panel"><h2>HNS Resolver Inventory</h2>${table(resolvers, [
      {key: "ip", label: "IP", render: resolverIpCell, width: "30%"},
      {key: "provider", label: "Provider", width: "40%"},
      {key: "hnsdoh_software", label: "Software", render: resolverSoftwareCell, width: "30%"}
    ], "No resolver inventory configured.", {wrapClass: "compact-table-wrap"})}</article>`;
}

function daneGeneratorUrl(row, intent) {
  return window.DaneGeneratorHandoff.buildUrl(row, {base: DANE_GENERATOR_BASE, intent});
}

function complianceStage(row) {
  if (row.compliance_stage) return row.compliance_stage;
  const failure = row.failure_reason || "";
  if (row.expired) return "non_actionable";
  if (row.dane_status === "valid") return "dane_verified";
  if (row.provider_type === "default_parking" || row.provider_type === "public_resolver") return "non_actionable";
  if (failure === "stale_tlsa_spki_mismatch" || failure === "tlsa_wrong_owner" || (row.tlsa_status === "present" && row.dane_status === "invalid")) return "stale_tlsa";
  if (failure === "dnssec_missing" || failure === "dnssec_bogus" || failure === "ds_dnskey_mismatch" || failure === "rrsig_expired") return "dnssec_broken";
  if (failure === "missing_glue" || row.onchain_class === "DELEGATED_NO_GLUE") return "missing_glue";
  if (failure === "certificate_expired") return "service_blocked";
  if (hasDs(row) && row.dane_status !== "valid") return "tlsa_gap";
  if (failure && failure !== "doh_fallback_only") return "service_blocked";
  if (row.doh_fallback_status === "required" || row.doh_fallback_status === "doh_fallback_only" || failure === "doh_fallback_only") return "resolver_fallback";
  if (hasSynth(row) || hasGlue(row) || row.onchain_class === "DELEGATED_WITH_GLUE") return "bootstrap_ready";
  return "non_actionable";
}

function rowAction(row) {
  const stage = complianceStage(row);
  const browserAction = browserPromotedAction(row, stage);
  if (browserAction) return browserAction;
  if (stage === "dane_verified") {
    return {
      type: "badge",
      label: "DANE verified",
      detail: "DNSSEC, exact TLSA, and HTTPS SPKI matched in the latest indexer live check.",
      href: sitePath(`names.html?filter=dane_working&q=${encodeURIComponent(row.name || "")}`)
    };
  }
  if (stage === "missing_glue") {
    if (hasNsHandoff(row)) {
      return {
        label: "Review NS handoff",
        detail: `${trailingDot(row.ns_handoff_ns)} can be traced through ${row.ns_handoff_root}/, but this name still lacks direct parent-side GLUE.`,
        href: daneGeneratorUrl(row, "missing_glue")
      };
    }
    return {
      label: "Create NS/GLUE handoff",
      detail: "Parent-side nameserver bootstrap is required before the signed TLSA zone is reachable.",
      href: daneGeneratorUrl(row, "missing_glue")
    };
  }
  if (stage === "dnssec_broken") {
    return {
      label: "Regenerate/check DS",
      detail: "DNSSEC signing needs review before DANE can validate.",
      href: daneGeneratorUrl(row, "dnssec_fix")
    };
  }
  if (stage === "stale_tlsa") {
    return {
      label: "Replace stale TLSA",
      detail: "TLSA data should match the current HTTPS certificate public key.",
      href: daneGeneratorUrl(row, "stale_tlsa")
    };
  }
  if (stage === "tlsa_gap") {
    return {
      label: "Generate TLSA record",
      detail: "DNSSEC is present or live-valid; add or verify TLSA 3 1 1 next.",
      href: daneGeneratorUrl(row, "generate_tlsa")
    };
  }
  if (stage === "bootstrap_ready") {
    return {
      label: hasSynth(row) ? "Generate SYNTH DNS setup" : "Plan DNSSEC + DANE",
      detail: hasSynth(row)
        ? "SYNTH points to nameserver IPs; the zone still serves A, AAAA, DNSSEC, and TLSA."
        : "HNS bootstrap exists; sign the zone and publish DS/TLSA when ready.",
      href: daneGeneratorUrl(row, hasSynth(row) ? "synth_setup" : "dnssec_dane")
    };
  }
  if (stage === "resolver_fallback") {
    return {
      label: "Remove resolver fallback",
      detail: "Strict HNS did not complete; use the generator to review parent-side bootstrap.",
      href: daneGeneratorUrl(row, "review")
    };
  }
  if (stage === "service_blocked") {
    return {
      label: row.failure_reason === "certificate_expired" ? "Renew HTTPS certificate" : "Review live service",
      detail: row.failure_reason === "certificate_expired"
        ? "The origin certificate is expired; fix certificate time before treating TLSA/DANE gaps as current."
        : "A live check failed before the indexer could prove DANE.",
      href: daneGeneratorUrl(row, "review")
    };
  }
  return {
    label: "Review setup",
    detail: "Open the generator with this name filled in.",
    href: daneGeneratorUrl(row, "review")
  };
}

function browserPromotedAction(row, stage) {
  if (row.browser_action === "renew_certificate" && !["missing_glue", "dnssec_broken"].includes(stage)) {
    return {
      label: row.browser_action_label || "Renew HTTPS certificate",
      detail: row.browser_action_detail || "Latest browser evidence saw an expired HTTPS certificate.",
      href: daneGeneratorUrl(row, "review")
    };
  }
  if (row.browser_action === "compare_browser_dane" && ["tlsa_gap", "bootstrap_ready", "service_blocked"].includes(stage)) {
    return {
      type: "badge",
      label: row.browser_action_label || "Review browser DANE proof",
      detail: row.browser_action_detail || "Browser evidence verified DANE; compare resolver paths.",
      href: sitePath(`names.html?filter=browser_dane_verified_names&q=${encodeURIComponent(row.name || "")}`)
    };
  }
  return null;
}

function actionCell(row) {
  const action = rowAction(row);
  if (action.type === "badge") {
    return `<div class="action-cell"><a class="verified-badge" href="${escapeHtml(action.href)}">${escapeHtml(action.label)}</a><span>${escapeHtml(action.detail)}</span></div>`;
  }
  return `<div class="action-cell"><a class="action-link" href="${escapeHtml(action.href)}">${escapeHtml(action.label)}</a><span>${escapeHtml(action.detail)}</span></div>`;
}

function snapshot(summary) {
  const stageCounts = summary.compliance_stage_counts || {};
  const hasStageCounts = Boolean(summary.compliance_stage_counts);
  const daneVerified = stageCounts.dane_verified ?? summary.dane_working;
  const tlsaGap = stageCounts.tlsa_gap ?? summary.needs_dane;
  const stageBlockers = ["missing_glue", "stale_tlsa", "dnssec_broken", "resolver_fallback", "service_blocked"]
    .reduce((total, stage) => total + Number(stageCounts[stage] || 0), 0);
  const blockerQueue = hasStageCounts ? stageBlockers : summary.needs_fix;
  return `<section class="snapshot">
    ${metric("Active names", summary.active_names, `${fmt.format(summary.expired_names)} expired`, "names.html")}
    ${metric("DANE verified", daneVerified, `${pct(daneVerified, summary.active_names)} of active`, `names.html?filter=${COMPLIANCE_STAGE_FILTER_PREFIX}dane_verified`)}
    ${metric("TLSA gaps", tlsaGap, "ready for generator handoff", `names.html?filter=${COMPLIANCE_STAGE_FILTER_PREFIX}tlsa_gap`)}
    ${metric("Compliance blockers", blockerQueue, "blocking verification")}
    ${metric("Live hosts", summary.live_site_names, "live/browser evidence", "names.html?filter=live_site_names")}
    ${metric("Browser evidence", summary.browser_evidence_names, `${fmt.format(summary.browser_network_blocks_53_names || 0)} network-blocked, ${fmt.format(summary.browser_certificate_expired_names || 0)} expired cert`, "names.html?filter=browser_evidence_names")}
  </section>`;
}

function liveCheckMeta(summary) {
  const checked = summary.host_live_check_checked_count ?? summary.live_check_checked_count ?? 0;
  const candidates = summary.host_live_check_candidate_count ?? summary.live_check_candidate_count ?? 0;
  const concurrency = summary.host_live_check_concurrency ?? summary.live_check_concurrency ?? 0;
  const delay = summary.host_live_check_min_delay_ms ?? summary.live_check_min_delay_ms ?? 0;
  const timeout = summary.host_live_check_timeout_seconds ?? summary.live_check_timeout_seconds ?? "";
  if (!summary.host_live_check_started_at && !summary.live_check_started_at) return "";
  return `<p class="meta">Host checks ${fmt.format(checked)} of ${fmt.format(candidates)} due - concurrency ${fmt.format(concurrency)} - delay ${fmt.format(delay)}ms - timeout ${timeout}s</p>`;
}

function collectionForFilter(index, filter) {
  if (filter && index.collections && index.collections[filter]) {
    return {key: filter, collection: collectionWithRowStore(index, index.collections[filter])};
  }
  if (filter) {
    return {key: filter, collection: emptyCollectionForFilter(index, filter)};
  }
  return {key: "all", collection: collectionWithRowStore(index, index.collections.all)};
}

function collectionWithRowStore(index, collection) {
  if (!collection || collection.row_source !== "postings") return collection;
  return {...collection, row_store: index.row_store || index.collections?.all};
}

function emptyCollectionForFilter(index, filter) {
  const rowStore = index.row_store || index.collections?.all || {};
  return {
    row_count: 0,
    total_count: 0,
    page_size: Number(rowStore.page_size || index.page_size || 1000),
    page_count: 0,
    path_template: "",
    truncated: false,
    row_source: "postings",
    row_detail: rowStore.row_detail || "full",
    columns: rowStore.columns || null,
    row_store: rowStore,
    missing_filter: filter
  };
}

function pagePath(pathTemplate, page) {
  return `data/${escapePathPercents(pathTemplate.replace("{page}", String(page)))}`;
}

function escapePathPercents(path) {
  return String(path || "").replaceAll("%", "%25");
}

function rowsFromPage(data, collection = {}) {
  const rows = Array.isArray(data.rows) ? data.rows : [];
  if (data.row_encoding === "ordinal") {
    return rows.map((ordinal) => ({ordinal: Number(ordinal)}));
  }
  if (data.row_encoding === "name") {
    const mask = Number(data.field_mask ?? collection.default_field_mask ?? 0);
    const fields = ipFieldsFromMask(mask, collection.field_map);
    return rows.map((name) => ({name, field_mask: mask, fields}));
  }
  const columns = Array.isArray(data.columns) ? data.columns : collection.columns;
  if (!Array.isArray(columns) || !rows.some((row) => Array.isArray(row))) return rows;
  return rows.map((row) => {
    const item = Object.fromEntries(columns.map((key, index) => [key, row[index]]));
    if (data.row_encoding === "name_field_mask" || item.field_mask !== undefined) {
      item.fields = ipFieldsFromMask(item.field_mask, collection.field_map);
    }
    return item;
  });
}

function ipFieldsFromMask(maskValue, fieldMap = {}) {
  const mask = Number(maskValue || 0);
  const map = Object.keys(fieldMap || {}).length ? fieldMap : IP_FIELD_MAP;
  return Object.entries(map)
    .map(([bit, field]) => [Number(bit), field])
    .filter(([bit]) => bit > 0 && (mask & bit) === bit)
    .map(([, field]) => field);
}

function clampedPage(collection) {
  const pageCount = Number(collection.page_count || 0);
  if (pageCount <= 0) return 1;
  return Math.min(activePage(), pageCount);
}

function currentPageName() {
  const pageName = window.location.pathname.split("/").pop() || "index.html";
  return pageName.endsWith(".html") ? pageName : "index.html";
}

function hrefWithoutParams(keys) {
  const params = new URLSearchParams(window.location.search);
  keys.forEach((key) => params.delete(key));
  const query = params.toString();
  const path = currentPageName();
  return sitePath(query ? `${path}?${query}` : path);
}

function pageRangeMeta(collection, page, rows) {
  const total = Number(collection.row_count || 0);
  if (!total) return "0 exported rows";
  if (!rows.length) return `No rows on page ${fmt.format(page)} of ${fmt.format(Math.max(1, Number(collection.page_count || 0)))}`;
  const start = (page - 1) * Number(collection.page_size || rows.length || 1) + 1;
  const end = Math.min(start + rows.length - 1, total);
  return `${fmt.format(start)}-${fmt.format(end)} of ${fmt.format(total)} exported rows`;
}

function hrefWithPage(page) {
  const params = new URLSearchParams(window.location.search);
  if (page <= 1) params.delete("page");
  else params.set("page", String(page));
  const query = params.toString();
  const path = currentPageName();
  return sitePath(query ? `${path}?${query}` : path);
}

async function loadPaginatedRows(indexPath, filter) {
  const index = await loadJson(indexPath);
  const {collection} = collectionForFilter(index, filter);
  const page = clampedPage(collection);
  const data = collection.page_count > 0
    ? await loadPageJson(pagePath(collection.path_template, page))
    : {rows: []};
  const rows = await rowsFromCollectionPage(data, collection);
  return {
    index,
    collection,
    page,
    rows
  };
}

async function rowsFromCollectionPage(data, collection = {}) {
  if (collection.row_source === "postings" || data.row_encoding === "ordinal") {
    const ordinals = rowsFromPage(data, collection)
      .map((row) => Number(row.ordinal))
      .filter((ordinal) => Number.isInteger(ordinal) && ordinal >= 0);
    return loadRowsByOrdinals(collection.row_store, ordinals);
  }
  return rowsFromPage(data, collection);
}

async function loadRowsByOrdinals(rowStore, ordinals) {
  if (!rowStore || !ordinals.length) return [];
  const pageSize = Number(rowStore.page_size || 0) || 1000;
  const byPage = new Map();
  ordinals.forEach((ordinal, index) => {
    const page = Math.floor(ordinal / pageSize) + 1;
    const offset = ordinal % pageSize;
    if (!byPage.has(page)) byPage.set(page, []);
    byPage.get(page).push({index, offset});
  });

  const resolved = Array(ordinals.length);
  await Promise.all(Array.from(byPage.entries()).map(async ([page, items]) => {
    const rows = await loadCollectionPageRows(rowStore, page);
    items.forEach(({index, offset}) => {
      if (rows[offset]) resolved[index] = rows[offset];
    });
  }));
  return resolved.filter(Boolean);
}

async function loadCollectionRows(collection) {
  const pageCount = Number(collection.page_count || 0);
  if (pageCount <= 0) return [];
  const cacheKey = collection.path_template;
  if (collectionRowsCache.has(cacheKey)) return collectionRowsCache.get(cacheKey);

  const rowsPromise = (async () => {
    const rows = [];
    for (let start = 1; start <= pageCount; start += COLLECTION_FETCH_BATCH_SIZE) {
      const end = Math.min(start + COLLECTION_FETCH_BATCH_SIZE - 1, pageCount);
      const pages = [];
      for (let page = start; page <= end; page += 1) {
        pages.push(loadJson(pagePath(collection.path_template, page))
          .then((data) => rowsFromCollectionPage(data, collection)));
      }
      const pageResults = await Promise.all(pages);
      pageResults.forEach((pageRows) => {
        rows.push(...pageRows);
      });
    }
    return rows;
  })();
  collectionRowsCache.set(cacheKey, rowsPromise);
  return rowsPromise;
}

async function loadCollectionPageRows(collection, page) {
  const cacheKey = `${collection.path_template}:${page}`;
  if (collectionPageRowsCache.has(cacheKey)) return collectionPageRowsCache.get(cacheKey);
  const rowsPromise = loadJson(pagePath(collection.path_template, page))
    .then((data) => rowsFromCollectionPage(data, collection));
  collectionPageRowsCache.set(cacheKey, rowsPromise);
  return rowsPromise;
}

function searchTokens(query) {
  return query.toLowerCase().split(/\s+/).filter(Boolean);
}

function flattenSearchValue(value, parts) {
  if (value === null || value === undefined) return;
  if (Array.isArray(value)) {
    value.forEach((item) => flattenSearchValue(item, parts));
    return;
  }
  if (typeof value === "object") {
    Object.values(value).forEach((item) => flattenSearchValue(item, parts));
    return;
  }
  parts.push(String(value).toLowerCase());
}

function rowMatchesSearch(row, tokens) {
  if (!tokens.length) return true;
  const parts = [];
  flattenSearchValue(row, parts);
  const searchable = parts.join(" ");
  return tokens.every((token) => searchable.includes(token));
}

function normalizeLookupQuery(query) {
  let name = query.trim().toLowerCase();
  for (const prefix of ["hns://", "https://", "http://"]) {
    if (name.startsWith(prefix)) {
      name = name.slice(prefix.length);
      break;
    }
  }
  name = name.split("/", 1)[0].split(".", 1)[0].trim();
  return /^[a-z0-9-]{1,63}$/.test(name) ? name : "";
}

function normalizeIpQuery(query) {
  let value = query.trim().toLowerCase();
  if (value.startsWith("[") && value.includes("]")) {
    value = value.slice(1, value.indexOf("]"));
  }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) {
    const parts = value.split(".");
    if (parts.every((part) => Number(part) <= 255)) {
      return parts.map((part) => String(Number(part))).join(".");
    }
  }
  if (value.includes(":") && /^[0-9a-f:.]+$/.test(value)) return value;
  return "";
}

function ipAddressLookupPath(ip) {
  return `data/ip-addresses/${escapePathPercents(encodeURIComponent(ip))}.json`;
}

function normalizeIpLookupResult(result, query, ip) {
  const rows = Array.isArray(result.rows) ? result.rows : [];
  return {
    found: result.found !== false,
    query,
    ip,
    rowCount: Number(result.row_count || rows.length || 0),
    pageCount: Number(result.page_count || 0),
    pageSize: Number(result.page_size || 0) || 100,
    page: Number(result.page || 1),
    rowDetail: result.row_detail || "ip_matches",
    columns: Array.isArray(result.columns) ? result.columns : null,
    fieldCounts: result.field_counts || {},
    source: "static",
    rows: rows.map((row) => ({...row, matched_ip: row.matched_ip || ip}))
  };
}

async function lookupIpAddress(query, page) {
  const ip = normalizeIpQuery(query);
  if (!ip) return null;
  if (!ipAddressLookupCache.has(ip)) {
    const lookupPromise = loadJson(ipAddressLookupPath(ip))
      .catch(() => null);
    ipAddressLookupCache.set(ip, lookupPromise);
  }
  const data = await ipAddressLookupCache.get(ip);
  if (!data) {
    return {
      found: false,
      query,
      ip,
      rowCount: 0,
      pageCount: 0,
      pageSize: 100,
      page: 1,
      rowDetail: "ip_matches",
      columns: null,
      fieldCounts: {},
      source: "static",
      rows: []
    };
  }
  const embeddedRows = Array.isArray(data.rows) ? data.rows : null;
  const rowCount = Number(data.row_count || embeddedRows?.length || 0);
  const pageSize = Number(data.page_size || 0) || 100;
  const pageCount = Number(data.page_count || 0) || (rowCount ? Math.ceil(rowCount / pageSize) : 0);
  const safePage = pageCount > 0 ? Math.min(Math.max(1, page), pageCount) : 1;
  const rows = embeddedRows
    ? embeddedRows.slice((safePage - 1) * pageSize, safePage * pageSize)
    : pageCount > 0 && data.path_template
      ? await loadJson(pagePath(data.path_template, safePage))
        .then((pageData) => rowsFromPage(pageData, data))
        .catch(() => [])
      : [];
  return normalizeIpLookupResult(
    {
      ...data,
      found: true,
      page: safePage,
      rows
    },
    query,
    ip
  );
}

async function lookupExactNameFromApi(query, name) {
  try {
    const response = await fetch(sitePath(`api/name?name=${encodeURIComponent(name)}`));
    if (!response.ok && response.status !== 404) return null;
    const result = await response.json();
    return {...result, source: "api", fullSnapshot: true};
  } catch (_error) {
    return null;
  }
}

async function lookupExactNameFromStatic(query, name, index) {
  const collection = index?.collections?.all;
  const pageCount = Number(collection?.page_count || 0);
  if (!collection || pageCount <= 0) return null;
  const rowCount = Number(collection.row_count || 0);
  const totalCount = Number(collection.total_count || rowCount);
  const fullSnapshot = rowCount === totalCount;
  let low = 1;
  let high = pageCount;

  while (low <= high) {
    const page = Math.floor((low + high) / 2);
    const rows = await loadCollectionPageRows(collection, page);
    if (!rows.length) break;
    const first = String(rows[0].name || "");
    const last = String(rows[rows.length - 1].name || "");
    if (name < first) {
      high = page - 1;
      continue;
    }
    if (name > last) {
      low = page + 1;
      continue;
    }
    const row = rows.find((item) => item.name === name);
    return {
      found: Boolean(row),
      query,
      normalized: name,
      source: "static",
      fullSnapshot,
      row,
    };
  }

  return {
    found: false,
    query,
    normalized: name,
    source: "static",
    fullSnapshot,
  };
}

async function lookupExactName(query, index) {
  const name = normalizeLookupQuery(query);
  if (!name) return null;
  const apiResult = await lookupExactNameFromApi(query, name);
  if (apiResult) return apiResult;
  return lookupExactNameFromStatic(query, name, index);
}

async function applySearchToPageData(pageData, query) {
  if (!query) return {...pageData, search: null, lookup: null};
  const ipLookup = await lookupIpAddress(query, activePage());
  if (ipLookup) {
    const allCollection = pageData.index?.collections?.all || pageData.collection;
    const exportedCount = Number(allCollection.row_count || 0);
    const totalCount = Number(allCollection.total_count || exportedCount);
    const fullSnapshot = exportedCount === totalCount;
    return {
      ...pageData,
      collection: {
        ...pageData.collection,
        row_count: ipLookup.rowCount,
        page_size: ipLookup.pageSize,
        page_count: ipLookup.pageCount,
        row_detail: ipLookup.rowDetail,
        columns: ipLookup.columns
      },
      page: ipLookup.page,
      rows: ipLookup.rows,
      search: {
        query,
        matchedCount: ipLookup.rowCount,
        totalCount: "snapshot",
        exact: false,
        ip: true,
        scoped: false,
        fullSnapshot
      },
      lookup: null,
      ipLookup
    };
  }
  const exactLookupEnabled = !textSearchOnly();
  const lookup = exactLookupEnabled ? await lookupExactName(query, pageData.index) : null;
  if (lookup && lookup.found) {
    return {
      ...pageData,
      collection: {
        ...pageData.collection,
        row_count: 1,
        page_count: 1
      },
      page: 1,
      rows: [lookup.row],
      search: {
        query,
        matchedCount: 1,
        totalCount: "snapshot",
        exact: true,
        exactSource: lookup.source || "api",
        fullSnapshot: lookup.fullSnapshot !== false
      },
      lookup
    };
  }
  const exportedCount = Number(pageData.collection.row_count || 0);
  if (exportedCount > SEARCH_FULL_SCAN_MAX_ROWS) {
    const tokens = searchTokens(query);
    const matchedRows = pageData.rows.filter((row) => rowMatchesSearch(row, tokens));
    return {
      ...pageData,
      rows: matchedRows,
      search: {
        query,
        matchedCount: matchedRows.length,
        totalCount: pageData.rows.length,
        exact: false,
        scoped: true,
        exactSource: lookup?.source || "api",
        fullSnapshot: lookup?.fullSnapshot !== false,
        textOnly: textSearchOnly()
      },
      lookup
    };
  }
  const allRows = await loadCollectionRows(pageData.collection);
  const tokens = searchTokens(query);
  const matchedRows = allRows.filter((row) => rowMatchesSearch(row, tokens));
  const pageSize = Number(pageData.collection.page_size || 0) || 100;
  const pageCount = matchedRows.length ? Math.ceil(matchedRows.length / pageSize) : 0;
  const page = pageCount > 0 ? Math.min(activePage(), pageCount) : 1;
  const start = (page - 1) * pageSize;
  return {
    ...pageData,
    collection: {
      ...pageData.collection,
      row_count: matchedRows.length,
      page_count: pageCount
    },
    page,
    rows: matchedRows.slice(start, start + pageSize),
    search: {
      query,
      matchedCount: matchedRows.length,
      totalCount: allRows.length,
      exact: false,
      scoped: false,
      exactSource: lookup?.source || "api",
      fullSnapshot: lookup?.fullSnapshot !== false,
      textOnly: textSearchOnly()
    },
    lookup
  };
}

function hiddenInputsWithout(keys) {
  const params = new URLSearchParams(window.location.search);
  keys.forEach((key) => params.delete(key));
  return Array.from(params.entries()).map(([key, value]) => (
    `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`
  )).join("");
}

function searchHiddenInputs() {
  return hiddenInputsWithout(["q", "page"]);
}

function searchControls({id, label, placeholder, query, search}) {
  const clearLink = query
    ? `<a class="search-clear" href="${escapeHtml(hrefWithoutParams(["q", "page", "search"]))}">Clear</a>`
    : "";
  const exactScope = search?.fullSnapshot === false ? "exported rows" : "full snapshot";
  const exactSource = search?.exactSource === "static" ? "static exact lookup" : "exact lookup";
  const searchMeta = search
      ? `<p class="meta search-meta">${search.exact
      ? `${exactSource[0].toUpperCase()}${exactSource.slice(1)} "${escapeHtml(query)}" matched ${fmt.format(search.matchedCount)} ${exactScope} row.`
      : search.ip
        ? `IP search "${escapeHtml(query)}" matched ${fmt.format(search.matchedCount)} ${exactScope} ${search.matchedCount === 1 ? "name" : "names"}.`
        : search.scoped
        ? `${search.textOnly ? "Text search" : "Search"} "${escapeHtml(query)}" matched ${fmt.format(search.matchedCount)} of ${fmt.format(search.totalCount)} loaded rows.${search.textOnly ? "" : ` Exact name lookup still checks ${exactScope}.`}`
        : `${search.textOnly ? "Text search" : "Search"} "${escapeHtml(query)}" matched ${fmt.format(search.matchedCount)} of ${fmt.format(search.totalCount)} exported rows.`}</p>`
    : "";
  return `<form class="search-form" role="search" action="${escapeHtml(currentPageName())}" method="get">
    ${searchHiddenInputs()}
    <label class="search-label" for="${escapeHtml(id)}">${escapeHtml(label)}</label>
    <div class="search-row">
      <input id="${escapeHtml(id)}" type="search" name="q" value="${escapeHtml(query)}" placeholder="${escapeHtml(placeholder)}" autocomplete="off">
      <button class="search-button" type="submit">Search</button>
      ${clearLink}
    </div>
    ${searchMeta}
  </form>`;
}

function lookupNotice(pageData) {
  if (!pageData.lookup || !activeSearch()) return "";
  if (pageData.lookup.found) {
    if (pageData.lookup.source === "static") {
      const scope = pageData.lookup.fullSnapshot === false ? "the exported Names rows" : "the sorted static Names export";
      return `<p class="meta search-meta">Exact lookup used ${scope}.</p>`;
    }
    return `<p class="meta search-meta">Exact lookup uses the full snapshot.</p>`;
  }
  if (pageData.lookup.source === "static" && pageData.lookup.fullSnapshot === false) {
    return `<p class="meta search-meta">Exact lookup did not find ${escapeHtml(pageData.lookup.normalized || activeSearch())} in the exported Names rows. This export is truncated.</p>`;
  }
  return `<p class="meta search-meta">Exact lookup did not find ${escapeHtml(pageData.lookup.normalized || activeSearch())} in the full snapshot.</p>`;
}

function optionTag(value, label, active) {
  return `<option value="${escapeHtml(value)}"${value === active ? " selected" : ""}>${escapeHtml(label)}</option>`;
}

function filterOptgroup(label, options, active) {
  if (!options.length) return "";
  return `<optgroup label="${escapeHtml(label)}">${options.map((item) => optionTag(item.value, item.label, active)).join("")}</optgroup>`;
}

function visibleSummaryOptions(options, summary, active) {
  return options.filter((item) => {
    if (!item.countKey) return true;
    return Number(summary?.[item.countKey] || 0) > 0 || item.value === active;
  });
}

function namesFilterControls({summary, providers, broken, active}) {
  const providerOptions = providers
    .filter((row) => row.provider_key)
    .sort((a, b) => Number(b.names_count || 0) - Number(a.names_count || 0) || String(a.provider_key).localeCompare(String(b.provider_key)))
    .map((row) => ({
      value: `${PROVIDER_FILTER_PREFIX}${row.provider_key}`,
      label: `${row.provider_key} (${fmt.format(row.names_count || 0)})`
    }));
  const failureOptions = (broken.reasons || [])
    .filter((row) => Number(row.count || 0) > 0)
    .map((row) => ({
      value: `${FAILURE_REASON_FILTER_PREFIX}${row.failure_reason}`,
      label: `${prettyToken(row.failure_reason)} (${fmt.format(row.count || 0)})`
    }));
  const complianceOptions = (summary.compliance_stages || [])
    .filter((row) => Number(row.count || 0) > 0 || `${COMPLIANCE_STAGE_FILTER_PREFIX}${row.stage}` === active)
    .map((row) => ({
      value: row.filter || `${COMPLIANCE_STAGE_FILTER_PREFIX}${row.stage}`,
      label: `${row.label || stageLabel(row.stage)} (${fmt.format(row.count || 0)})`
    }));
  const generalOptions = [
    {value: "", label: "All names"},
    {value: "direct_ip_records", label: "SYNTH nameservers", countKey: "direct_ip_records"},
    {value: "delegated_names", label: "Delegated names", countKey: "delegated_names"},
    {value: "default_provider_names", label: "Default providers", countKey: "default_provider_names"},
    {value: "likely_websites", label: "Likely host roots", countKey: "likely_websites"},
    {value: "browser_target_names", label: "Browser targets", countKey: "browser_target_names"},
    {value: "live_site_names", label: "Live host evidence", countKey: "live_site_names"},
    {value: "strict_hns_ready", label: "Strict HNS ready", countKey: "strict_hns_ready"},
    {value: "strict_hns_working", label: "Strict HNS working", countKey: "strict_hns_working"},
    {value: "needs_fix", label: "Needs fix", countKey: "needs_fix"},
    {value: "doh_fallback_required", label: "Resolver fallback required", countKey: "doh_fallback_required"}
  ];
  const daneOptions = [
    {value: "ds_records", label: "DS records", countKey: "ds_records"},
    {value: "dnssec_candidates", label: "DNSSEC candidates", countKey: "dnssec_candidates"},
    {value: "static_tlsa_certificate_expired_names", label: "Static TLSA expired certificate", countKey: "static_tlsa_certificate_expired_names"},
    {value: "needs_dane", label: "Needs DANE", countKey: "needs_dane"},
    {value: "dane_working", label: "DANE verified", countKey: "dane_working"},
    {value: "stale_tlsa_only", label: "Stale TLSA", countKey: "stale_tlsa_only"}
  ];
  const browserOptions = [
    {value: "browser_evidence_names", label: "Any browser evidence", countKey: "browser_evidence_names"},
    {value: "browser_dane_verified_names", label: "Browser DANE verified", countKey: "browser_dane_verified_names"},
    {value: "browser_network_blocks_53_names", label: "Browser network blocks 53", countKey: "browser_network_blocks_53_names"},
    {value: "browser_certificate_expired_names", label: "Browser expired certificate", countKey: "browser_certificate_expired_names"}
  ];
  const clearLink = active
    ? `<a class="search-clear" href="${escapeHtml(hrefWithoutParams(["filter", "page"]))}">Clear</a>`
    : "";
  return `<form class="filter-form" action="${escapeHtml(currentPageName())}" method="get">
    ${hiddenInputsWithout(["filter", "page"])}
    <label class="filter-field" for="names-filter">
      <span class="search-label">Filter</span>
      <select id="names-filter" name="filter">
        ${filterOptgroup("Compliance Stage", complianceOptions, active)}
        ${filterOptgroup("General", visibleSummaryOptions(generalOptions, summary, active), active)}
        ${filterOptgroup("DANE and DNSSEC", visibleSummaryOptions(daneOptions, summary, active), active)}
        ${filterOptgroup("Browser Evidence", visibleSummaryOptions(browserOptions, summary, active), active)}
        ${filterOptgroup("Failure Reasons", failureOptions, active)}
        ${filterOptgroup("Providers", providerOptions, active)}
      </select>
    </label>
    ${clearLink}
  </form>`;
}

function wireAutoSubmitFilter() {
  const select = document.getElementById("names-filter");
  if (!select) return;
  select.addEventListener("change", () => select.form.submit());
}

function adoptionFunnel(summary) {
  const active = Number(summary.active_names || 0);
  const checked = Number(summary.host_live_check_checked_count ?? summary.live_check_checked_count ?? 0);
  const candidates = Number(summary.host_live_check_candidate_count ?? summary.live_check_candidate_count ?? 0);
  const stages = (summary.compliance_stages || []).filter((stage) => Number(stage.count || 0) > 0);
  return `<section class="panel adoption-funnel">
    <div class="panel-heading">
      <div>
        <h2>Host Verification Pipeline</h2>
        <p class="meta">${fmt.format(checked)} host checks sampled from ${fmt.format(candidates)} candidates. Terminal state is signed TLSA matching the live HTTPS key.</p>
      </div>
    </div>
    <div class="funnel-grid">${stages.map((stage) => `
      <a class="funnel-stage" href="${escapeHtml(sitePath(stage.filter_link || `names.html?filter=${COMPLIANCE_STAGE_FILTER_PREFIX}${stage.stage}`))}">
        <span>${escapeHtml(stage.label || stageLabel(stage.stage))}</span>
        <strong>${fmt.format(stage.count ?? 0)}</strong>
        <small>${pct(stage.count ?? 0, active)} of active. ${escapeHtml(stage.definition || stageDefinition(stage.stage))}</small>
      </a>`).join("")}</div>
  </section>`;
}

function nextActionsPanel(actions = []) {
  if (!actions.length) return "";
  return `<article class="panel next-actions-panel">
    <h2>Generator Handoffs</h2>
    <div class="next-action-list">${actions.map((action) => `
      <a class="next-action" href="${escapeHtml(sitePath(action.filter_link || "names.html"))}">
        <span>${escapeHtml(action.label)}</span>
        <strong>${fmt.format(action.count ?? 0)}</strong>
        <small>${escapeHtml(action.definition || "")}</small>
      </a>`).join("")}</div>
  </article>`;
}

function filterFromLink(link) {
  try {
    return new URL(sitePath(link || "names.html"), window.location.origin).searchParams.get("filter") || "";
  } catch (_error) {
    return "";
  }
}

function actionForFilter(actions = [], filter = "") {
  if (!filter) return null;
  return actions.find((action) => (action.filter || filterFromLink(action.filter_link)) === filter) || null;
}

function namesActionContext(actions = [], filter = "") {
  const action = actionForFilter(actions, filter);
  if (!action) return "";
  return `<section class="queue-context" data-generator-intent="${escapeHtml(action.generator_intent || "")}">
    <div>
      <span class="search-label">Generator Queue</span>
      <strong>${escapeHtml(action.label)}</strong>
    </div>
    <p class="meta">${escapeHtml(action.definition || "")}</p>
  </section>`;
}

function hostDirectoryPanel(directory) {
  const rows = (directory?.rows || []).slice(0, 12);
  const columns = [
    {
      key: "host",
      label: "Host",
      render: (row) => `<a href="${escapeHtml(row.url || `https://${row.host}/`)}">${escapeHtml(row.host || "")}</a>`
    },
    {
      key: "root_name",
      label: "Root",
      render: (row) => `<a href="${escapeHtml(sitePath(`names.html?q=${encodeURIComponent(row.root_name || "")}&host=${encodeURIComponent(row.host || "")}`))}">${escapeHtml(row.root_name || "")}</a>`
    },
    {key: "directory_status", label: "Status", render: (row) => escapeHtml(prettyToken(row.directory_status || row.evidence_confidence || row.evidence_source || ""))},
    {key: "dane_status", label: "DANE", render: (row) => statusPill(row.dane_status || "")},
    {key: "https_status", label: "HTTPS", render: (row) => statusPill(row.https_status || "")},
    {key: "checked_at", label: "Checked", render: lastCheckedCell}
  ];
  return `<section class="panel">
    <div class="panel-heading">
      <div>
        <h2>Live HNS Hosts</h2>
        <p class="meta">${fmt.format(directory?.row_count || 0)} host rows with crawler or browser evidence.</p>
      </div>
      <a href="${escapeHtml(sitePath("names.html?filter=live_site_names"))}">Root diagnostics</a>
    </div>
    ${table(rows, columns, "No live hosts in this snapshot.")}
  </section>`;
}

async function renderOverview(app) {
  const summary = await loadJson("data/summary.json");
  const hostDirectory = await loadJson("data/host-directory.json");
  const providers = summary.providers || [];
  const classes = summary.classes || [];
  app.innerHTML = `${snapshot(summary)}
    ${hostDirectoryPanel(hostDirectory)}
    ${adoptionFunnel(summary)}
    <section class="grid">
      ${nextActionsPanel(summary.next_actions || [])}
      ${topologySignals(summary)}
      <article class="panel"><h2>Provider Concentration</h2>${bars(providers, "provider_key", "names_count", 12, (value) => value, providerFilterHref)}</article>
      <article class="panel"><h2>Parent-Side State</h2>${bars(classes, "class", "count", 12, classLabel, (row) => classFilterHref(row.class))}</article>
      <article class="panel"><h2>Run Metadata</h2>
      <p class="meta">Height ${summary.last_indexed_height ?? ""} generated ${summary.generated_at ?? ""}</p>
      <p class="meta">Source ${escapeHtml(summary.source_type || "unknown")} - rules v${summary.provider_rules_version ?? ""} ${escapeHtml((summary.provider_rules_hash || "").slice(0, 12))}</p>
      ${liveCheckMeta(summary)}</article>
    </section>`;
}

function pageLink(label, targetPage, disabled) {
  if (disabled) return `<span class="page-link disabled">${escapeHtml(label)}</span>`;
  return `<a class="page-link" href="${escapeHtml(hrefWithPage(targetPage))}">${escapeHtml(label)}</a>`;
}

function namesPagination(collection, page) {
  const pageCount = Number(collection.page_count || 0);
  if (pageCount <= 1) return "";
  const safePage = Math.min(Math.max(1, page), pageCount);
  return `<nav class="pagination names-pagination" aria-label="Name audit pages">
    ${pageLink("First", 1, safePage <= 1)}
    ${pageLink("Previous", safePage - 1, safePage <= 1)}
    <span class="page-status">Page ${fmt.format(safePage)} of ${fmt.format(pageCount)}</span>
    ${pageLink("Next", safePage + 1, safePage >= pageCount)}
    ${pageLink("Last", pageCount, safePage >= pageCount)}
  </nav>`;
}

function shortenName(value) {
  const name = String(value || "");
  if (name.length <= 18) return name;
  return `${name.slice(0, 15)}...`;
}

function nameCell(row) {
  const name = String(row.name || "");
  return `<span class="name-cell" title="${escapeHtml(name)}">${escapeHtml(shortenName(name))}</span>`;
}

function ipFieldsCell(row) {
  const fields = Array.isArray(row.fields) ? row.fields : String(row.fields || "").split(",").filter(Boolean);
  return fields.map((field) => `<code>${escapeHtml(field)}</code>`).join(" ");
}

function complianceStageCell(row) {
  const stage = complianceStage(row);
  return `<span title="${escapeHtml(stageDefinition(stage))}">${escapeHtml(stageLabel(stage))}</span>`;
}

function exactNameLookupCell(row) {
  const name = String(row.name || "");
  if (!name) return "";
  return `<a href="${escapeHtml(sitePath(namesSearchHref(name, {filter: ""})))}">Open name</a>`;
}

function lastCheckedCell(row) {
  const checkedAt = String(row.checked_at || "");
  if (!checkedAt) return "";
  return `<span title="${escapeHtml(checkedAt)}">${escapeHtml(checkedAt.replace("T", " ").replace(/:\d\d(?:\.\d+)?Z$/, " UTC"))}</span>`;
}

function listValues(...values) {
  const seen = new Set();
  const result = [];
  values.flatMap((value) => Array.isArray(value) ? value : [value]).forEach((value) => {
    const text = String(value || "").trim();
    if (!text || seen.has(text)) return;
    seen.add(text);
    result.push(text);
  });
  return result;
}

function trailingDot(value) {
  const text = String(value || "").trim();
  return text && !text.endsWith(".") ? `${text}.` : text;
}

function hnsRootFromNs(ns, fallback) {
  const normalized = String(ns || "").toLowerCase().replace(/\.+$/, "");
  const labels = normalized.split(".").filter(Boolean);
  return labels.length ? labels[labels.length - 1] : fallback;
}

function hnsNameLink(root, label) {
  const name = String(root || "").toLowerCase().replace(/\.+$/, "");
  const text = label || root;
  if (!/^[a-z0-9-]{1,63}$/.test(name)) return escapeHtml(text);
  return `<a href="${escapeHtml(sitePath(namesSearchHref(name)))}">${escapeHtml(text)}</a>`;
}

function codeLine(value) {
  return `<code>${escapeHtml(value)}</code>`;
}

function dsRecordLine(record) {
  if (!record || typeof record !== "object") return "";
  return [
    record.keyTag,
    record.algorithm,
    record.digestType,
    String(record.digest || "").toLowerCase()
  ].filter((value) => value !== null && value !== undefined && value !== "").join(" ");
}

function resourceRecordBlock(label, lines) {
  if (!lines.length) return "";
  return lines.map((line) => `<div class="resource-record"><span>${escapeHtml(label)}</span>${line}</div>`).join("");
}

function resourceRecordSections(row) {
  const sections = [];
  const name = String(row.name || "");
  const nsNames = listValues(row.ns_names, row.first_ns).map(trailingDot);
  const glue4 = listValues(row.glue4, row.first_glue4);
  const glue6 = listValues(row.glue6, row.first_glue6);
  const synth4 = listValues(row.synth4, row.first_synth4);
  const synth6 = listValues(row.synth6, row.first_synth6);
  const dsRecords = Array.isArray(row.ds_records) ? row.ds_records : [];

  sections.push(resourceRecordBlock("DS", dsRecords.map(dsRecordLine).filter(Boolean).map(codeLine)));
  sections.push(resourceRecordBlock("GLUE4", glue4.map((address, index) => {
    const ns = nsNames[index] || nsNames[0] || name;
    return `${hnsNameLink(hnsRootFromNs(ns, name), ns)}${codeLine(address)}`;
  })));
  sections.push(resourceRecordBlock("GLUE6", glue6.map((address, index) => {
    const ns = nsNames[index] || nsNames[0] || name;
    return `${hnsNameLink(hnsRootFromNs(ns, name), ns)}${codeLine(address)}`;
  })));
  sections.push(resourceRecordBlock("NS", nsNames.map((ns) => hnsNameLink(hnsRootFromNs(ns, name), ns))));
  sections.push(resourceRecordBlock("SYNTH4", synth4.map(codeLine)));
  sections.push(resourceRecordBlock("SYNTH6", synth6.map(codeLine)));

  return sections.filter(Boolean).join("");
}

function resourceMetadata(row) {
  const items = [];
  if (row.resource_version !== null && row.resource_version !== undefined && row.resource_version !== "") {
    items.push(["Version", row.resource_version]);
  }
  if (row.raw_size !== null && row.raw_size !== undefined && row.raw_size !== "") {
    items.push(["Size", `${fmt.format(Number(row.raw_size || 0))} Bytes`]);
  }
  if (row.resource_hash) {
    items.push(["Hash", String(row.resource_hash)]);
  }
  if (row.last_seen_height !== null && row.last_seen_height !== undefined && row.last_seen_height !== "") {
    items.push(["Height", row.last_seen_height]);
  }
  if (row.updated_at) {
    items.push(["Indexed", String(row.updated_at).replace("T", " ").replace(/:\d\d(?:\.\d+)?Z$/, " UTC")]);
  }
  if (!items.length) return "";
  return `<dl class="diagnostic-kv">${items.map(([key, value]) => `
    <div><dt>${escapeHtml(key)}</dt><dd title="${escapeHtml(value)}">${escapeHtml(value)}</dd></div>`).join("")}</dl>`;
}

function liveDiagnosticStatus(row) {
  const stage = complianceStage(row);
  const fields = [
    ["Compliance stage", stageLabel(stage)],
    ["DNS reachable", row.dns_reachable],
    ["DNSSEC", row.dnssec_status],
    ["TLSA", row.tlsa_status],
    ["DANE", row.dane_status],
    ["HTTPS", row.https_status],
    ["Strict HNS", row.strict_hns_status],
    ["Resolver fallback", row.doh_fallback_status],
    ["Failure", row.failure_reason],
    ["NS handoff", row.ns_handoff_ns],
    ["NS handoff root", row.ns_handoff_root ? `${row.ns_handoff_root}/` : ""],
    ["NS handoff bootstrap", row.ns_handoff_bootstrap_ip
      ? `${row.ns_handoff_bootstrap_field || "bootstrap"} ${row.ns_handoff_bootstrap_ip}`
      : ""],
    ["Static TLSA cert notAfter", row.tlsa_cert_not_valid_after],
    ["Static TLSA cert expired", row.tlsa_cert_expired === true ? "yes" : ""],
    ["Cert notAfter", row.https_cert_not_valid_after],
    ["Cert SHA-256", row.https_cert_sha256],
    ["SPKI SHA-256", row.https_spki_sha256],
    ["Last checked", row.checked_at ? String(row.checked_at).replace("T", " ").replace(/:\d\d(?:\.\d+)?Z$/, " UTC") : ""],
    ["Browser result", row.browser_result],
    ["Browser HNS proof", row.browser_hns_proof],
    ["Browser resolution", row.browser_resolution_source],
    ["Browser UDP 53", row.browser_authoritative_udp],
    ["Browser TCP 53", row.browser_authoritative_tcp],
    ["Browser authoritative DoH", row.browser_authoritative_doh],
    ["Browser fallback", row.browser_fallback_used === true ? (row.browser_fallback_reason || "used") : ""],
    ["Browser cert notAfter", row.browser_certificate_not_valid_after],
    ["Browser cert expired", row.browser_certificate_expired === true ? "yes" : ""],
    ["Browser effect", row.browser_evidence_effect],
    ["Browser action", row.browser_action_label],
    ["Browser captured", row.browser_captured_at ? String(row.browser_captured_at).replace("T", " ").replace(/:\d\d(?:\.\d+)?Z$/, " UTC") : ""]
  ].filter(([, value]) => value !== null && value !== undefined && value !== "");
  if (!fields.length) return `<p class="meta">No live-check result in this row.</p>`;
  return `<dl class="diagnostic-kv">${fields.map(([key, value]) => `
    <div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(prettyToken(value))}</dd></div>`).join("")}</dl>`;
}

function complianceChecklist(row) {
  const items = complianceChecklistItems(row);
  return `<section class="compliance-checklist-panel">
    <h3>Compliance Checklist</h3>
    <div class="compliance-checklist">${items.map((item) => `
      <article class="checklist-item checklist-${escapeHtml(item.status)}">
        <div>
          <strong>${escapeHtml(item.label)}</strong>
          <p>${escapeHtml(item.detail)}</p>
        </div>
        <span>${escapeHtml(checklistStatusLabel(item.status))}</span>
      </article>`).join("")}</div>
  </section>`;
}

function complianceChecklistItems(row) {
  return [
    parentDelegationCheck(row),
    hnsBootstrapCheck(row),
    dnssecChainCheck(row),
    tlsaOwnerCheck(row),
    httpsSpkiCheck(row),
    resolverFallbackCheck(row),
    browserEvidencePolicyCheck(row)
  ];
}

function browserEvidencePolicyCheck(row) {
  const effect = row.browser_evidence_effect || "";
  if (!effect) {
    return {label: "Browser evidence", status: "pending", detail: "No browser/device evidence is available yet."};
  }
  if (row.browser_evidence_severity === "action") {
    return {label: "Browser evidence", status: "fail", detail: row.browser_action_detail || "Latest browser evidence requires action."};
  }
  if (row.browser_evidence_severity === "review") {
    return {label: "Browser evidence", status: "warn", detail: row.browser_action_detail || "Latest browser evidence should be compared with crawler results."};
  }
  if (row.browser_evidence_severity === "pass") {
    return {label: "Browser evidence", status: "pass", detail: row.browser_action_detail || "Browser evidence agrees with crawler results."};
  }
  return {label: "Browser evidence", status: "pass", detail: row.browser_action_detail || "Browser evidence is contextual and does not change domain compliance."};
}

function checklistStatusLabel(status) {
  return ({
    pass: "Pass",
    warn: "Review",
    fail: "Action",
    pending: "Pending",
    skip: "N/A"
  })[status] || prettyToken(status);
}

function parentDelegationCheck(row) {
  const stage = complianceStage(row);
  if (hasNs(row)) {
    return {label: "Parent delegation", status: "pass", detail: "Parent resource publishes NS delegation."};
  }
  if (hasSynth(row)) {
    return {label: "Parent delegation", status: "pass", detail: "Parent resource publishes SYNTH nameserver bootstrap."};
  }
  if (stage === "non_actionable") {
    return {label: "Parent delegation", status: "skip", detail: "No actionable parent delegation in this resource."};
  }
  return {label: "Parent delegation", status: "fail", detail: "No NS or SYNTH delegation material is present."};
}

function hnsBootstrapCheck(row) {
  if (hasSynth(row)) {
    return {label: "HNS bootstrap", status: "pass", detail: "SYNTH bootstrap address is available from the HNS resource."};
  }
  if (hasGlue(row)) {
    return {label: "HNS bootstrap", status: "pass", detail: "Delegated nameserver has parent-side GLUE."};
  }
  if (hasNsHandoff(row)) {
    return {
      label: "HNS bootstrap",
      status: "warn",
      detail: `No direct GLUE for this name; resolve ${trailingDot(row.ns_handoff_ns)} through ${row.ns_handoff_root}/ first.`
    };
  }
  if (hasNs(row)) {
    return {label: "HNS bootstrap", status: "fail", detail: "Delegation exists but GLUE bootstrap addresses are missing."};
  }
  return {label: "HNS bootstrap", status: "pending", detail: "No strict HNS bootstrap path is visible yet."};
}

function dnssecChainCheck(row) {
  const failure = row.failure_reason || "";
  if (row.dane_status === "valid" || row.dnssec_status === "valid") {
    return {label: "DNSSEC chain", status: "pass", detail: "Latest live check validated the DNSSEC chain."};
  }
  if (failure === "dnssec_missing" || failure === "dnssec_bogus" || failure === "ds_dnskey_mismatch" || failure === "rrsig_expired" || ["bogus", "ds_dnskey_mismatch", "rrsig_expired", "missing_dnskey", "missing_rrsig"].includes(row.dnssec_status)) {
    return {label: "DNSSEC chain", status: "fail", detail: `DNSSEC validation failed: ${prettyToken(failure || row.dnssec_status)}.`};
  }
  if (hasDs(row)) {
    return {label: "DNSSEC chain", status: "pending", detail: "Parent DS is present; delegated DNSSEC has not been validated yet."};
  }
  return {label: "DNSSEC chain", status: "fail", detail: "No parent DS record is present."};
}

function tlsaOwnerCheck(row) {
  const failure = row.failure_reason || "";
  if (row.dane_status === "valid" || row.tlsa_status === "present") {
    return {label: "TLSA owner", status: "pass", detail: "TLSA data was observed at the HTTPS service owner."};
  }
  if (failure === "tlsa_wrong_owner") {
    return {label: "TLSA owner", status: "fail", detail: "TLSA data was found at the wrong owner name."};
  }
  if (complianceStage(row) === "tlsa_gap" || row.tlsa_status === "missing") {
    return {label: "TLSA owner", status: "fail", detail: "No matching _443._tcp TLSA owner has been proven."};
  }
  return {label: "TLSA owner", status: "pending", detail: "TLSA owner evidence is not available yet."};
}

function httpsSpkiCheck(row) {
  const failure = row.failure_reason || "";
  const stage = complianceStage(row);
  if (row.dane_status === "valid") {
    return {label: "HTTPS SPKI match", status: "pass", detail: "HTTPS certificate/SPKI matched the TLSA association."};
  }
  if (row.browser_certificate_expired === true && failure !== "certificate_expired") {
    return {label: "HTTPS SPKI match", status: "fail", detail: "Latest browser evidence saw an expired HTTPS certificate; renew it before treating TLSA/DANE gaps as current."};
  }
  if (stage === "stale_tlsa" || failure === "stale_tlsa_spki_mismatch" || row.dane_status === "invalid") {
    return {label: "HTTPS SPKI match", status: "fail", detail: "TLSA data does not match the current HTTPS certificate/SPKI."};
  }
  if (failure === "certificate_expired") {
    return {label: "HTTPS SPKI match", status: "fail", detail: "HTTPS certificate is expired; renew it before treating TLSA/DANE gaps as current."};
  }
  if (stage === "service_blocked") {
    return {label: "HTTPS SPKI match", status: "fail", detail: "Live service failure blocked certificate/SPKI proof."};
  }
  if (row.https_status === "working" || row.https_status === "tls_unverified") {
    return {label: "HTTPS SPKI match", status: "pending", detail: "HTTPS certificate was reachable; TLSA/SPKI match is not proven yet."};
  }
  return {label: "HTTPS SPKI match", status: "pending", detail: "No HTTPS SPKI match result is available yet."};
}

function resolverFallbackCheck(row) {
  const fallback = row.doh_fallback_status || "";
  const browserPort53Blocked = isBrowserPort53Blocked(row);
  if (complianceStage(row) === "resolver_fallback" || fallback === "required" || fallback === "doh_fallback_only" || row.failure_reason === "doh_fallback_only") {
    return {label: "Resolver fallback", status: "warn", detail: "Latest check required the fallback resolver path."};
  }
  if (fallback === "not_required" || row.strict_hns_status === "working" || row.dane_status === "valid") {
    if (browserPort53Blocked) {
      return {label: "Resolver fallback", status: "pass", detail: "Crawler strict HNS did not require fallback; latest browser fallback appears to be client-network port 53 blocking context."};
    }
    return {label: "Resolver fallback", status: "pass", detail: "Strict HNS completed without resolver fallback."};
  }
  if (browserPort53Blocked) {
    return {label: "Resolver fallback", status: "pending", detail: "Latest browser trace fell back because the client network blocks UDP/TCP 53; this is device context, not domain-side proof of resolver fallback."};
  }
  return {label: "Resolver fallback", status: "pending", detail: "No resolver fallback result is available yet."};
}

function isBrowserPort53Blocked(row) {
  const reason = String(row.browser_fallback_reason || "").toLowerCase();
  if (reason === "network_blocks_53") return true;
  const udp = String(row.browser_authoritative_udp || "").toLowerCase();
  const tcp = String(row.browser_authoritative_tcp || "").toLowerCase();
  const doh = String(row.browser_authoritative_doh || "").toLowerCase();
  return ["blocked", "timeout", "transport_error"].includes(udp)
    && ["blocked", "timeout", "transport_error", "not_attempted"].includes(tcp)
    && doh === "ok";
}

function dnsProbeCommands(row) {
  const name = String(row.name || "").replace(/\.+$/, "");
  const server = firstValue(row.synth4) || firstValue(row.glue4) || row.first_synth4 || row.first_glue4
    || firstValue(row.synth6) || firstValue(row.glue6) || row.first_synth6 || row.first_glue6;
  const nsHost = trailingDot(firstValue(row.ns_names) || row.first_ns || row.ns_handoff_ns);
  if (!name) return [];
  if (!server && hasNsHandoff(row)) {
    return [
      ...dnsTransportCommands(row.ns_handoff_bootstrap_ip, nsHost, "A"),
      ...dnsTransportCommands(row.ns_handoff_bootstrap_ip, nsHost, "AAAA"),
      ...dnsTransportCommands(row.ns_handoff_bootstrap_ip, `_dns.${nsHost}`, "SVCB"),
      ...targetProbeCommands(name, "<resolved-ns-ip>")
    ];
  }
  if (!server) return [];
  return [
    ...(nsHost ? dnsTransportCommands(server, `_dns.${nsHost}`, "SVCB") : []),
    ...targetProbeCommands(name, server)
  ];
}

function targetProbeCommands(name, server) {
  return [
    ...dnsTransportCommands(server, `${name}.`, "A"),
    ...dnsTransportCommands(server, `${name}.`, "AAAA"),
    ...dnsTransportCommands(server, `_443._tcp.${name}.`, "TLSA"),
    ...dnsTransportCommands(server, `${name}.`, "DNSKEY")
  ];
}

function dnsTransportCommands(server, qname, rrtype) {
  if (!server || !qname || !rrtype) return [];
  return [
    `dig @${server} ${qname} ${rrtype} +norecurse +dnssec`,
    `dig @${server} ${qname} ${rrtype} +tcp +norecurse +dnssec`
  ];
}

function dnsEvidenceSection(row) {
  const path = row.dns_evidence_path || "";
  if (!path) return `<section><h3>Observed DNS</h3><p class="meta">No stored DNS evidence for this name yet.</p></section>`;
  return `<section>
    <h3>Observed DNS</h3>
    <div class="dns-evidence-body" data-evidence-path="${escapeHtml(path)}">
      <p class="meta">Open diagnostics to load stored DNS evidence.</p>
    </div>
  </section>`;
}

function browserEvidenceSection(row) {
  const path = row.browser_evidence_path || "";
  if (!path) return `<section><h3>Browser Evidence</h3><p class="meta">No imported browser evidence for this name yet.</p></section>`;
  return `<section>
    <h3>Browser Evidence</h3>
    <div class="browser-evidence-body" data-browser-evidence-path="${escapeHtml(path)}">
      <p class="meta">Open diagnostics to load imported browser evidence.</p>
    </div>
  </section>`;
}

function renderDnsEvidence(payload) {
  const observations = Array.isArray(payload?.observations) ? payload.observations : [];
  if (!observations.length) return `<p class="meta">No stored DNS evidence for this name yet.</p>`;
  return `<div class="dns-evidence-list">${observations.map((item) => {
    const title = `${item.qname || ""} ${item.rrtype || ""}`.trim();
    const meta = [
      item.server ? `@${item.server}` : "",
      item.source || "",
      item.source_id || "",
      item.rcode || item.status || "",
      item.captured_at || ""
    ].filter(Boolean).join(" - ");
    return `<article class="dns-evidence-item">
      <header><strong>${escapeHtml(title)}</strong><span>${escapeHtml(meta)}</span></header>
      ${evidenceLines("Answer", item.answer)}
      ${evidenceLines("Authority", item.authority)}
      ${evidenceLines("Additional", item.additional)}
      ${item.error ? `<p class="meta">Error: ${escapeHtml(item.error)}</p>` : ""}
    </article>`;
  }).join("")}</div>`;
}

function renderBrowserEvidence(payload) {
  const observations = Array.isArray(payload?.observations) ? payload.observations : [];
  if (!observations.length) return `<p class="meta">No imported browser evidence for this name yet.</p>`;
  return `<div class="dns-evidence-list">${observations.map((item) => {
    const title = `${item.host || payload.name || ""} ${item.browser_result || item.evidence_type || ""}`.trim();
    const meta = [
      item.source || "",
      item.source_id || "",
      item.mode || "",
      item.resolution_source || "",
      item.captured_at || ""
    ].filter(Boolean).join(" - ");
    const fields = [
      ["Status", item.status_code],
      ["Stage", item.stage],
      ["Reason", item.reason],
      ["DNSSEC", item.dnssec_status],
      ["TLSA", item.tlsa_status],
      ["DANE", item.dane_status],
      ["TLSA owner", item.tlsa_owner],
      ["UDP 53", item.authoritative_udp],
      ["TCP 53", item.authoritative_tcp],
      ["Authoritative DoH", item.authoritative_doh],
      ["Fallback", item.fallback_used === true ? (item.fallback_reason || "used") : ""],
      ["Cert SHA-256", item.certificate_sha256],
      ["SPKI SHA-256", item.spki_sha256],
      ["Cert notAfter", item.certificate_not_valid_after],
      ["Certificate expired", item.certificate_expired === true ? "yes" : ""],
      ["Final error", item.final_error]
    ].filter(([, value]) => value !== null && value !== undefined && value !== "");
    return `<article class="dns-evidence-item">
      <header><strong>${escapeHtml(title)}</strong><span>${escapeHtml(meta)}</span></header>
      <dl class="diagnostic-kv">${fields.map(([key, value]) => `
        <div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(prettyToken(value))}</dd></div>`).join("")}</dl>
    </article>`;
  }).join("")}</div>`;
}

function evidenceLines(label, lines) {
  if (!Array.isArray(lines) || !lines.length) return "";
  return `<div class="evidence-lines"><span>${escapeHtml(label)}</span>${lines.map(codeLine).join("")}</div>`;
}

function wireNameDetails() {
  document.querySelectorAll(".name-detail").forEach((details) => {
    details.addEventListener("toggle", async () => {
      if (!details.open) return;
      await loadLazyEvidence(details, "dns");
      await loadLazyEvidence(details, "browser");
    });
  });
}

async function loadLazyEvidence(details, kind) {
  const datasetKey = `${kind}EvidenceLoaded`;
  if (details.dataset[datasetKey] === "true") return;
  const bodyClass = kind === "browser" ? ".browser-evidence-body" : ".dns-evidence-body";
  const pathKey = kind === "browser" ? "browserEvidencePath" : "evidencePath";
  const target = details.querySelector(bodyClass);
  const path = details.dataset[pathKey];
  if (!target || !path) return;
  target.innerHTML = `<p class="meta">Loading ${kind} evidence...</p>`;
  try {
    const payload = await loadJson(`data/${path}`);
    target.innerHTML = kind === "browser" ? renderBrowserEvidence(payload) : renderDnsEvidence(payload);
    details.dataset[datasetKey] = "true";
  } catch (error) {
    target.innerHTML = `<p class="meta">Could not load ${kind} evidence: ${escapeHtml(error.message)}</p>`;
  }
}

function nameDetailRow(row, colspan) {
  const name = String(row.name || "");
  const displayName = name || String(row.domain || row.normalized || "Selected name");
  const records = resourceRecordSections(row);
  const recordTypesText = recordTypes(row).join(", ");
  const commands = dnsProbeCommands(row);
  const compactNotice = !Array.isArray(row.ds_records) && hasRecordType(row, "DS")
    ? `<p class="meta">Compact row: DS payload is not embedded in this collection.</p>`
    : "";
  const evidenceAttr = row.dns_evidence_path
    ? ` data-evidence-path="${escapeHtml(row.dns_evidence_path)}"`
    : "";
  const browserEvidenceAttr = row.browser_evidence_path
    ? ` data-browser-evidence-path="${escapeHtml(row.browser_evidence_path)}"`
    : "";
  return `<tr class="name-detail-row"><td colspan="${colspan}">
    <details class="name-detail"${evidenceAttr}${browserEvidenceAttr}>
      <summary><strong class="name-detail-name">${escapeHtml(displayName)}</strong><span>Audit diagnostics</span></summary>
      <div class="name-detail-grid">
        ${complianceChecklist(row)}
        <section>
          <h3>Latest Resource</h3>
          ${resourceMetadata(row)}
          ${recordTypesText ? `<p class="meta">Types: ${escapeHtml(recordTypesText)}</p>` : ""}
          <div class="resource-records">${records || `<p class="meta">No resource records in this row.</p>`}</div>
          ${compactNotice}
        </section>
        <section>
          <h3>Live Check</h3>
          ${liveDiagnosticStatus(row)}
          ${commands.length ? `<div class="dns-probes">${commands.map(codeLine).join("")}</div>` : ""}
        </section>
        ${dnsEvidenceSection(row)}
        ${browserEvidenceSection(row)}
      </div>
    </details>
  </td></tr>`;
}

function namesColumns(rowDetail) {
  if (rowDetail === "ip_matches") {
    return [
      {key: "name", label: "Name", render: nameCell, width: "35%"},
      {key: "matched_ip", label: "IP", width: "20%"},
      {key: "fields", label: "Matched fields", render: ipFieldsCell, width: "25%"},
      {key: "lookup", label: "Lookup", render: exactNameLookupCell, width: "20%"}
    ];
  }
  const compactColumns = [
    {key: "name", label: "Name", render: nameCell, width: "10%"},
    {key: "next_step", label: "Next step", render: actionCell, width: "16%"},
    {key: "compliance_stage", label: "Stage", render: complianceStageCell, width: "10%"},
    {key: "provider_guess", label: "Provider", width: "10%"},
    {key: "provider_type", label: "Provider type", width: "9%"},
    {key: "record_types", label: "Records", width: "8%"},
    {key: "has_ds", label: "DS", width: "4%"},
    {key: "dnssec_status", label: "DNSSEC", width: "7%"},
    {key: "tlsa_status", label: "TLSA", width: "6%"},
    {key: "dane_status", label: "DANE", width: "6%"},
    {key: "failure_reason", label: "Failure", width: "7%"},
    {key: "checked_at", label: "Last checked", render: lastCheckedCell, width: "7%"}
  ];
  if (rowDetail === "compact") return compactColumns;
  return [
    {...compactColumns[0], width: "8%"},
    {...compactColumns[1], width: "14%"},
    {...compactColumns[2], width: "8%"},
    {...compactColumns[3], width: "8%"},
    {...compactColumns[4], width: "7%"},
    {...compactColumns[5], width: "6%"},
    {key: "ns_names", label: "NS", width: "8%"},
    {key: "synth4", label: "SYNTH4", width: "6%"},
    {key: "synth6", label: "SYNTH6", width: "6%"},
    {...compactColumns[6], width: "3%"},
    {...compactColumns[7], width: "5%"},
    {...compactColumns[8], width: "4%"},
    {...compactColumns[9], width: "4%"},
    {...compactColumns[10], width: "6%"},
    {...compactColumns[11], width: "7%"}
  ];
}

async function renderNames(app) {
  const [summary, loadedPageData] = await Promise.all([
    loadJson("data/summary.json"),
    loadPaginatedRows("data/names-pages.json", activeFilter())
  ]);
  const providers = summary.providers || [];
  const broken = summary.broken || {reasons: []};
  const filter = activeFilter();
  const query = activeSearch();
  const pageData = await applySearchToPageData(loadedPageData, query);
  const columns = namesColumns(pageData.collection.row_detail);
  const detailRender = pageData.collection.row_detail === "ip_matches" ? null : nameDetailRow;
  app.innerHTML = `${filterNotice(filter, pageData.index.collections.all.row_count, loadedPageData.collection.row_count)}
    <section class="names-layout">
      <div class="panel names-main">
        <div class="panel-heading">
          <div><h2>Names</h2><p class="meta">${pageRangeMeta(pageData.collection, pageData.page, pageData.rows)} - height ${summary.last_indexed_height ?? ""}</p></div>
        </div>
        ${namesFilterControls({summary, providers, broken, active: filter})}
        ${searchControls({
          id: "names-search",
          label: "Search Names",
          placeholder: "Name, provider, records, status",
          query,
          search: pageData.search
        })}
        ${namesActionContext(summary.next_actions || [], filter)}
        ${lookupNotice(pageData)}
        ${namesPagination(pageData.collection, pageData.page)}
        ${table(pageData.rows, columns, query ? "No names match this search." : "No rows in this page.", {
          wrapClass: "names-table-wrap",
          tableClass: "names-table",
          detailRender,
          rowClass: detailRender ? "name-summary-row" : ""
        })}
        ${namesPagination(pageData.collection, pageData.page)}
      </div>
  </section>`;
  wireAutoSubmitFilter();
  wireNameDetails();
}

async function boot() {
  const page = document.body.dataset.page || "overview";
  setActiveNav(page);
  const app = document.getElementById("app");
  const renderers = {
    overview: renderOverview,
    names: renderNames
  };
  try {
    await (renderers[page] || renderOverview)(app);
  } catch (error) {
    app.innerHTML = `<section class="panel"><h2>Load Failed</h2><p class="definition">${escapeHtml(error.message)}</p></section>`;
  }
}

boot();

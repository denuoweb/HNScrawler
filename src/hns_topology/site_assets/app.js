const fmt = new Intl.NumberFormat("en-US");
const SITE_BASE_PATH = window.__HNS_TOPOLOGY_BASE__ || "/hns-topology/";
const PAGE_FETCH_MIN_DELAY_MS = 350;
const COLLECTION_FETCH_BATCH_SIZE = 8;
const SEARCH_FULL_SCAN_MAX_ROWS = 5000;
const PROVIDER_FILTER_PREFIX = "provider:";
const COMPLIANCE_STAGE_FILTER_PREFIX = "stage:";
const DANE_GENERATOR_BASE = window.__DANE_GENERATOR_BASE__ || "/dane-generator/";
const LIVE_DIRECTORY_SUMMARY_PATH = "/hns-live/data/summary.json";
const LIVE_STATUS_BASE_PATH = "/hns-live/data/live-status/";
const IP_FIELD_MAP = {
  1: "GLUE4",
  2: "GLUE6",
  4: "SYNTH4",
  8: "SYNTH6"
};
const IP_FIELD_AGGREGATE_KEYS = new Set(["name", "names", "names_count", "row_count", "total", "total_names"]);
let nextPageFetchAt = 0;
const collectionRowsCache = new Map();
const collectionPageRowsCache = new Map();
const ipAddressLookupCache = new Map();
const nameserverLookupCache = new Map();
let nameserverLookupIndexPromise = null;
const nameserverLookupShardCache = new Map();

function sitePath(path) {
  if (/^(?:[a-z]+:)?\/\//i.test(path) || path.startsWith("/")) return path;
  return `${SITE_BASE_PATH}${path}`;
}

async function loadJson(path) {
  const response = await fetch(sitePath(path));
  if (!response.ok) throw new Error(`Failed to load ${path}`);
  return response.json();
}

async function loadLiveDirectorySummary() {
  const response = await fetch(LIVE_DIRECTORY_SUMMARY_PATH, {cache: "no-store"});
  if (!response.ok) throw new Error("Failed to load live directory summary");
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

function activeFilter() {
  return new URLSearchParams(window.location.search).get("filter") || "";
}

function activePage() {
  return pageFromParam("page");
}

function pageFromParam(paramName) {
  const page = Number.parseInt(new URLSearchParams(window.location.search).get(paramName) || "1", 10);
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

function nameserverSearchOnly() {
  return activeSearchMode() === "nameserver";
}

function namesSearchHref(query, options = {}) {
  const text = String(query || "").trim();
  if (!text) return "";
  const params = new URLSearchParams();
  const filter = options.filter === undefined ? activeFilter() : options.filter;
  if (filter) params.set("filter", filter);
  if (options.searchMode) params.set("search", options.searchMode);
  else if (options.textSearch) params.set("search", "text");
  params.set("q", text);
  return `names.html?${params.toString()}`;
}

function hasDs(row) {
  return row.has_ds === true || Number(row.has_ds || 0) === 1;
}

function hasTlsa(row) {
  return row.has_tlsa === true
    || Number(row.has_tlsa || 0) === 1
    || (Array.isArray(row.tlsa_records) && row.tlsa_records.length > 0);
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
  if (filter.startsWith(PROVIDER_FILTER_PREFIX)) return `provider ${providerRuleBucketLabel(filter.slice(PROVIDER_FILTER_PREFIX.length))}`;
  if (filter.startsWith(COMPLIANCE_STAGE_FILTER_PREFIX)) return stageLabel(filter.slice(COMPLIANCE_STAGE_FILTER_PREFIX.length));
  return ({
    direct_ip_records: "SYNTH nameservers",
    delegated_names: "delegated names",
    default_provider_names: "default providers",
    ds_records: "DS records",
    dnssec_candidates: "DNSSEC candidates",
    tlsa_present_names: "TLSA observed",
    strict_hns_ready: "strict HNS ready",
    likely_websites: "likely host roots",
    needs_dane: "TLSA unobserved",
    needs_fix: "needs fix",
    missing_glue_only: "missing GLUE only"
  })[filter] || filter;
}

function stageLabel(stage) {
  return ({
    tlsa_present: "DS + TLSA observed",
    tlsa_gap: "TLSA unobserved",
    missing_glue: "Missing GLUE",
    bootstrap_ready: "Bootstrap ready",
    non_actionable: "Non-actionable"
  })[stage] || prettyToken(stage);
}

function stageDefinition(stage) {
  return ({
    tlsa_present: "Parent DS and authoritative or authenticated TLSA evidence are present.",
    tlsa_gap: "Parent DS is present, but stored DNS evidence does not prove TLSA presence.",
    missing_glue: "Parent-side nameserver bootstrap is missing.",
    bootstrap_ready: "HNS bootstrap exists; publish DNSSEC and TLSA.",
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

function providerLabel(value) {
  return ({
    "bulk/default": "BNS collision study glue",
    "impervious/default": "Impervious",
    "namebase/default": "Namebase"
  })[value] || value;
}

function providerRuleBucketLabel(value) {
  return ({
    "bulk/default": "BNS study glue IP matches",
    "hns-resolver/plain-dns": "Public HNS resolver IP matches",
    "namebase/default": "Namebase NS suffix matches",
    "self-hosted": "Self-hosted/custom NS matches",
    "unknown/custom": "No provider rule matched"
  })[value] || `${providerLabel(value)} rule matches`;
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
    row.filter_link || namesSearchHref(nameserver, {filter: "", searchMode: "nameserver"})
  );
}

function resolverIpCell(row) {
  return aggregateSearchLink(row.ip, row.filter_link);
}

function ipFieldCountsCell(row) {
  const counts = row.field_counts || {};
  const parts = Object.entries(counts)
    .filter(([field]) => !IP_FIELD_AGGREGATE_KEYS.has(String(field).toLowerCase()))
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

function overviewPageLink(label, targetPage, disabled, pageParam, collectionKey) {
  if (disabled) return `<button type="button" class="page-link disabled" disabled>${escapeHtml(label)}</button>`;
  return `<button type="button" class="page-link" data-overview-page="${escapeHtml(String(targetPage))}" data-overview-page-param="${escapeHtml(pageParam)}">${escapeHtml(label)}</button>`;
}

function overviewPagination(state, pageParam, label, collectionKey) {
  const collection = state?.collection || {};
  const pageCount = Number(collection.page_count || 0);
  if (pageCount <= 1) return "";
  const safePage = Math.min(Math.max(1, state.page || 1), pageCount);
  return `<nav class="pagination overview-pagination" aria-label="${escapeHtml(label)}">
    ${overviewPageLink("Previous", safePage - 1, safePage <= 1, pageParam, collectionKey)}
    <span class="page-status">${fmt.format(safePage)} / ${fmt.format(pageCount)}</span>
    ${overviewPageLink("Next", safePage + 1, safePage >= pageCount, pageParam, collectionKey)}
  </nav>`;
}

async function loadOverviewCollections(summary, index) {
  const [resourceIps, nameservers, resolvers] = await Promise.all([
    loadOverviewCollection(index, "resource_ips", "resource_ip_page", summary.top_resource_ips || []),
    loadOverviewCollection(index, "nameservers", "nameserver_page", summary.top_nameservers || []),
    loadOverviewCollection(index, "resolvers", "resolver_page", summary.known_hns_resolvers || [])
  ]);
  return {resourceIps, nameservers, resolvers};
}

async function loadOverviewCollection(index, key, pageParam, fallbackRows) {
  const fallback = Array.isArray(fallbackRows) ? fallbackRows : [];
  const collection = index?.collections?.[key];
  if (!collection) {
    return {
      collection: {
        row_count: fallback.length,
        page_size: fallback.length || 1,
        page_count: fallback.length ? 1 : 0
      },
      page: 1,
      rows: fallback
    };
  }
  const pageCount = Number(collection.page_count || 0);
  const page = pageCount > 0 ? Math.min(pageFromParam(pageParam), pageCount) : 1;
  const data = pageCount > 0
    ? await loadPageJson(pagePath(collection.path_template, page))
    : {rows: []};
  return {
    collection,
    page,
    rows: rowsFromPage(data, collection)
  };
}

async function loadOverviewCollectionPage(state, page) {
  const collection = state?.collection || {};
  const pageCount = Number(collection.page_count || 0);
  const safePage = pageCount > 0 ? Math.min(Math.max(1, page), pageCount) : 1;
  const data = pageCount > 0 && collection.path_template
    ? await loadPageJson(pagePath(collection.path_template, safePage))
    : {rows: []};
  return {
    collection,
    page: safePage,
    rows: rowsFromPage(data, collection)
  };
}

function overviewCollectionConfig(collectionKey) {
  return {
    resourceIps: {
      title: "Nameserver IP Evidence",
      pageParam: "resource_ip_page",
      pageLabel: "Nameserver IP Evidence pages",
      fallbackRows: "top_resource_ips",
      emptyMessage: "No resource IPs in this snapshot.",
      columns: [
      {key: "ip", label: "IP", render: topIpCell, width: "30%"},
      {key: "names_count", label: "Names", width: "18%"},
      {key: "field_counts", label: "Fields", render: ipFieldCountsCell, width: "27%"},
      {key: "role", label: "Role", render: ipRoleCell, width: "25%"}
      ]
    },
    nameservers: {
      title: "Delegation Hosts",
      pageParam: "nameserver_page",
      pageLabel: "Delegation Host pages",
      fallbackRows: "top_nameservers",
      emptyMessage: "No nameservers in this snapshot.",
      columns: [
      {key: "nameserver", label: "Nameserver", render: nameserverCell, width: "70%"},
      {key: "names_count", label: "Names", width: "30%"}
      ]
    },
    resolvers: {
      title: "HNS Resolver Inventory",
      pageParam: "resolver_page",
      pageLabel: "HNS Resolver Inventory pages",
      fallbackRows: "known_hns_resolvers",
      emptyMessage: "No resolver inventory configured.",
      columns: [
      {key: "ip", label: "IP", render: resolverIpCell, width: "26%"},
      {key: "names_count", label: "Names", width: "16%"},
      {key: "provider", label: "Provider", width: "34%"},
      {key: "hnsdoh_software", label: "Software", render: resolverSoftwareCell, width: "24%"}
      ]
    }
  }[collectionKey];
}

function overviewRows(summary, overview, collectionKey) {
  const config = overviewCollectionConfig(collectionKey);
  return overview[collectionKey]?.rows || summary[config.fallbackRows] || [];
}

function overviewCollectionCardBody(collectionKey, state, rows) {
  const config = overviewCollectionConfig(collectionKey);
  return `<div class="panel-heading"><h2>${escapeHtml(config.title)}</h2>${overviewPagination(state, config.pageParam, config.pageLabel, collectionKey)}</div>
    ${table(rows, config.columns, config.emptyMessage, {wrapClass: "compact-table-wrap"})}`;
}

function overviewCollectionCard(collectionKey, state, rows) {
  return `<article class="panel overview-collection" data-overview-key="${escapeHtml(collectionKey)}">
    ${overviewCollectionCardBody(collectionKey, state, rows)}
  </article>`;
}

function topologySignals(summary, overview = {}) {
  return ["resourceIps", "nameservers", "resolvers"]
    .map((collectionKey) => overviewCollectionCard(collectionKey, overview[collectionKey], overviewRows(summary, overview, collectionKey)))
    .join("");
}

function updateOverviewPageParam(pageParam, page) {
  if (!window.history || typeof window.history.replaceState !== "function") return;
  const params = new URLSearchParams(window.location.search);
  if (page <= 1) params.delete(pageParam);
  else params.set(pageParam, String(page));
  const query = params.toString();
  const path = currentPageName();
  window.history.replaceState({}, "", sitePath(query ? `${path}?${query}` : path));
}

function wireOverviewPagination(app, summary, overview) {
  app.addEventListener("click", async (event) => {
    const control = event.target.closest?.("[data-overview-page]");
    if (!control || !app.contains(control)) return;
    event.preventDefault();
    if (control.disabled) return;
    const article = control.closest(".overview-collection[data-overview-key]");
    const collectionKey = article?.dataset.overviewKey || "";
    const pageParam = control.dataset.overviewPageParam || "";
    const targetPage = Number.parseInt(control.dataset.overviewPage || "1", 10);
    const currentState = overview[collectionKey];
    if (!currentState || !article || !Number.isFinite(targetPage)) return;
    if (article.getAttribute("aria-busy") === "true") return;

    article.setAttribute("aria-busy", "true");
    try {
      overview[collectionKey] = await loadOverviewCollectionPage(currentState, targetPage);
      article.innerHTML = overviewCollectionCardBody(
        collectionKey,
        overview[collectionKey],
        overviewRows(summary, overview, collectionKey)
      );
      article.removeAttribute("aria-busy");
      updateOverviewPageParam(pageParam, overview[collectionKey].page);
    } catch (error) {
      article.removeAttribute("aria-busy");
      console.error(error);
    }
  });
}

function daneGeneratorUrl(row, intent) {
  return window.DaneGeneratorHandoff.buildUrl(row, {base: DANE_GENERATOR_BASE, intent});
}

function complianceStage(row) {
  if (row.compliance_stage) return row.compliance_stage;
  if (row.expired) return "non_actionable";
  if (row.provider_type === "default_parking" || row.provider_type === "public_resolver") return "non_actionable";
  if (hasNs(row) && !hasGlue(row)) return "missing_glue";
  if (hasDs(row) && hasTlsa(row)) return "tlsa_present";
  if (hasDs(row)) return "tlsa_gap";
  if (hasSynth(row) || hasGlue(row) || row.onchain_class === "DELEGATED_WITH_GLUE") return "bootstrap_ready";
  return "non_actionable";
}

function rowAction(row) {
  const stage = complianceStage(row);
  if (stage === "tlsa_present") {
    return {
      type: "badge",
      label: "TLSA observed",
      detail: "Parent DS and authoritative or authenticated TLSA evidence are stored; certificate matching is not implied.",
      href: sitePath(`names.html?filter=tlsa_present_names&q=${encodeURIComponent(row.name || "")}`)
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
  if (stage === "tlsa_gap") {
    return {
      label: "Verify or generate TLSA",
      detail: "Parent DS is present, but no authoritative or authenticated TLSA answer is stored.",
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
  return {
    label: "Review setup",
    detail: "Open the generator with this name filled in.",
    href: daneGeneratorUrl(row, "review")
  };
}

function actionCell(row) {
  const action = rowAction(row);
  if (action.type === "badge") {
    return `<div class="action-cell"><a class="verified-badge" href="${escapeHtml(action.href)}">${escapeHtml(action.label)}</a><span>${escapeHtml(action.detail)}</span></div>`;
  }
  return `<div class="action-cell"><a class="action-link" href="${escapeHtml(action.href)}">${escapeHtml(action.label)}</a><span>${escapeHtml(action.detail)}</span></div>`;
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
  return hrefWithPageParam(page, "page");
}

function hrefWithPageParam(page, paramName) {
  const params = new URLSearchParams(window.location.search);
  if (page <= 1) params.delete(paramName);
  else params.set(paramName, String(page));
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

function normalizeNameserverQuery(query) {
  let value = query.trim().toLowerCase();
  for (const prefix of ["hns://", "https://", "http://"]) {
    if (value.startsWith(prefix)) {
      value = value.slice(prefix.length);
      break;
    }
  }
  value = value.split("/", 1)[0].replace(/\.+$/, "");
  if (!value || value.length > 253) return "";
  if (!/^[a-z0-9-]+(?:\.[a-z0-9-]+)*$/.test(value)) return "";
  return value;
}

function ipAddressLookupPath(ip) {
  return `data/ip-addresses/${escapePathPercents(encodeURIComponent(ip))}.json`;
}

function nameserverLookupPath(nameserver) {
  return `data/nameservers/${escapePathPercents(encodeURIComponent(nameserver))}.json`;
}

function nameserverLookupIndexPath() {
  return "data/nameservers/index.json";
}

function fnv1a32(value) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index) & 0xff;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function nameserverShardId(nameserver, index) {
  const shardCount = Number(index?.shard_count || 0) || 1024;
  const shardWidth = Number(index?.shard_width || 0) || Math.max(1, (shardCount - 1).toString(16).length);
  return String((fnv1a32(nameserver) % shardCount).toString(16)).padStart(shardWidth, "0");
}

function nameserverShardPath(nameserver, index) {
  const template = index?.path_template || "nameservers/shards/{shard}.jsonl";
  return `data/${template.replace("{shard}", nameserverShardId(nameserver, index))}`;
}

async function loadText(path) {
  const response = await fetch(sitePath(path));
  if (!response.ok) throw new Error(`Failed to load ${path}`);
  return response.text();
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

function normalizeNameserverLookupResult(result, query, nameserver) {
  const rows = Array.isArray(result.rows) ? result.rows : [];
  return {
    found: result.found !== false,
    query,
    nameserver,
    rowCount: Number(result.row_count || rows.length || 0),
    pageCount: Number(result.page_count || 0),
    pageSize: Number(result.page_size || 0) || 100,
    page: Number(result.page || 1),
    rowDetail: result.row_detail || "nameserver_matches",
    columns: Array.isArray(result.columns) ? result.columns : null,
    source: "static",
    rows: rows.map((row) => ({...row, nameserver: row.nameserver || nameserver}))
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

async function lookupNameserver(query, page) {
  const nameserver = normalizeNameserverQuery(query);
  if (!nameserver) return null;
  if (!nameserverLookupCache.has(nameserver)) {
    const lookupPromise = loadNameserverLookup(nameserver)
      .catch(() => null);
    nameserverLookupCache.set(nameserver, lookupPromise);
  }
  const data = await nameserverLookupCache.get(nameserver);
  if (!data) {
    return {
      found: false,
      query,
      nameserver,
      rowCount: 0,
      pageCount: 0,
      pageSize: 100,
      page: 1,
      rowDetail: "nameserver_matches",
      columns: null,
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
  return normalizeNameserverLookupResult(
    {
      ...data,
      found: true,
      page: safePage,
      rows
    },
    query,
    nameserver
  );
}

async function loadNameserverLookup(nameserver) {
  const index = await loadNameserverLookupIndex();
  if (index?.lookup === "sharded-jsonl") {
    return loadNameserverFromShard(nameserver, index);
  }
  return loadJson(nameserverLookupPath(nameserver));
}

async function loadNameserverLookupIndex() {
  if (!nameserverLookupIndexPromise) {
    nameserverLookupIndexPromise = loadJson(nameserverLookupIndexPath())
      .catch(() => null);
  }
  return nameserverLookupIndexPromise;
}

async function loadNameserverFromShard(nameserver, index) {
  const shardPath = nameserverShardPath(nameserver, index);
  if (!nameserverLookupShardCache.has(shardPath)) {
    nameserverLookupShardCache.set(
      shardPath,
      loadText(shardPath).then((text) => {
        const entries = new Map();
        for (const line of text.split("\n")) {
          if (!line) continue;
          const entry = JSON.parse(line);
          if (entry?.n) entries.set(entry.n, entry);
        }
        return entries;
      })
    );
  }
  const entries = await nameserverLookupShardCache.get(shardPath);
  const entry = entries.get(nameserver);
  if (!entry) return null;
  const rowCount = Number(entry.c || 0);
  const pageSize = Number(index.page_size || 0) || 100;
  const pageCount = rowCount ? Math.ceil(rowCount / pageSize) : 0;
  const result = {
    nameserver,
    row_count: rowCount,
    page_count: pageCount,
    page_size: pageSize,
    row_detail: index.row_detail || "nameserver_matches",
    columns: Array.isArray(index.columns) ? index.columns : ["name", "nameserver"]
  };
  if (Array.isArray(entry.r)) {
    result.rows = entry.r.map((name) => ({name, nameserver}));
  } else if (entry.t) {
    result.path_template = entry.t;
  }
  return result;
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
  const nameserverLookup = nameserverSearchOnly() ? await lookupNameserver(query, activePage()) : null;
  if (nameserverLookup) {
    const allCollection = pageData.index?.collections?.all || pageData.collection;
    const exportedCount = Number(allCollection.row_count || 0);
    const totalCount = Number(allCollection.total_count || exportedCount);
    const fullSnapshot = exportedCount === totalCount;
    return {
      ...pageData,
      collection: {
        ...pageData.collection,
        row_count: nameserverLookup.rowCount,
        page_size: nameserverLookup.pageSize,
        page_count: nameserverLookup.pageCount,
        row_detail: nameserverLookup.rowDetail,
        columns: nameserverLookup.columns
      },
      page: nameserverLookup.page,
      rows: nameserverLookup.rows,
      search: {
        query,
        matchedCount: nameserverLookup.rowCount,
        totalCount: "snapshot",
        exact: false,
        nameserver: true,
        scoped: false,
        fullSnapshot
      },
      lookup: null,
      nameserverLookup
    };
  }
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
  const activeScope = search?.fullSnapshot === false ? "exported active names" : "active full snapshot";
  const exactSource = search?.exactSource === "static" ? "static exact lookup" : "exact lookup";
  const searchMeta = search
      ? `<p class="meta search-meta">${search.exact
      ? `${exactSource[0].toUpperCase()}${exactSource.slice(1)} "${escapeHtml(query)}" matched ${fmt.format(search.matchedCount)} ${exactScope} row.`
      : search.nameserver
        ? `Nameserver search "${escapeHtml(query)}" matched ${fmt.format(search.matchedCount)} ${activeScope} ${search.matchedCount === 1 ? "name" : "names"}.`
      : search.ip
        ? `IP search "${escapeHtml(query)}" matched ${fmt.format(search.matchedCount)} ${activeScope} ${search.matchedCount === 1 ? "name" : "names"}.`
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

function namesFilterControls({summary, providers, active}) {
  const providerOptions = providers
    .filter((row) => row.provider_key)
    .sort((a, b) => Number(b.names_count || 0) - Number(a.names_count || 0) || String(a.provider_key).localeCompare(String(b.provider_key)))
    .map((row) => ({
      value: `${PROVIDER_FILTER_PREFIX}${row.provider_key}`,
      label: `${providerRuleBucketLabel(row.provider_key)} (${fmt.format(row.names_count || 0)})`
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
    {value: "strict_hns_ready", label: "Strict HNS ready", countKey: "strict_hns_ready"},
    {value: "needs_fix", label: "Needs fix", countKey: "needs_fix"}
  ];
  const daneOptions = [
    {value: "ds_records", label: "DS records", countKey: "ds_records"},
    {value: "dnssec_candidates", label: "DNSSEC candidates", countKey: "dnssec_candidates"},
    {value: "tlsa_present_names", label: "TLSA observed", countKey: "tlsa_present_names"},
    {value: "needs_dane", label: "TLSA unobserved", countKey: "needs_dane"}
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

function liveDaneStage(liveSummary) {
  const evidence = liveSummary?.live_dane_evidence;
  if (!evidence) return null;
  return {
    live: true,
    label: "DS + TLSA observed by live scan",
    count: Number(evidence.observed_roots || 0),
    checkedRoots: Number(evidence.checked_roots || 0),
    activeRoots: Number(evidence.active_roots || 0),
    checkedAt: String(evidence.last_checked_at || ""),
    href: "/hns-live/"
  };
}

function adoptionFunnel(summary, liveSummary = null) {
  const active = Number(summary.active_names || 0);
  const stages = (summary.compliance_stages || [])
    .filter((stage) => stage.stage !== "tlsa_present" && Number(stage.count || 0) > 0);
  const liveStage = liveDaneStage(liveSummary);
  if (liveStage) stages.unshift(liveStage);
  return `<section class="panel adoption-funnel">
    <div class="panel-heading">
      <div>
        <h2>HNS Readiness and Live Evidence</h2>
        <p class="meta">The DS + TLSA stage is refreshed by the live authoritative DNS scan. All other stages come from the current topology snapshot. TLSA presence is not the same as DANE certificate verification.</p>
      </div>
    </div>
    <div class="funnel-grid">${stages.map((stage) => {
      const href = stage.live
        ? stage.href
        : sitePath(stage.filter_link || `names.html?filter=${COMPLIANCE_STAGE_FILTER_PREFIX}${stage.stage}`);
      const detail = stage.live
        ? `${fmt.format(stage.checkedRoots)} of ${fmt.format(stage.activeRoots)} eligible roots checked${stage.checkedAt ? `, latest ${stage.checkedAt}` : ""}. Authoritative DNSSEC and TLSA observation; certificate matching is not implied.`
        : `${pct(stage.count ?? 0, active)} of active. ${stage.definition || stageDefinition(stage.stage)}`;
      return `
      <a class="funnel-stage" href="${escapeHtml(href)}">
        <span>${escapeHtml(stage.label || stageLabel(stage.stage))}</span>
        <strong>${fmt.format(stage.count ?? 0)}</strong>
        <small>${escapeHtml(detail)}</small>
      </a>`;
    }).join("")}</div>
  </section>`;
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

async function renderOverview(app) {
  const [summary, overviewIndex, liveSummary] = await Promise.all([
    loadJson("data/summary.json"),
    loadJson("data/overview-pages.json").catch(() => null),
    loadLiveDirectorySummary().catch(() => null)
  ]);
  const overview = await loadOverviewCollections(summary, overviewIndex);
  const providers = summary.providers || [];
  const classes = summary.classes || [];
  app.innerHTML = `${adoptionFunnel(summary, liveSummary)}
    <section class="grid">
      ${topologySignals(summary, overview)}
      <article class="panel"><h2>Infrastructure Rule Buckets</h2><p class="meta">Each value is active names whose current resource matched that rule in this snapshot, not a provider total. Rules use nameserver suffixes, shared glue IPs, public resolver IPs, and self-hosted patterns.</p>${bars(providers, "provider_key", "names_count", 12, providerRuleBucketLabel, providerFilterHref)}</article>
      <article class="panel"><h2>Parent-Side State</h2>${bars(classes, "class", "count", 12, classLabel, (row) => classFilterHref(row.class))}</article>
      <article class="panel"><h2>Run Metadata</h2>
      <p class="meta">Height ${summary.last_indexed_height ?? ""} generated ${summary.generated_at ?? ""}</p>
      <p class="meta">Source ${escapeHtml(summary.source_type || "unknown")} - rules v${summary.provider_rules_version ?? ""} ${escapeHtml((summary.provider_rules_hash || "").slice(0, 12))}</p></article>
    </section>`;
  wireOverviewPagination(app, summary, overview);
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

function tlsaRecordLine(record) {
  if (!record || typeof record !== "object") return "";
  return [
    record.owner,
    record.usage,
    record.selector,
    record.matchingType,
    record.association
  ].filter((value) => value !== null && value !== undefined && value !== "").join(" ");
}

function tlsaRecordsCell(row) {
  const records = Array.isArray(row.tlsa_records) ? row.tlsa_records : [];
  if (!records.length) return "";
  return records.map(tlsaRecordLine).filter(Boolean).map((line) => `<code>${escapeHtml(line)}</code>`).join("<br>");
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

function staticDiagnosticStatus(row) {
  const stage = complianceStage(row);
  const fields = [
    ["Compliance stage", stageLabel(stage)],
    ["NS handoff", row.ns_handoff_ns],
    ["NS handoff root", row.ns_handoff_root ? `${row.ns_handoff_root}/` : ""],
    ["NS handoff bootstrap", row.ns_handoff_bootstrap_ip
      ? `${row.ns_handoff_bootstrap_field || "bootstrap"} ${row.ns_handoff_bootstrap_ip}`
      : ""],
    ["TLSA owners", Array.isArray(row.tlsa_owners) ? row.tlsa_owners.join(", ") : ""],
    ["TLSA observed", row.tlsa_observed_at],
    ["TLSA last checked", row.tlsa_checked_at]
  ].filter(([, value]) => value !== null && value !== undefined && value !== "");
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
    tlsaOwnerCheck(row)
  ];
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
  if (hasDs(row)) {
    return {label: "DNSSEC chain", status: "pass", detail: "Parent DS is present in current HNS resource data."};
  }
  return {label: "DNSSEC chain", status: "fail", detail: "No parent DS record is present."};
}

function tlsaOwnerCheck(row) {
  if (hasTlsa(row)) {
    return {label: "TLSA evidence", status: "pass", detail: "An authoritative or authenticated HTTPS TLSA answer is stored."};
  }
  if (complianceStage(row) === "tlsa_gap") {
    return {label: "TLSA evidence", status: "warn", detail: "DS is present, but stored DNS evidence does not prove whether TLSA is currently published."};
  }
  return {label: "TLSA evidence", status: "pending", detail: "No qualifying TLSA answer is stored yet."};
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

function evidenceLines(label, lines) {
  if (!Array.isArray(lines) || !lines.length) return "";
  return `<div class="evidence-lines"><span>${escapeHtml(label)}</span>${lines.map(codeLine).join("")}</div>`;
}

function liveStatusShard(name) {
  let value = 2166136261;
  for (const character of String(name || "").toLowerCase()) {
    value = Math.imul(value ^ character.charCodeAt(0), 16777619) >>> 0;
  }
  return (value & 0xff).toString(16).padStart(2, "0");
}

function liveStatusValue(label, value) {
  if (value === null || value === undefined || value === "") return "";
  return `${label} ${value}`;
}

function renderLiveDnsStatus(payload, name) {
  const hosts = payload?.roots?.[name];
  if (!Array.isArray(hosts) || !hosts.length) {
    return `<p class="meta">No live scan result for this name yet.</p>`;
  }
  return `<div class="dns-evidence-list">${hosts.map((item) => {
    const status = [
      liveStatusValue("DNS", item.dns_status),
      Array.isArray(item.addresses) && item.addresses.length ? `Addresses ${item.addresses.join(", ")}` : "",
      liveStatusValue("DNSSEC", item.dnssec_status),
      liveStatusValue("TLSA", item.tlsa_status),
      liveStatusValue("DANE", item.dane_status),
      liveStatusValue("HTTP", item.http_status_code || item.http_status),
      liveStatusValue("HTTPS", item.https_status_code || item.https_status),
      liveStatusValue("WebPKI", item.webpki_status),
      item.checked_at ? `Checked ${item.checked_at}` : ""
    ].filter(Boolean).join(" - ");
    return `<article class="dns-evidence-item">
      <header><strong>${escapeHtml(item.host || name)}</strong><span>${escapeHtml(status)}</span></header>
      ${item.failure_reason ? `<p class="meta">Result: ${escapeHtml(String(item.failure_reason).replaceAll("_", " "))}</p>` : ""}
    </article>`;
  }).join("")}</div>`;
}

function liveDnsSection(row) {
  const name = String(row.name || "");
  if (!name) return "";
  return `<section>
    <h3>Live DNS Scan</h3>
    <div class="live-dns-body" data-live-dns-name="${escapeHtml(name)}">
      <p class="meta">Open diagnostics to load the latest bounded live scan.</p>
    </div>
  </section>`;
}

function wireNameDetails() {
  document.querySelectorAll(".name-detail").forEach((details) => {
    details.addEventListener("toggle", async () => {
      if (!details.open) return;
      await loadLazyEvidence(details);
    });
  });
}

async function loadLazyEvidence(details) {
  await Promise.all([
    loadStoredDnsEvidence(details),
    loadLiveDnsStatus(details)
  ]);
}

async function loadStoredDnsEvidence(details) {
  if (details.dataset.evidenceLoaded === "true") return;
  const target = details.querySelector(".dns-evidence-body");
  const path = details.dataset.evidencePath;
  if (!target || !path) return;
  target.innerHTML = `<p class="meta">Loading DNS evidence...</p>`;
  try {
    const payload = await loadJson(`data/${path}`);
    target.innerHTML = renderDnsEvidence(payload);
    details.dataset.evidenceLoaded = "true";
  } catch (error) {
    target.innerHTML = `<p class="meta">Could not load DNS evidence: ${escapeHtml(error.message)}</p>`;
  }
}

async function loadLiveDnsStatus(details) {
  const target = details.querySelector(".live-dns-body");
  const name = target?.dataset.liveDnsName || "";
  if (!target || !name || target.dataset.loaded === "true") return;
  target.innerHTML = `<p class="meta">Loading live DNS scan...</p>`;
  try {
    const response = await fetch(`${LIVE_STATUS_BASE_PATH}${liveStatusShard(name)}.json`, {cache: "no-store"});
    if (response.status === 404) {
      target.innerHTML = renderLiveDnsStatus(null, name);
    } else if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    } else {
      target.innerHTML = renderLiveDnsStatus(await response.json(), name);
    }
    target.dataset.loaded = "true";
  } catch (error) {
    target.innerHTML = `<p class="meta">Could not load live DNS scan: ${escapeHtml(error.message)}</p>`;
  }
}

function nameDetailRow(row, colspan) {
  const name = String(row.name || "");
  const displayName = name || String(row.domain || row.normalized || "Selected name");
  const records = resourceRecordSections(row);
  const recordTypesText = recordTypes(row).join(", ");
  const compactNotice = !Array.isArray(row.ds_records) && hasRecordType(row, "DS")
    ? `<p class="meta">Compact row: DS payload is not embedded in this collection.</p>`
    : "";
  const evidenceAttr = row.dns_evidence_path
    ? ` data-evidence-path="${escapeHtml(row.dns_evidence_path)}"`
    : "";
  return `<tr class="name-detail-row"><td colspan="${colspan}">
    <details class="name-detail"${evidenceAttr}>
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
          <h3>Static Analysis</h3>
          ${staticDiagnosticStatus(row)}
        </section>
        ${dnsEvidenceSection(row)}
        ${liveDnsSection(row)}
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
  if (rowDetail === "nameserver_matches") {
    return [
      {key: "name", label: "Name", render: nameCell, width: "45%"},
      {key: "nameserver", label: "Nameserver", width: "35%"},
      {key: "lookup", label: "Lookup", render: exactNameLookupCell, width: "20%"}
    ];
  }
  const compactColumns = [
    {key: "name", label: "Name", render: nameCell, width: "12%"},
    {key: "next_step", label: "Next step", render: actionCell, width: "20%"},
    {key: "compliance_stage", label: "Stage", render: complianceStageCell, width: "12%"},
    {key: "provider_guess", label: "Provider", width: "12%"},
    {key: "provider_type", label: "Provider type", width: "12%"},
    {key: "record_types", label: "Records", width: "12%"},
    {key: "has_ds", label: "DS", width: "5%"},
    {key: "first_ns", label: "NS", width: "15%"}
  ];
  if (rowDetail === "compact") return compactColumns;
  return [
    {...compactColumns[0], width: "10%"},
    {...compactColumns[1], width: "18%"},
    {...compactColumns[2], width: "10%"},
    {...compactColumns[3], width: "10%"},
    {...compactColumns[4], width: "10%"},
    {...compactColumns[5], width: "9%"},
    {key: "ns_names", label: "NS", width: "9%"},
    {key: "synth4", label: "SYNTH4", width: "7%"},
    {key: "synth6", label: "SYNTH6", width: "7%"},
    {...compactColumns[6], width: "4%"},
    {key: "tlsa_records", label: "Observed TLSA", render: tlsaRecordsCell, width: "6%"}
  ];
}

async function renderNames(app) {
  const [summary, loadedPageData] = await Promise.all([
    loadJson("data/summary.json"),
    loadPaginatedRows("data/names-pages.json", activeFilter())
  ]);
  const providers = summary.providers || [];
  const filter = activeFilter();
  const query = activeSearch();
  const pageData = await applySearchToPageData(loadedPageData, query);
  const columns = namesColumns(pageData.collection.row_detail);
  const lookupRow = ["ip_matches", "nameserver_matches"].includes(pageData.collection.row_detail);
  const detailRender = lookupRow ? null : nameDetailRow;
  app.innerHTML = `${filterNotice(filter, pageData.index.collections.all.row_count, loadedPageData.collection.row_count)}
    <section class="names-layout">
      <div class="panel names-main">
        <div class="panel-heading">
          <div><h2>Names</h2><p class="meta">${pageRangeMeta(pageData.collection, pageData.page, pageData.rows)} - height ${summary.last_indexed_height ?? ""}</p></div>
        </div>
        ${namesFilterControls({summary, providers, active: filter})}
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

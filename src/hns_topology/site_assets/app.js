const fmt = new Intl.NumberFormat("en-US");
const SITE_BASE_PATH = window.__HNS_TOPOLOGY_BASE__ || "/hns-topology/";
const PAGE_FETCH_MIN_DELAY_MS = 350;
const COLLECTION_FETCH_BATCH_SIZE = 8;
const SEARCH_FULL_SCAN_MAX_ROWS = 5000;
const FAILURE_REASON_FILTER_PREFIX = "failure_reason:";
const PROVIDER_FILTER_PREFIX = "provider:";
const PROVIDER_TYPE_FILTER_PREFIX = "provider_type:";
const DANE_GENERATOR_BASE = window.__DANE_GENERATOR_BASE__ || "/dane-generator/";
let nextPageFetchAt = 0;
const collectionRowsCache = new Map();
const collectionPageRowsCache = new Map();

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

function hasDs(row) {
  return row.has_ds === true || Number(row.has_ds || 0) === 1;
}

function recordTypes(row) {
  return Array.isArray(row.record_types) ? row.record_types : [];
}

function hasRecordType(row, type) {
  return recordTypes(row).includes(type);
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

function filterName(filter) {
  if (filter.startsWith(FAILURE_REASON_FILTER_PREFIX)) return prettyToken(filter.slice(FAILURE_REASON_FILTER_PREFIX.length));
  if (filter.startsWith(PROVIDER_FILTER_PREFIX)) return `provider ${filter.slice(PROVIDER_FILTER_PREFIX.length)}`;
  if (filter.startsWith(PROVIDER_TYPE_FILTER_PREFIX)) return `provider ${prettyToken(filter.slice(PROVIDER_TYPE_FILTER_PREFIX.length))}`;
  return ({
    direct_ip_records: "SYNTH nameservers",
    delegated_names: "delegated names",
    default_provider_names: "default providers",
    ds_records: "DS records",
    dnssec_candidates: "DNSSEC candidates",
    dane_rows: "DANE rows",
    strict_hns_ready: "strict HNS ready",
    likely_websites: "likely websites",
    strict_hns_working: "strict HNS working",
    doh_fallback_required: "resolver fallback required",
    needs_dane: "needs DANE",
    dane_working: "valid DANE",
    needs_fix: "needs fix",
    missing_glue: "missing GLUE",
    missing_glue_only: "missing GLUE only",
    stale_tlsa: "stale TLSA",
    stale_tlsa_only: "stale TLSA only"
  })[filter] || filter;
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

function tableRows(rows, columns) {
  return rows.map((row) => `<tr>${columns.map((column) => `<td class="${escapeHtml(columnClass(column))}">${column.render ? column.render(row) : formatCell(row[column.key])}</td>`).join("")}</tr>`).join("");
}

function table(rows, columns, emptyMessage = "No rows in this page.", options = {}) {
  if (!rows.length) return `<p class="empty-state">${escapeHtml(emptyMessage)}</p>`;
  const tbodyId = options.tbodyId ? ` id="${escapeHtml(options.tbodyId)}"` : "";
  const wrapClass = options.wrapClass ? `table-wrap ${escapeHtml(options.wrapClass)}` : "table-wrap";
  const tableClass = options.tableClass ? ` class="${escapeHtml(options.tableClass)}"` : "";
  const colgroup = columns.some((column) => column.width)
    ? `<colgroup>${columns.map((column) => `<col${column.width ? ` style="width:${escapeHtml(column.width)}"` : ""}>`).join("")}</colgroup>`
    : "";
  return `<div class="${wrapClass}"><table${tableClass}>${colgroup}<thead><tr>${columns.map((column) => `<th class="${escapeHtml(columnClass(column))}">${escapeHtml(column.label)}</th>`).join("")}</tr></thead><tbody${tbodyId}>${tableRows(rows, columns)}</tbody></table></div>`;
}

function formatCell(value) {
  if (Array.isArray(value)) return escapeHtml(value.join(", "));
  if (value === null || value === undefined) return "";
  if (typeof value === "number") return fmt.format(value);
  return escapeHtml(String(value));
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

function daneGeneratorUrl(row, intent) {
  const params = new URLSearchParams();
  const name = String(row.name || "");
  params.set("domain", name && !name.endsWith("/") ? `${name}/` : name);
  params.set("domain_type", "hns");
  params.set("intent", intent);
  params.set("mode", hasSynth(row) && row.onchain_class === "DIRECT_SYNTH" ? "synth" : "delegated");
  const nameserver = firstValue(row.ns_names) || row.first_ns;
  const ns4 = firstValue(row.synth4) || firstValue(row.glue4) || row.first_synth4 || row.first_glue4;
  const ns6 = firstValue(row.synth6) || firstValue(row.glue6) || row.first_synth6 || row.first_glue6;
  if (nameserver) params.set("nameserver", nameserver);
  if (ns4) params.set("ns4", ns4);
  if (ns6) params.set("ns6", ns6);
  return `${DANE_GENERATOR_BASE}?${params.toString()}`;
}

function rowAction(row) {
  const failure = row.failure_reason || "";
  if (row.dane_status === "valid") {
    return {
      type: "badge",
      label: "Verified DANE",
      detail: "DNSSEC, TLSA, and HTTPS matched in the latest live check.",
      href: sitePath(`names.html?filter=dane_working&q=${encodeURIComponent(row.name || "")}`)
    };
  }
  if (failure === "missing_glue" || row.onchain_class === "DELEGATED_NO_GLUE") {
    return {
      label: "Generate NS/GLUE setup",
      detail: "Delegation needs nameserver bootstrap records before strict HNS can work.",
      href: daneGeneratorUrl(row, "missing_glue")
    };
  }
  if (failure === "ds_dnskey_mismatch" || row.dnssec_status === "ds_dnskey_mismatch") {
    return {
      label: "Regenerate/check DS",
      detail: "Parent DS and delegated DNSKEY do not match.",
      href: daneGeneratorUrl(row, "ds_dnskey_mismatch")
    };
  }
  if (failure === "rrsig_expired" || failure === "dnssec_bogus" || row.dnssec_status === "rrsig_expired" || row.dnssec_status === "bogus") {
    return {
      label: "Regenerate/check DS",
      detail: "DNSSEC signing needs review before DANE can validate.",
      href: daneGeneratorUrl(row, "dnssec_fix")
    };
  }
  if (failure === "stale_tlsa_spki_mismatch" || failure === "tlsa_wrong_owner" || (row.tlsa_status === "present" && row.dane_status === "invalid")) {
    return {
      label: "Generate current TLSA",
      detail: "TLSA data should match the current HTTPS certificate public key.",
      href: daneGeneratorUrl(row, "stale_tlsa")
    };
  }
  if (hasDs(row) && row.dane_status !== "valid") {
    return {
      label: "Generate TLSA",
      detail: "DS exists; add or verify TLSA 3 1 1 next.",
      href: daneGeneratorUrl(row, "generate_tlsa")
    };
  }
  if (hasSynth(row)) {
    return {
      label: "Generate SYNTH DNS setup",
      detail: "SYNTH points to nameserver IPs; the zone still serves A, AAAA, DNSSEC, and TLSA.",
      href: daneGeneratorUrl(row, "synth_setup")
    };
  }
  if (hasGlue(row) || row.onchain_class === "DELEGATED_WITH_GLUE") {
    return {
      label: "Plan DNSSEC/DANE",
      detail: "Strict-HNS bootstrap exists; sign the zone and publish DS/TLSA when ready.",
      href: daneGeneratorUrl(row, "dnssec_dane")
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

function snapshot(summary) {
  return `<section class="snapshot">
    ${metric("Active names", summary.active_names, `${fmt.format(summary.expired_names)} expired`, "names.html")}
    ${metric("SYNTH NS", summary.synth_nameserver_records ?? summary.direct_ip_records, pct(summary.synth_nameserver_records ?? summary.direct_ip_records, summary.active_names), "names.html?filter=direct_ip_records")}
    ${metric("DS records", summary.ds_records, pct(summary.ds_records, summary.active_names), "names.html?filter=ds_records")}
    ${metric("Valid DANE", summary.dane_working, `${fmt.format(summary.strict_hns_working)} strict HNS working`, "names.html?filter=dane_working")}
  </section>`;
}

function liveCheckMeta(summary) {
  if (!summary.live_check_started_at) return "";
  return `<p class="meta">Live checks ${fmt.format(summary.live_check_checked_count ?? 0)} of ${fmt.format(summary.live_check_candidate_count ?? 0)} due - concurrency ${fmt.format(summary.live_check_concurrency ?? 0)} - delay ${fmt.format(summary.live_check_min_delay_ms ?? 0)}ms - timeout ${summary.live_check_timeout_seconds ?? ""}s</p>`;
}

function collectionForFilter(index, filter) {
  if (filter && index.collections && index.collections[filter]) {
    return {key: filter, collection: index.collections[filter]};
  }
  return {key: "all", collection: index.collections.all};
}

function pagePath(pathTemplate, page) {
  return `data/${pathTemplate.replace("{page}", String(page))}`;
}

function rowsFromPage(data, collection = {}) {
  const rows = Array.isArray(data.rows) ? data.rows : [];
  const columns = Array.isArray(data.columns) ? data.columns : collection.columns;
  if (!Array.isArray(columns) || !rows.some((row) => Array.isArray(row))) return rows;
  return rows.map((row) => Object.fromEntries(columns.map((key, index) => [key, row[index]])));
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
  return {
    index,
    collection,
    page,
    rows: rowsFromPage(data, collection)
  };
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
        pages.push(loadJson(pagePath(collection.path_template, page)));
      }
      const pageResults = await Promise.all(pages);
      pageResults.forEach((data) => {
        rows.push(...rowsFromPage(data, collection));
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
    .then((data) => rowsFromPage(data, collection));
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

function isDaneRow(row) {
  return hasDs(row) || Boolean(row.tlsa_status) || Boolean(row.dane_status);
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

async function applySearchToPageData(pageData, query, options = {}) {
  if (!query) return {...pageData, search: null, lookup: null};
  const lookup = await lookupExactName(query, pageData.index);
  if (lookup && lookup.found && (!options.daneOnly || isDaneRow(lookup.row))) {
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
  if (lookup && lookup.found && options.daneOnly) {
    return {
      ...pageData,
      collection: {
        ...pageData.collection,
        row_count: 0,
        page_count: 0
      },
      page: 1,
      rows: [],
      search: {
        query,
        matchedCount: 0,
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
        fullSnapshot: lookup?.fullSnapshot !== false
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
      fullSnapshot: lookup?.fullSnapshot !== false
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
    ? `<a class="search-clear" href="${escapeHtml(hrefWithoutParams(["q", "page"]))}">Clear</a>`
    : "";
  const exactScope = search?.fullSnapshot === false ? "exported rows" : "full snapshot";
  const exactSource = search?.exactSource === "static" ? "static exact lookup" : "exact lookup";
  const searchMeta = search
    ? `<p class="meta search-meta">${search.exact
      ? `${exactSource[0].toUpperCase()}${exactSource.slice(1)} "${escapeHtml(query)}" matched ${fmt.format(search.matchedCount)} ${exactScope} row.`
      : search.scoped
        ? `Search "${escapeHtml(query)}" matched ${fmt.format(search.matchedCount)} of ${fmt.format(search.totalCount)} loaded rows. Exact name lookup still checks ${exactScope}.`
        : `Search "${escapeHtml(query)}" matched ${fmt.format(search.matchedCount)} of ${fmt.format(search.totalCount)} exported rows.`}</p>`
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

function lookupNotice(pageData, pageName) {
  if (!pageData.lookup || !activeSearch()) return "";
  if (pageData.lookup.found && pageName === "dane" && !isDaneRow(pageData.lookup.row)) {
    return `<p class="meta search-meta">Exact lookup found ${escapeHtml(pageData.lookup.row.name)} in the full snapshot, but it is not a DANE candidate in the current data.</p>`;
  }
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

function namesFilterControls({providers, broken, active}) {
  const providerCounts = new Map();
  providers.forEach((row) => {
    const type = row.provider_type || "unknown";
    providerCounts.set(type, (providerCounts.get(type) || 0) + Number(row.names_count || 0));
  });
  const providerOptions = providers
    .filter((row) => row.provider_key)
    .sort((a, b) => Number(b.names_count || 0) - Number(a.names_count || 0) || String(a.provider_key).localeCompare(String(b.provider_key)))
    .map((row) => ({
      value: `${PROVIDER_FILTER_PREFIX}${row.provider_key}`,
      label: `${row.provider_key} (${fmt.format(row.names_count || 0)})`
    }));
  const providerTypeOptions = Array.from(providerCounts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([type, count]) => ({
      value: `${PROVIDER_TYPE_FILTER_PREFIX}${type}`,
      label: `${prettyToken(type)} (${fmt.format(count)})`
    }));
  const failureOptions = (broken.reasons || [])
    .filter((row) => Number(row.count || 0) > 0)
    .map((row) => ({
      value: `${FAILURE_REASON_FILTER_PREFIX}${row.failure_reason}`,
      label: `${prettyToken(row.failure_reason)} (${fmt.format(row.count || 0)})`
    }));
  const generalOptions = [
    {value: "", label: "All names"},
    {value: "direct_ip_records", label: "SYNTH nameservers"},
    {value: "delegated_names", label: "Delegated names"},
    {value: "default_provider_names", label: "Default providers"},
    {value: "likely_websites", label: "Likely websites"},
    {value: "strict_hns_ready", label: "Strict HNS ready"},
    {value: "strict_hns_working", label: "Strict HNS working"},
    {value: "needs_fix", label: "Needs fix"},
    {value: "doh_fallback_required", label: "Resolver fallback required"}
  ];
  const daneOptions = [
    {value: "ds_records", label: "DS records"},
    {value: "dnssec_candidates", label: "DNSSEC candidates"},
    {value: "needs_dane", label: "Needs DANE"},
    {value: "dane_working", label: "Valid DANE"},
    {value: "stale_tlsa_only", label: "Stale TLSA"}
  ];
  const clearLink = active
    ? `<a class="search-clear" href="${escapeHtml(hrefWithoutParams(["filter", "page"]))}">Clear</a>`
    : "";
  return `<form class="filter-form" action="${escapeHtml(currentPageName())}" method="get">
    ${hiddenInputsWithout(["filter", "page"])}
    <label class="filter-field" for="names-filter">
      <span class="search-label">Filter</span>
      <select id="names-filter" name="filter">
        ${filterOptgroup("General", generalOptions, active)}
        ${filterOptgroup("DANE and DNSSEC", daneOptions, active)}
        ${filterOptgroup("Failure Reasons", failureOptions, active)}
        ${filterOptgroup("Providers", providerOptions, active)}
        ${filterOptgroup("Provider Types", providerTypeOptions, active)}
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
  const checked = Number(summary.live_check_checked_count || 0);
  const stages = [
    {
      label: "Likely websites",
      value: summary.likely_websites,
      filter: "likely_websites",
      note: "Have on-chain data worth turning into a site."
    },
    {
      label: "Strict HNS ready",
      value: summary.strict_hns_ready,
      filter: "strict_hns_ready",
      note: "SYNTH or GLUE bootstrap exists on chain."
    },
    {
      label: "DNSSEC ready",
      value: summary.dnssec_candidates,
      filter: "dnssec_candidates",
      note: "DS plus delegated nameserver data."
    },
    {
      label: "Needs DANE",
      value: summary.needs_dane,
      filter: "needs_dane",
      note: "DS exists but valid TLSA is not proven."
    },
    {
      label: "Valid DANE",
      value: summary.dane_working,
      filter: "dane_working",
      note: "DNSSEC, TLSA, and HTTPS matched."
    },
    {
      label: "Needs fix",
      value: summary.needs_fix,
      filter: "needs_fix",
      note: "Missing glue or live-check failure."
    }
  ];
  return `<section class="panel adoption-funnel">
    <div class="panel-heading">
      <div>
        <h2>Adoption Funnel</h2>
        <p class="meta">${fmt.format(checked)} live checks sampled from ${fmt.format(summary.live_check_candidate_count ?? 0)} candidates.</p>
      </div>
    </div>
    <div class="funnel-grid">${stages.map((stage) => `
      <a class="funnel-stage" href="${escapeHtml(sitePath(`names.html?filter=${stage.filter}`))}">
        <span>${escapeHtml(stage.label)}</span>
        <strong>${fmt.format(stage.value ?? 0)}</strong>
        <small>${pct(stage.value ?? 0, active)} of active. ${escapeHtml(stage.note)}</small>
      </a>`).join("")}</div>
  </section>`;
}

function nextActionsPanel(actions = []) {
  if (!actions.length) return "";
  return `<article class="panel next-actions-panel">
    <h2>Next Actions</h2>
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
      <span class="search-label">Action Queue</span>
      <strong>${escapeHtml(action.label)}</strong>
    </div>
    <p class="meta">${escapeHtml(action.definition || "")}</p>
  </section>`;
}

async function renderOverview(app) {
  const summary = await loadJson("data/summary.json");
  const providers = summary.providers || [];
  const classes = summary.classes || [];
  app.innerHTML = `${snapshot(summary)}
    ${adoptionFunnel(summary)}
    <section class="grid">
      ${nextActionsPanel(summary.next_actions || [])}
      <article class="panel"><h2>Provider Dominance</h2>${bars(providers, "provider_key", "names_count", 12, (value) => value, providerFilterHref)}</article>
      <article class="panel"><h2>On-Chain Classes</h2>${bars(classes, "class", "count", 12, classLabel, (row) => classFilterHref(row.class))}</article>
      <article class="panel"><h2>DANE</h2>
        <div class="stat-list">
          <a class="stat-line stat-link" href="${escapeHtml(sitePath("names.html?filter=ds_records"))}"><span>DS records</span><strong>${fmt.format(summary.ds_records)}</strong></a>
          <a class="stat-line stat-link" href="${escapeHtml(sitePath("names.html?filter=needs_dane"))}"><span>Needs DANE</span><strong>${fmt.format(summary.needs_dane)}</strong></a>
          <a class="stat-line stat-link" href="${escapeHtml(sitePath("names.html?filter=dane_working"))}"><span>Valid DANE</span><strong>${fmt.format(summary.dane_working)}</strong></a>
        </div>
      </article>
      <article class="panel"><h2>Fix Queues</h2>
        <div class="stat-list">
          <a class="stat-line stat-link" href="${escapeHtml(sitePath("names.html?filter=needs_fix"))}"><span>Needs fix</span><strong>${fmt.format(summary.needs_fix)}</strong></a>
          <a class="stat-line stat-link" href="${escapeHtml(sitePath("names.html?filter=missing_glue_only"))}"><span>Missing GLUE</span><strong>${fmt.format(summary.missing_glue_only)}</strong></a>
          <a class="stat-line stat-link" href="${escapeHtml(sitePath("names.html?filter=stale_tlsa_only"))}"><span>Stale TLSA</span><strong>${fmt.format(summary.stale_tlsa_only)}</strong></a>
        </div>
      </article>
      <article class="panel"><h2>Snapshot</h2>
      <p class="meta">Height ${summary.last_indexed_height ?? ""} generated ${summary.generated_at ?? ""}</p>
      <p class="meta">Source ${escapeHtml(summary.source_type || "unknown")} - rules v${summary.provider_rules_version ?? ""} ${escapeHtml((summary.provider_rules_hash || "").slice(0, 12))}</p>
      ${liveCheckMeta(summary)}</article>
    </section>`;
}

async function renderFaq(app) {
  const [summary, answers] = await Promise.all([
    loadJson("data/summary.json"),
    loadJson("data/faq_answers.json")
  ]);
  app.innerHTML = `<section class="faq-list">${answers.map((item) => `
    <article class="faq-item">
      <h3>${escapeHtml(item.question)}</h3>
      <span class="faq-count">${fmt.format(item.count)}</span>
      <p class="definition">${escapeHtml(item.definition)}</p>
      <p class="examples">Examples: ${escapeHtml((item.examples || []).join(", ") || "none in current export")}</p>
      <p class="meta">${item.percentage_of_active}% of active names. Height ${item.last_checked_height ?? ""}.</p>
      <a href="${escapeHtml(sitePath(item.filter_link))}">Filtered table</a>
    </article>`).join("")}</section>`;
}

function pageLink(label, targetPage, disabled) {
  if (disabled) return `<span class="page-link disabled">${escapeHtml(label)}</span>`;
  return `<a class="page-link" href="${escapeHtml(hrefWithPage(targetPage))}">${escapeHtml(label)}</a>`;
}

function namesPagination(collection, page) {
  const pageCount = Number(collection.page_count || 0);
  if (pageCount <= 1) return "";
  const safePage = Math.min(Math.max(1, page), pageCount);
  return `<nav class="pagination names-pagination" aria-label="Names pages">
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

function lastCheckedCell(row) {
  const checkedAt = String(row.checked_at || "");
  if (!checkedAt) return "";
  return `<span title="${escapeHtml(checkedAt)}">${escapeHtml(checkedAt.replace("T", " ").replace(/:\d\d(?:\.\d+)?Z$/, " UTC"))}</span>`;
}

function namesColumns(rowDetail) {
  const compactColumns = [
    {key: "name", label: "Name", render: nameCell, width: "10%"},
    {key: "next_step", label: "Next step", render: actionCell, width: "16%"},
    {key: "onchain_class", label: "Class", width: "10%"},
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
  app.innerHTML = `${filterNotice(filter, pageData.index.collections.all.row_count, loadedPageData.collection.row_count)}
    <section class="names-layout">
      <div class="panel names-main">
        <div class="panel-heading">
          <div><h2>Names</h2><p class="meta">${pageRangeMeta(pageData.collection, pageData.page, pageData.rows)} - height ${summary.last_indexed_height ?? ""}</p></div>
        </div>
        ${namesFilterControls({providers, broken, active: filter})}
        ${searchControls({
          id: "names-search",
          label: "Search Names",
          placeholder: "Name, provider, records, status",
          query,
          search: pageData.search
        })}
        ${namesActionContext(summary.next_actions || [], filter)}
        ${lookupNotice(pageData, "names")}
        ${namesPagination(pageData.collection, pageData.page)}
        ${table(pageData.rows, columns, query ? "No names match this search." : "No rows in this page.", {wrapClass: "names-table-wrap", tableClass: "names-table"})}
        ${namesPagination(pageData.collection, pageData.page)}
      </div>
    </section>`;
  wireAutoSubmitFilter();
}

async function boot() {
  const page = document.body.dataset.page || "overview";
  setActiveNav(page);
  const app = document.getElementById("app");
  const renderers = {
    overview: renderOverview,
    faq: renderFaq,
    names: renderNames
  };
  try {
    await (renderers[page] || renderOverview)(app);
  } catch (error) {
    app.innerHTML = `<section class="panel"><h2>Load Failed</h2><p class="definition">${escapeHtml(error.message)}</p></section>`;
  }
}

boot();

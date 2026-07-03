const fmt = new Intl.NumberFormat("en-US");
const SITE_BASE_PATH = window.__HNS_TOPOLOGY_BASE__ || "/hns-topology/";
const PAGE_FETCH_MIN_DELAY_MS = 350;
const COLLECTION_FETCH_BATCH_SIZE = 8;
const SEARCH_FULL_SCAN_MAX_ROWS = 5000;
const FAILURE_REASON_FILTER_PREFIX = "failure_reason:";
const PROVIDER_TYPE_FILTER_PREFIX = "provider_type:";
let nextPageFetchAt = 0;
const collectionRowsCache = new Map();

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

function metric(label, value, sub = "") {
  return `<article class="metric"><span class="label">${label}</span><span class="value">${fmt.format(value ?? 0)}</span><span class="sub">${sub}</span></article>`;
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

function filterName(filter) {
  if (filter.startsWith(FAILURE_REASON_FILTER_PREFIX)) return prettyToken(filter.slice(FAILURE_REASON_FILTER_PREFIX.length));
  if (filter.startsWith(PROVIDER_TYPE_FILTER_PREFIX)) return `provider ${prettyToken(filter.slice(PROVIDER_TYPE_FILTER_PREFIX.length))}`;
  return ({
    direct_ip_records: "direct IP records",
    delegated_names: "delegated names",
    default_provider_names: "default providers",
    ds_records: "DS records",
    dnssec_candidates: "DNSSEC candidates",
    dane_rows: "DANE rows",
    likely_websites: "likely websites",
    strict_hns_working: "strict HNS working",
    doh_fallback_required: "fallback required",
    dane_working: "valid DANE",
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

function bars(rows, labelKey, valueKey, limit = 12) {
  const max = Math.max(1, ...rows.map((row) => Number(row[valueKey] || 0)));
  return `<div class="bar-list">${rows.slice(0, limit).map((row) => {
    const value = Number(row[valueKey] || 0);
    return `<div class="bar-row"><span class="bar-label" title="${escapeHtml(row[labelKey])}">${escapeHtml(row[labelKey])}</span><span class="bar-track"><span class="bar-fill" style="width:${(value / max) * 100}%"></span></span><strong>${fmt.format(value)}</strong></div>`;
  }).join("")}</div>`;
}

function tableRows(rows, columns) {
  return rows.map((row) => `<tr>${columns.map((column) => `<td>${formatCell(row[column.key])}</td>`).join("")}</tr>`).join("");
}

function table(rows, columns, emptyMessage = "No rows in this page.", options = {}) {
  if (!rows.length) return `<p class="empty-state">${escapeHtml(emptyMessage)}</p>`;
  const tbodyId = options.tbodyId ? ` id="${escapeHtml(options.tbodyId)}"` : "";
  return `<div class="table-wrap"><table><thead><tr>${columns.map((column) => `<th>${column.label}</th>`).join("")}</tr></thead><tbody${tbodyId}>${tableRows(rows, columns)}</tbody></table></div>`;
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

function snapshot(summary) {
  return `<section class="snapshot">
    ${metric("Active names", summary.active_names, `${fmt.format(summary.expired_names)} expired`)}
    ${metric("Direct IP", summary.direct_ip_records, pct(summary.direct_ip_records, summary.active_names))}
    ${metric("DS records", summary.ds_records, pct(summary.ds_records, summary.active_names))}
    ${metric("Valid DANE", summary.dane_working, `${fmt.format(summary.strict_hns_working)} strict HNS working`)}
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
  const start = (page - 1) * Number(collection.page_size || rows.length || 1) + 1;
  const end = Math.min(start + rows.length - 1, total);
  return `${fmt.format(start)}-${fmt.format(end)} of ${fmt.format(total)} exported rows`;
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
    rows: Array.isArray(data.rows) ? data.rows : []
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
        if (Array.isArray(data.rows)) rows.push(...data.rows);
      });
    }
    return rows;
  })();
  collectionRowsCache.set(cacheKey, rowsPromise);
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

async function lookupExactName(query) {
  const name = normalizeLookupQuery(query);
  if (!name) return null;
  try {
    const response = await fetch(sitePath(`api/name?name=${encodeURIComponent(name)}`));
    if (!response.ok && response.status !== 404) return null;
    return response.json();
  } catch (_error) {
    return null;
  }
}

async function applySearchToPageData(pageData, query, options = {}) {
  if (!query) return {...pageData, search: null, lookup: null};
  const lookup = await lookupExactName(query);
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
        exact: true
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
        exact: true
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
        scoped: true
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
      scoped: false
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
  const searchMeta = search
    ? `<p class="meta search-meta">${search.exact
      ? `Exact lookup "${escapeHtml(query)}" matched ${fmt.format(search.matchedCount)} full-snapshot row.`
      : search.scoped
        ? `Search "${escapeHtml(query)}" matched ${fmt.format(search.matchedCount)} of ${fmt.format(search.totalCount)} loaded rows. Exact name lookup still uses the full snapshot.`
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
    return `<p class="meta search-meta">Exact lookup uses the full snapshot.</p>`;
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
  const providerOptions = Array.from(providerCounts.entries())
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
    {value: "direct_ip_records", label: "Direct IP records"},
    {value: "delegated_names", label: "Delegated names"},
    {value: "default_provider_names", label: "Default providers"},
    {value: "likely_websites", label: "Likely websites"},
    {value: "strict_hns_working", label: "Strict HNS working"},
    {value: "doh_fallback_required", label: "Fallback required"}
  ];
  const daneOptions = [
    {value: "dane_rows", label: "DANE rows"},
    {value: "ds_records", label: "DS records"},
    {value: "dnssec_candidates", label: "DNSSEC candidates"},
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
        ${filterOptgroup("Provider Types", providerOptions, active)}
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

async function renderOverview(app) {
  const [summary, providers, classes, broken] = await Promise.all([
    loadJson("data/summary.json"),
    loadJson("data/providers.json"),
    loadJson("data/classes.json"),
    loadJson("data/broken.json")
  ]);
  app.innerHTML = `${snapshot(summary)}
    <section class="grid">
      <article class="panel"><h2>Provider Dominance</h2>${bars(providers, "provider_key", "names_count")}</article>
      <article class="panel"><h2>On-Chain Classes</h2>${bars(classes, "class", "count")}</article>
      <article class="panel"><h2>DANE</h2>
        <div class="stat-list">
          <div class="stat-line"><span>DS records</span><strong>${fmt.format(summary.ds_records)}</strong></div>
          <div class="stat-line"><span>Valid DANE</span><strong>${fmt.format(summary.dane_working)}</strong></div>
        </div>
      </article>
      <article class="panel"><h2>Failure Reasons</h2>${bars(broken.reasons, "failure_reason", "count", 10)}</article>
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

function namesScrollControls(collection, page, rows, disabled = false) {
  const pageCount = Number(collection.page_count || 0);
  if (disabled || pageCount <= page || !rows.length) return "";
  return `<div class="scroll-controls">
    <button class="load-more" id="load-more-names" type="button">Load more</button>
    <p class="meta" id="names-scroll-status">${pageRangeMeta(collection, page, rows)}</p>
  </div>`;
}

function wireNamesInfiniteScroll(collection, page, columns) {
  const button = document.getElementById("load-more-names");
  const tbody = document.getElementById("names-tbody");
  const status = document.getElementById("names-scroll-status");
  if (!button || !tbody) return;
  const pageCount = Number(collection.page_count || 0);
  const pageSize = Number(collection.page_size || 0) || 100;
  let nextPage = page + 1;
  let loadedRows = tbody.rows.length;
  let loading = false;

  const updateStatus = () => {
    if (!status) return;
    const start = (page - 1) * pageSize + 1;
    const end = Math.min(start + loadedRows - 1, Number(collection.row_count || 0));
    status.textContent = `${fmt.format(start)}-${fmt.format(end)} of ${fmt.format(collection.row_count || 0)} exported rows`;
  };

  const loadNext = async () => {
    if (loading || nextPage > pageCount) return;
    loading = true;
    button.disabled = true;
    button.textContent = "Loading";
    try {
      const data = await loadPageJson(pagePath(collection.path_template, nextPage));
      const rows = Array.isArray(data.rows) ? data.rows : [];
      tbody.insertAdjacentHTML("beforeend", tableRows(rows, columns));
      loadedRows += rows.length;
      nextPage += 1;
      updateStatus();
      if (nextPage > pageCount) {
        button.remove();
        return;
      }
    } finally {
      loading = false;
      if (nextPage <= pageCount) {
        button.disabled = false;
        button.textContent = "Load more";
      }
    }
  };

  button.addEventListener("click", loadNext);
  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) loadNext();
    }, {rootMargin: "600px"});
    observer.observe(button);
  }
}

function namesColumns(rowDetail) {
  const compactColumns = [
    {key: "name", label: "Name"},
    {key: "onchain_class", label: "Class"},
    {key: "provider_guess", label: "Provider"},
    {key: "provider_type", label: "Provider type"},
    {key: "record_types", label: "Records"},
    {key: "has_ds", label: "DS"},
    {key: "dnssec_status", label: "DNSSEC"},
    {key: "tlsa_status", label: "TLSA"},
    {key: "dane_status", label: "DANE"},
    {key: "failure_reason", label: "Failure"}
  ];
  if (rowDetail === "compact") return compactColumns;
  return [
    ...compactColumns.slice(0, 5),
    {key: "ns_names", label: "NS"},
    {key: "synth4", label: "SYNTH4"},
    {key: "synth6", label: "SYNTH6"},
    ...compactColumns.slice(5)
  ];
}

async function renderNames(app) {
  const [summary, providers, broken, loadedPageData] = await Promise.all([
    loadJson("data/summary.json"),
    loadJson("data/providers.json"),
    loadJson("data/broken.json"),
    loadPaginatedRows("data/names-pages.json", activeFilter())
  ]);
  const filter = activeFilter();
  const query = activeSearch();
  const pageData = await applySearchToPageData(loadedPageData, query);
  const columns = namesColumns(pageData.collection.row_detail);
  app.innerHTML = `${filterNotice(filter, pageData.index.collections.all.row_count, loadedPageData.collection.row_count)}
    <section class="panel full">
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
      ${lookupNotice(pageData, "names")}
      ${table(pageData.rows, columns, query ? "No names match this search." : "No rows in this page.", {tbodyId: "names-tbody"})}
      ${namesScrollControls(pageData.collection, pageData.page, pageData.rows, Boolean(query))}
    </section>`;
  wireAutoSubmitFilter();
  wireNamesInfiniteScroll(pageData.collection, pageData.page, columns);
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

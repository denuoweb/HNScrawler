const fmt = new Intl.NumberFormat("en-US");
const PAGE_FETCH_MIN_DELAY_MS = 350;
const COLLECTION_FETCH_BATCH_SIZE = 8;
let nextPageFetchAt = 0;
const collectionRowsCache = new Map();

async function loadJson(path) {
  const response = await fetch(path);
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

function activeProviderFilter() {
  return new URLSearchParams(window.location.search).get("provider_filter") || activeFilter();
}

function hasItems(value) {
  return Array.isArray(value) && value.length > 0;
}

function hasDs(row) {
  return row.has_ds === true || Number(row.has_ds || 0) === 1;
}

function filterName(filter) {
  return ({
    direct_ip_records: "direct IP records",
    delegated_names: "delegated names",
    default_provider_names: "default providers",
    ds_records: "DS records",
    dnssec_candidates: "DNSSEC candidates",
    likely_websites: "likely websites",
    strict_hns_working: "strict HNS working",
    doh_fallback_required: "fallback required",
    dane_working: "working DANE",
    missing_glue: "missing GLUE",
    missing_glue_only: "missing GLUE only",
    stale_tlsa: "stale TLSA",
    stale_tlsa_only: "stale TLSA only",
    provider_has_working: "working providers",
    provider_has_dane: "DANE providers",
    provider_has_likely_websites: "likely website providers"
  })[filter] || filter;
}

function rowMatchesFilter(row, filter) {
  const predicates = {
    direct_ip_records: (item) => hasItems(item.synth4) || hasItems(item.synth6),
    delegated_names: (item) => hasItems(item.ns_names),
    ds_records: (item) => hasDs(item),
    dnssec_candidates: (item) => hasDs(item) && hasItems(item.ns_names),
    likely_websites: (item) => hasItems(item.synth4) || hasItems(item.synth6) || hasItems(item.glue4) || hasItems(item.glue6) || (hasDs(item) && hasItems(item.ns_names)),
    strict_hns_working: (item) => item.strict_hns_status === "working",
    doh_fallback_required: (item) => ["required", "doh_fallback_only"].includes(item.doh_fallback_status),
    dane_working: (item) => item.dane_status === "valid",
    missing_glue: (item) => item.failure_reason === "missing_glue",
    missing_glue_only: (item) => item.failure_reason === "missing_glue" || (hasItems(item.ns_names) && !hasItems(item.glue4) && !hasItems(item.glue6) && !item.failure_reason),
    stale_tlsa: (item) => item.failure_reason === "stale_tlsa_spki_mismatch",
    stale_tlsa_only: (item) => item.failure_reason === "stale_tlsa_spki_mismatch"
  };
  return predicates[filter] ? predicates[filter](row) : true;
}

function providerMatchesFilter(row, filter) {
  if (filter === "default_provider_names") return row.provider_type === "default_parking";
  if (filter === "provider_has_working") return Number(row.working_count || 0) > 0;
  if (filter === "provider_has_dane") return Number(row.dane_count || 0) > 0;
  if (filter === "provider_has_likely_websites") return Number(row.likely_website_count || 0) > 0;
  if (filter.startsWith("provider_type:")) return row.provider_type === filter.slice("provider_type:".length);
  return true;
}

function applyFilter(rows, filter, predicate = rowMatchesFilter) {
  if (!filter) return rows;
  return rows.filter((row) => predicate(row, filter));
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

function table(rows, columns, emptyMessage = "No rows in this page.") {
  if (!rows.length) return `<p class="empty-state">${escapeHtml(emptyMessage)}</p>`;
  return `<div class="table-wrap"><table><thead><tr>${columns.map((column) => `<th>${column.label}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${columns.map((column) => `<td>${formatCell(row[column.key])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}

function formatCell(value) {
  if (Array.isArray(value)) return escapeHtml(value.join(", "));
  if (value === null || value === undefined) return "";
  if (typeof value === "number") return fmt.format(value);
  return escapeHtml(String(value));
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
    ${metric("Delegated", summary.delegated_names, `${fmt.format(summary.delegated_with_glue)} with glue`)}
    ${metric("Working DANE", summary.dane_working, `${fmt.format(summary.strict_hns_working)} strict HNS working`)}
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
  return window.location.pathname.split("/").pop() || "index.html";
}

function pageHref(page) {
  const params = new URLSearchParams(window.location.search);
  if (page <= 1) {
    params.delete("page");
  } else {
    params.set("page", String(page));
  }
  const query = params.toString();
  const path = currentPageName();
  return query ? `${path}?${query}` : path;
}

function hrefWithoutParams(keys) {
  const params = new URLSearchParams(window.location.search);
  keys.forEach((key) => params.delete(key));
  const query = params.toString();
  const path = currentPageName();
  return query ? `${path}?${query}` : path;
}

function hrefWithParams(values) {
  const params = new URLSearchParams(window.location.search);
  Object.entries(values).forEach(([key, value]) => {
    if (value === null || value === "") {
      params.delete(key);
    } else {
      params.set(key, value);
    }
  });
  const query = params.toString();
  const path = currentPageName();
  return query ? `${path}?${query}` : path;
}

function providerFilterControls(providers, active) {
  const types = Array.from(new Set(providers.map((row) => row.provider_type).filter(Boolean))).sort();
  const options = [
    {value: "", label: "All"},
    ...types.map((type) => ({value: `provider_type:${type}`, label: type.replaceAll("_", " ")})),
    {value: "provider_has_likely_websites", label: "Likely websites"},
    {value: "provider_has_working", label: "Working"},
    {value: "provider_has_dane", label: "DANE"}
  ];
  return `<div class="filter-controls" aria-label="Provider filters">${options.map((item) => {
    const selected = item.value === active;
    return `<a class="filter-chip${selected ? " active" : ""}" href="${escapeHtml(hrefWithParams({provider_filter: item.value || null, filter: null, page: null}))}">${escapeHtml(item.label)}</a>`;
  }).join("")}</div>`;
}

function pagination(collection, page) {
  const pageCount = Number(collection.page_count || 0);
  if (pageCount <= 1) return "";
  const prev = page > 1
    ? `<a class="page-link" href="${escapeHtml(pageHref(page - 1))}">Previous</a>`
    : `<span class="page-link disabled">Previous</span>`;
  const next = page < pageCount
    ? `<a class="page-link" href="${escapeHtml(pageHref(page + 1))}">Next</a>`
    : `<span class="page-link disabled">Next</span>`;
  return `<nav class="pagination" aria-label="Pagination">${prev}<span class="page-status">Page ${fmt.format(page)} of ${fmt.format(pageCount)}</span>${next}</nav>`;
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
    const response = await fetch(`api/name?name=${encodeURIComponent(name)}`);
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
      exact: false
    },
    lookup
  };
}

function searchHiddenInputs() {
  const params = new URLSearchParams(window.location.search);
  params.delete("q");
  params.delete("page");
  return Array.from(params.entries()).map(([key, value]) => (
    `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`
  )).join("");
}

function searchControls({id, label, placeholder, query, search}) {
  const clearLink = query
    ? `<a class="search-clear" href="${escapeHtml(hrefWithoutParams(["q", "page"]))}">Clear</a>`
    : "";
  const searchMeta = search
    ? `<p class="meta search-meta">${search.exact
      ? `Exact lookup "${escapeHtml(query)}" matched ${fmt.format(search.matchedCount)} full-snapshot row.`
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
    return `<p class="meta search-meta">Exact lookup uses the full snapshot. Browse pagination remains capped for bandwidth.</p>`;
  }
  return `<p class="meta search-meta">Exact lookup did not find ${escapeHtml(pageData.lookup.normalized || activeSearch())} in the full snapshot. The table search below only scans the exported browse sample.</p>`;
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
      <article class="panel"><h2>Broken Paths</h2>${bars(broken.reasons, "failure_reason", "count", 10)}</article>
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
      <a href="${escapeHtml(item.filter_link)}">Filtered table</a>
    </article>`).join("")}</section>`;
}

async function renderProviders(app) {
  const providers = await loadJson("data/providers.json");
  const filter = activeProviderFilter();
  const rows = applyFilter(providers, filter, providerMatchesFilter);
  app.innerHTML = `${filterNotice(filter, providers.length, rows.length)}<section class="panel full"><div class="panel-heading"><h2>Providers</h2>${providerFilterControls(providers, filter)}</div>${bars(rows, "provider_key", "names_count", 20)}</section>
    <section class="panel full">${table(rows, [
      {key: "provider_key", label: "Provider"},
      {key: "provider_type", label: "Type"},
      {key: "ns_pattern", label: "NS Pattern"},
      {key: "ip_pattern", label: "IP Pattern"},
      {key: "names_count", label: "Names"},
      {key: "likely_website_count", label: "Likely websites"},
      {key: "working_count", label: "Working"},
      {key: "dane_count", label: "DANE"}
    ])}</section>`;
}

async function renderClasses(app) {
  const classes = await loadJson("data/classes.json");
  app.innerHTML = `<section class="panel full"><h2>Classes</h2>${bars(classes, "class", "count", 20)}</section>`;
}

async function renderNames(app) {
  const [summary, loadedPageData] = await Promise.all([
    loadJson("data/summary.json"),
    loadPaginatedRows("data/names-pages.json", activeFilter())
  ]);
  const filter = activeFilter();
  const query = activeSearch();
  const pageData = await applySearchToPageData(loadedPageData, query);
  app.innerHTML = `${filterNotice(filter, pageData.index.collections.all.row_count, loadedPageData.collection.row_count)}
    <section class="panel full">
      <div class="panel-heading">
        <div><h2>Names</h2><p class="meta">${pageRangeMeta(pageData.collection, pageData.page, pageData.rows)} - height ${summary.last_indexed_height ?? ""}</p></div>
        ${pagination(pageData.collection, pageData.page)}
      </div>
      ${searchControls({
        id: "names-search",
        label: "Search Names",
        placeholder: "Name, provider, records, status",
        query,
        search: pageData.search
      })}
      ${lookupNotice(pageData, "names")}
      ${table(pageData.rows, [
        {key: "name", label: "Name"},
        {key: "onchain_class", label: "Class"},
        {key: "provider_guess", label: "Provider"},
        {key: "record_types", label: "Records"},
        {key: "ns_names", label: "NS"},
        {key: "synth4", label: "SYNTH4"},
        {key: "synth6", label: "SYNTH6"},
        {key: "dnssec_status", label: "DNSSEC"},
        {key: "dane_status", label: "DANE"},
        {key: "failure_reason", label: "Failure"}
      ], query ? "No names match this search." : "No rows in this page.")}
      ${pagination(pageData.collection, pageData.page)}
    </section>`;
}

async function renderBroken(app) {
  const broken = await loadJson("data/broken.json");
  const filter = activeFilter();
  const examples = applyFilter(broken.examples, filter);
  app.innerHTML = `<section class="grid">
    <article class="panel"><h2>Failure Reasons</h2>${bars(broken.reasons, "failure_reason", "count", 20)}</article>
    <article class="panel"><h2>Examples</h2>${filterNotice(filter, broken.examples.length, examples.length)}${table(examples, [
      {key: "name", label: "Name"},
      {key: "onchain_class", label: "Class"},
      {key: "provider_guess", label: "Provider"},
      {key: "strict_hns_status", label: "Strict HNS"},
      {key: "doh_fallback_status", label: "Fallback"},
      {key: "failure_reason", label: "Reason"},
      {key: "checked_at", label: "Checked"}
    ])}</article>
  </section>`;
}

async function renderDane(app) {
  const [summary, dane, loadedPageData] = await Promise.all([
    loadJson("data/summary.json"),
    loadJson("data/dane.json"),
    loadPaginatedRows("data/dane-pages.json", activeFilter())
  ]);
  const filter = activeFilter();
  const query = activeSearch();
  const pageData = await applySearchToPageData(loadedPageData, query, {daneOnly: true});
  app.innerHTML = `<section class="grid">
    <article class="panel"><h2>DANE Summary</h2>
      <div class="stat-list">
        <div class="stat-line"><span>DS records</span><strong>${fmt.format(dane.ds_count)}</strong></div>
        <div class="stat-line"><span>Valid DANE</span><strong>${fmt.format(dane.valid_dane_count)}</strong></div>
      </div>
      <p class="meta">Height ${summary.last_indexed_height ?? ""}</p>
    </article>
    <article class="panel"><div class="panel-heading">
      <div><h2>DANE Rows</h2>${filterNotice(filter, pageData.index.collections.all.row_count, loadedPageData.collection.row_count)}<p class="meta">${pageRangeMeta(pageData.collection, pageData.page, pageData.rows)}</p></div>
      ${pagination(pageData.collection, pageData.page)}
    </div>
    ${searchControls({
      id: "dane-search",
      label: "Search DANE Rows",
      placeholder: "Name, DNSSEC, TLSA, DANE, failure",
      query,
      search: pageData.search
    })}
    ${lookupNotice(pageData, "dane")}
    ${table(pageData.rows, [
      {key: "name", label: "Name"},
      {key: "has_ds", label: "DS"},
      {key: "ns_names", label: "NS"},
      {key: "dnssec_status", label: "DNSSEC"},
      {key: "tlsa_status", label: "TLSA"},
      {key: "dane_status", label: "DANE"},
      {key: "failure_reason", label: "Failure"},
      {key: "checked_at", label: "Checked"}
    ], query ? "No DANE rows match this search." : "No rows in this page.")}${pagination(pageData.collection, pageData.page)}</article>
  </section>`;
}

async function boot() {
  const page = document.body.dataset.page || "overview";
  setActiveNav(page);
  const app = document.getElementById("app");
  const renderers = {
    overview: renderOverview,
    faq: renderFaq,
    providers: renderProviders,
    classes: renderClasses,
    names: renderNames,
    broken: renderBroken,
    dane: renderDane
  };
  try {
    await (renderers[page] || renderOverview)(app);
  } catch (error) {
    app.innerHTML = `<section class="panel"><h2>Load Failed</h2><p class="definition">${escapeHtml(error.message)}</p></section>`;
  }
}

boot();

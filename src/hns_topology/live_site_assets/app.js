const numberFormat = new Intl.NumberFormat();
const PAGE_SIZE = 100;

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function loadJson(path) {
  const response = await fetch(path, {cache: "no-store"});
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json();
}

function activeCategory(summary) {
  const requested = new URLSearchParams(window.location.search).get("category");
  if (["https", "http_only", "offline"].includes(requested)) return requested;
  if (Number(summary.https_count || 0) > 0) return "https";
  if (Number(summary.http_only_count || 0) > 0) return "http_only";
  return "offline";
}

function activeSearch() {
  return new URLSearchParams(window.location.search).get("q") || "";
}

function activePage() {
  const page = Number(new URLSearchParams(window.location.search).get("page") || 1);
  return Number.isFinite(page) && page > 0 ? Math.floor(page) : 1;
}

function hrefWith(updates) {
  const url = new URL(window.location.href);
  Object.entries(updates).forEach(([key, value]) => {
    if (value === null || value === "") url.searchParams.delete(key);
    else url.searchParams.set(key, String(value));
  });
  return `${url.pathname}${url.search}`;
}

function categoryLabel(category) {
  return ({https: "HTTPS Endpoints", http_only: "HTTP Endpoints", offline: "No Endpoint Available"})[category] || category;
}

function categoryCount(summary, category) {
  return Number(({
    https: summary.https_count,
    http_only: summary.http_only_count,
    offline: summary.offline_count
  })[category] || 0);
}

function protocolBadge(row) {
  if (row.category === "https") return '<span class="badge badge-secure">HTTPS</span>';
  if (row.category === "http_only") return '<span class="badge badge-http">HTTP</span>';
  return '<span class="badge badge-offline">No endpoint</span>';
}

function trustBadges(row) {
  const badges = [];
  if (row.dane_status === "valid") badges.push('<span class="badge badge-dane">DANE verified</span>');
  else if (String(row.tlsa_status || "").startsWith("present")) badges.push('<span class="badge badge-neutral">TLSA present</span>');
  if (row.webpki_status === "valid") badges.push('<span class="badge badge-webpki">WebPKI</span>');
  if (row.listing_state === "degraded") badges.push('<span class="badge badge-degraded">Recheck pending</span>');
  return badges.join(" ");
}

function responseText(row) {
  if (row.category === "https") return row.https_status_code ? `HTTPS ${row.https_status_code}` : "HTTPS response";
  if (row.category === "http_only") return row.http_status_code ? `HTTP ${row.http_status_code}` : "HTTP response";
  const reason = String(row.failure_reason || "Needs review").replaceAll("_", " ");
  const label = reason.charAt(0).toUpperCase() + reason.slice(1);
  return row.https_status_code ? `${label} - HTTPS ${row.https_status_code}` : label;
}

function checkedText(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"});
}

function actionCell(row) {
  if (row.category === "http_only") {
    const params = new URLSearchParams({
      domain: row.host,
      domain_type: "hns",
      intent: "generate_tlsa"
    });
    return `<a class="button button-upgrade" href="/dane-generator/?${params.toString()}">Upgrade HTTPS</a>`;
  }
  if (row.category === "offline") {
    return `<a class="button" href="/hns-topology/names.html?q=${encodeURIComponent(row.root_name)}">Review</a>`;
  }
  return `<a class="button" href="${escapeHtml(row.url)}" rel="noreferrer">Open</a>`;
}

function rowHtml(row) {
  const source = Array.isArray(row.sources) ? row.sources.join(", ") : "";
  const hostHref = row.url || `/hns-topology/names.html?q=${encodeURIComponent(row.root_name)}`;
  return `<tr>
    <td class="host-cell" data-label="Host">
      <a class="host-link" href="${escapeHtml(hostHref)}" rel="noreferrer">${escapeHtml(row.host)}</a>
      ${row.host !== row.root_name ? `<span class="root-name">${escapeHtml(row.root_name)}/</span>` : ""}
    </td>
    <td data-label="Protocol"><div class="badge-line">${protocolBadge(row)} ${trustBadges(row)}</div><span class="response">${escapeHtml(responseText(row))}</span></td>
    <td data-label="DNS"><strong>${escapeHtml(row.dnssec_status || "unknown")}</strong><span>${escapeHtml(row.dns_status || "")}</span></td>
    <td data-label="Source"><strong>${escapeHtml(row.provider_guess || "unknown")}</strong><span title="${escapeHtml(source)}">${escapeHtml(source)}</span></td>
    <td data-label="Checked"><time datetime="${escapeHtml(row.checked_at)}">${escapeHtml(checkedText(row.checked_at))}</time></td>
    <td class="action-cell" data-label="Action">${actionCell(row)}</td>
  </tr>`;
}

function categoryTabs(summary, active) {
  return `<nav class="category-tabs" aria-label="Endpoint protocol">
    ${["https", "http_only", "offline"].map((category) => `
      <a class="category-tab${category === active ? " active" : ""}" href="${escapeHtml(hrefWith({category, page: null}))}">
        <span>${escapeHtml(categoryLabel(category))}</span>
        <strong>${numberFormat.format(categoryCount(summary, category))}</strong>
      </a>`).join("")}
  </nav>`;
}

function metrics(summary) {
  const due = Number(summary.candidate_plan?.due_total || 0);
  const sweep = summary.sweep_coverage || {};
  return `<section class="metrics">
    <div><span>Reachable endpoints</span><strong>${numberFormat.format(summary.online_count || 0)}</strong></div>
    <div><span>HTTPS endpoints</span><strong>${numberFormat.format(summary.https_count || 0)}</strong></div>
    <div><span>HTTP endpoints</span><strong>${numberFormat.format(summary.http_only_count || 0)}</strong></div>
    <div><span>Evidence queue</span><strong>${numberFormat.format(due)}</strong></div>
    <div><span>Broad roots checked</span><strong>${numberFormat.format(sweep.checked || 0)}</strong></div>
  </section>`;
}

function pagination(page, pageCount) {
  if (pageCount <= 1) return "";
  return `<nav class="pagination" aria-label="Endpoint pages">
    <a class="page-button${page <= 1 ? " disabled" : ""}" href="${escapeHtml(hrefWith({page: Math.max(1, page - 1)}))}">Previous</a>
    <span>Page ${numberFormat.format(page)} of ${numberFormat.format(pageCount)}</span>
    <a class="page-button${page >= pageCount ? " disabled" : ""}" href="${escapeHtml(hrefWith({page: Math.min(pageCount, page + 1)}))}">Next</a>
  </nav>`;
}

function searchForm(query) {
  return `<form class="search-form" action="/hns-live/" method="get">
    <input type="hidden" name="category" value="${escapeHtml(new URLSearchParams(window.location.search).get("category") || "")}">
    <label for="site-search">Search</label>
    <div>
      <input id="site-search" type="search" name="q" value="${escapeHtml(query)}" placeholder="Host, root, provider">
      <button type="submit">Search</button>
      ${query ? `<a href="${escapeHtml(hrefWith({q: null, page: null}))}">Clear</a>` : ""}
    </div>
  </form>`;
}

function render(app, summary, data) {
  const category = activeCategory(summary);
  const query = activeSearch().trim().toLowerCase();
  const matching = (data.rows || []).filter((row) => {
    if (row.category !== category) return false;
    if (!query) return true;
    return [row.host, row.root_name, row.provider_guess, ...(row.sources || [])]
      .some((value) => String(value || "").toLowerCase().includes(query));
  });
  const pageCount = Math.max(1, Math.ceil(matching.length / PAGE_SIZE));
  const page = Math.min(activePage(), pageCount);
  const rows = matching.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  app.innerHTML = `${metrics(summary)}
    ${categoryTabs(summary, category)}
    <section class="directory-band">
      <header class="directory-heading">
        <div><h2>${escapeHtml(categoryLabel(category))}</h2><span>${numberFormat.format(matching.length)} hosts</span></div>
        <time datetime="${escapeHtml(summary.generated_at || "")}">${escapeHtml(checkedText(summary.generated_at))}</time>
      </header>
      ${searchForm(query)}
      ${pagination(page, pageCount)}
      <div class="table-wrap"><table>
        <thead><tr><th>Host</th><th>Protocol</th><th>DNS</th><th>Source</th><th>Checked</th><th></th></tr></thead>
        <tbody>${rows.length ? rows.map(rowHtml).join("") : '<tr><td class="empty" colspan="6">No matching endpoints.</td></tr>'}</tbody>
      </table></div>
      ${pagination(page, pageCount)}
    </section>`;
}

async function boot() {
  const app = document.getElementById("app");
  try {
    const [summary, sites] = await Promise.all([
      loadJson("data/summary.json"),
      loadJson("data/sites.json")
    ]);
    render(app, summary, sites);
  } catch (error) {
    app.innerHTML = `<section class="error-panel"><h2>Live directory unavailable</h2><p>${escapeHtml(error.message)}</p></section>`;
  }
}

boot();

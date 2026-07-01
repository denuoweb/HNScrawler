const fmt = new Intl.NumberFormat("en-US");

async function loadJson(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`Failed to load ${path}`);
  return response.json();
}

function pct(value, total) {
  if (!total) return "0%";
  return `${((value / total) * 100).toFixed(2)}%`;
}

function metric(label, value, sub = "") {
  return `<article class="metric"><span class="label">${label}</span><span class="value">${fmt.format(value ?? 0)}</span><span class="sub">${sub}</span></article>`;
}

function bars(rows, labelKey, valueKey, limit = 12) {
  const max = Math.max(1, ...rows.map((row) => Number(row[valueKey] || 0)));
  return `<div class="bar-list">${rows.slice(0, limit).map((row) => {
    const value = Number(row[valueKey] || 0);
    return `<div class="bar-row"><span class="bar-label" title="${escapeHtml(row[labelKey])}">${escapeHtml(row[labelKey])}</span><span class="bar-track"><span class="bar-fill" style="width:${(value / max) * 100}%"></span></span><strong>${fmt.format(value)}</strong></div>`;
  }).join("")}</div>`;
}

function table(rows, columns) {
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
      <article class="panel"><h2>Downloads</h2><div class="downloads">
        <a href="data/summary.json">summary.json</a>
        <a href="data/providers.json">providers.json</a>
        <a href="data/classes.json">classes.json</a>
        <a href="data/names.csv">names.csv</a>
        <a href="data/topology.sqlite.gz">topology.sqlite.gz</a>
      </div><p class="meta">Height ${summary.last_indexed_height ?? ""} generated ${summary.generated_at ?? ""}</p></article>
    </section>`;
}

async function renderFaq(app) {
  const [summary, answers] = await Promise.all([
    loadJson("data/summary.json"),
    loadJson("data/faq_answers.json")
  ]);
  app.innerHTML = `${snapshot(summary)}<section class="faq-list">${answers.map((item) => `
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
  const [summary, providers] = await Promise.all([loadJson("data/summary.json"), loadJson("data/providers.json")]);
  app.innerHTML = `${snapshot(summary)}<section class="panel full"><h2>Providers</h2>${bars(providers, "provider_key", "names_count", 20)}</section>
    <section class="panel full">${table(providers, [
      {key: "provider_key", label: "Provider"},
      {key: "provider_type", label: "Type"},
      {key: "names_count", label: "Names"},
      {key: "likely_website_count", label: "Likely websites"},
      {key: "working_count", label: "Working"},
      {key: "dane_count", label: "DANE"}
    ])}</section>`;
}

async function renderClasses(app) {
  const [summary, classes] = await Promise.all([loadJson("data/summary.json"), loadJson("data/classes.json")]);
  app.innerHTML = `${snapshot(summary)}<section class="panel full"><h2>Classes</h2>${bars(classes, "class", "count", 20)}</section>`;
}

async function renderNames(app) {
  const [summary, names] = await Promise.all([loadJson("data/summary.json"), loadJson("data/names.json")]);
  app.innerHTML = `${snapshot(summary)}<section class="panel full"><h2>Names</h2>${table(names, [
    {key: "name", label: "Name"},
    {key: "onchain_class", label: "Class"},
    {key: "provider_guess", label: "Provider"},
    {key: "record_types", label: "Records"},
    {key: "ns_names", label: "NS"},
    {key: "synth4", label: "SYNTH4"},
    {key: "synth6", label: "SYNTH6"},
    {key: "dane_status", label: "DANE"},
    {key: "failure_reason", label: "Failure"}
  ])}</section>`;
}

async function renderBroken(app) {
  const [summary, broken] = await Promise.all([loadJson("data/summary.json"), loadJson("data/broken.json")]);
  app.innerHTML = `${snapshot(summary)}<section class="grid">
    <article class="panel"><h2>Failure Reasons</h2>${bars(broken.reasons, "failure_reason", "count", 20)}</article>
    <article class="panel"><h2>Examples</h2>${table(broken.examples, [
      {key: "name", label: "Name"},
      {key: "onchain_class", label: "Class"},
      {key: "provider_guess", label: "Provider"},
      {key: "failure_reason", label: "Reason"},
      {key: "checked_at", label: "Checked"}
    ])}</article>
  </section>`;
}

async function renderDane(app) {
  const [summary, dane] = await Promise.all([loadJson("data/summary.json"), loadJson("data/dane.json")]);
  app.innerHTML = `${snapshot(summary)}<section class="grid">
    <article class="panel"><h2>DANE Summary</h2>
      <div class="stat-list">
        <div class="stat-line"><span>DS records</span><strong>${fmt.format(dane.ds_count)}</strong></div>
        <div class="stat-line"><span>Valid DANE</span><strong>${fmt.format(dane.valid_dane_count)}</strong></div>
      </div>
    </article>
    <article class="panel"><h2>DANE Rows</h2>${table(dane.rows, [
      {key: "name", label: "Name"},
      {key: "has_ds", label: "DS"},
      {key: "tlsa_status", label: "TLSA"},
      {key: "dane_status", label: "DANE"},
      {key: "failure_reason", label: "Failure"},
      {key: "checked_at", label: "Checked"}
    ])}</article>
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

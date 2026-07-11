const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

function loadApp(search = "") {
  const source = fs.readFileSync("src/hns_topology/site_assets/app.js", "utf8")
    .replace(/\nboot\(\);\s*$/, "\n");
  const context = {
    URL,
    URLSearchParams,
    Intl,
    console,
    window: {
      __HNS_TOPOLOGY_BASE__: "/hns-topology/",
      location: {
        origin: "https://hns.denuoweb.com",
        pathname: "/hns-topology/names.html",
        search
      }
    },
    document: {
      body: {dataset: {page: "names"}},
      querySelectorAll: () => [],
      getElementById: () => ({innerHTML: ""})
    }
  };
  vm.runInNewContext(source, context);
  return context;
}

function loadOverviewApp(search = "") {
  const source = fs.readFileSync("src/hns_topology/site_assets/app.js", "utf8")
    .replace(/\nboot\(\);\s*$/, "\n");
  const context = {
    URL,
    URLSearchParams,
    Intl,
    console,
    Date,
    setTimeout,
    fetch: async () => ({
      ok: true,
      json: async () => ({
        rows: [{ip: "203.0.113.11", names_count: 2, field_counts: {GLUE4: 2}, role: "unknown"}]
      })
    }),
    window: {
      __HNS_TOPOLOGY_BASE__: "/hns-topology/",
      location: {
        origin: "https://hns.denuoweb.com",
        pathname: "/hns-topology/index.html",
        search
      },
      history: {
        replaced: "",
        replaceState(_state, _title, url) {
          this.replaced = url;
        }
      }
    },
    document: {
      body: {dataset: {page: "overview"}},
      querySelectorAll: () => [],
      getElementById: () => ({innerHTML: ""})
    }
  };
  vm.runInNewContext(source, context);
  return context;
}

{
  const app = loadApp("?filter=stage%3Atlsa_gap&q=mercenary");
  const html = app.hnsNameLink("mercenary", "mercenary");
  assert.equal(html.includes("shakeshift"), false);
  assert.equal(
    html,
    '<a href="/hns-topology/names.html?filter=stage%3Atlsa_gap&amp;q=mercenary">mercenary</a>'
  );
}

{
  const app = loadApp("");
  const html = app.nameserverCell({nameserver: "ns1.skyinclude."});
  assert.equal(html.includes("search=nameserver"), true);
  assert.equal(html.includes("filter=delegated_names"), false);
  assert.equal(html.includes("q=ns1.skyinclude."), true);
}

{
  const app = loadApp("");
  assert.equal(app.normalizeIpQuery("2001:db8::10"), "2001:db8::10");
  assert.equal(app.normalizeIpQuery("[2001:db8::10]"), "2001:db8::10");
  assert.equal(
    app.ipAddressLookupPath("2001:db8::10"),
    "data/ip-addresses/2001%253Adb8%253A%253A10.json"
  );
  assert.equal(
    app.pagePath("ip-addresses/2001%3Adb8%3A%3A10/page-{page}.json", 1),
    "data/ip-addresses/2001%253Adb8%253A%253A10/page-1.json"
  );
  assert.equal(app.normalizeNameserverQuery("ns1.skyinclude."), "ns1.skyinclude");
  assert.equal(
    app.nameserverLookupIndexPath(),
    "data/nameservers/index.json"
  );
  assert.match(
    app.nameserverShardPath("a.shakestation", {shard_count: 1024, shard_width: 3}),
    /^data\/nameservers\/shards\/[0-9a-f]{3}\.jsonl$/
  );
}

{
  const app = loadApp("");
  const html = app.adoptionFunnel({
    active_names: 100,
    compliance_stages: [
      {stage: "tlsa_present", count: 99, filter_link: "names.html?filter=stage:tlsa_present"},
      {stage: "tlsa_gap", count: 7, filter_link: "names.html?filter=stage:tlsa_gap"}
    ]
  }, {
    live_dane_evidence: {
      observed_roots: 2,
      checked_roots: 5,
      active_roots: 8,
      last_checked_at: "2026-07-11T00:00:00Z"
    }
  });
  assert.equal(html.includes("HNS Readiness and Live Evidence"), true);
  assert.equal(html.includes("Active names"), false);
  assert.equal(html.includes("stage:tlsa_gap"), true);
  assert.equal(html.includes("DS + TLSA observed by live scan"), true);
  assert.equal(html.includes("99"), false);
}

{
  const app = loadApp("");
  assert.equal(
    app.ipFieldCountsCell({field_counts: {GLUE4: 12, Names: 12, names_count: 12, total_names: 12}}),
    "GLUE4 12"
  );
  assert.equal(app.providerLabel("namebase/default"), "Namebase");
  assert.equal(app.providerRuleBucketLabel("namebase/default"), "Namebase NS suffix matches");
  assert.equal(app.providerRuleBucketLabel("bulk/default"), "BNS study glue IP matches");
}

{
  const app = loadApp("");
  assert.match(app.liveStatusShard("ansbank"), /^[0-9a-f]{2}$/);
  const html = app.renderLiveDnsStatus({
    roots: {
      ansbank: [{
        host: "ansbank",
        dns_status: "unreachable",
        addresses: [],
        dnssec_status: "dnskey_missing",
        tlsa_status: "missing",
        dane_status: "missing",
        http_status: "not_checked",
        https_status: "failed",
        webpki_status: "not_checked",
        failure_reason: "authoritative_dns_unreachable",
        checked_at: "2026-07-11T20:39:29Z"
      }]
    }
  }, "ansbank");
  assert.equal(html.includes("DNS unreachable"), true);
  assert.equal(html.includes("authoritative dns unreachable"), true);
  assert.equal(app.renderLiveDnsStatus(null, "missing").includes("No live scan result"), true);
}

{
  const app = loadApp("");
  const html = app.topologySignals(
    {top_resource_ips: []},
    {
      resourceIps: {
        collection: {page_count: 2, path_template: "overview-pages/resource_ips/page-{page}.json"},
        page: 1,
        rows: [{ip: "203.0.113.10", names_count: 1, field_counts: {SYNTH4: 1}, role: "unknown"}]
      },
      nameservers: {
        collection: {page_count: 1},
        page: 1,
        rows: []
      },
      resolvers: {
        collection: {page_count: 1},
        page: 1,
        rows: []
      }
    }
  );
  assert.equal(html.includes("Generator Handoffs"), false);
  assert.equal(html.includes("Provider Classification"), false);
  assert.equal(html.includes('data-overview-key="resourceIps"'), true);
  assert.equal(html.includes('data-overview-page="2"'), true);
  assert.equal(html.includes("<button"), true);
  assert.equal(html.includes('class="page-link" data-overview-key'), false);
  assert.equal(html.includes('href="/hns-topology/index.html?resource_ip_page=2"'), false);
}

(async () => {
  const app = loadOverviewApp("");
  let listener = null;
  const appRoot = {
    addEventListener(type, callback) {
      if (type === "click") listener = callback;
    },
    contains(node) {
      return node === control;
    }
  };
  const attrs = {};
  const article = {
    dataset: {overviewKey: "resourceIps"},
    innerHTML: "",
    getAttribute(key) {
      return attrs[key] || "";
    },
    setAttribute(key, value) {
      attrs[key] = value;
    },
    removeAttribute(key) {
      delete attrs[key];
    }
  };
  const control = {
    disabled: false,
    dataset: {
      overviewKey: "resourceIps",
      overviewPage: "2",
      overviewPageParam: "resource_ip_page"
    },
    closest(selector) {
      if (selector === "[data-overview-page]") return control;
      if (selector === ".overview-collection[data-overview-key]") return article;
      return null;
    }
  };
  let prevented = false;
  app.wireOverviewPagination(appRoot, {top_resource_ips: []}, {
    resourceIps: {
      collection: {page_count: 2, path_template: "overview-pages/resource_ips/page-{page}.json"},
      page: 1,
      rows: []
    }
  });
  assert.equal(typeof listener, "function");
  await listener({
    target: control,
    preventDefault() {
      prevented = true;
    }
  });
  assert.equal(prevented, true);
  assert.equal(attrs["aria-busy"], undefined);
  assert.equal(article.innerHTML.includes("<article"), false);
  assert.equal(article.innerHTML.includes("203.0.113.11"), true);
  assert.equal(app.window.history.replaced, "/hns-topology/index.html?resource_ip_page=2");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

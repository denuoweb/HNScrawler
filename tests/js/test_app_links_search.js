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

{
  const app = loadApp("?filter=stage%3Aservice_blocked&q=mercenary");
  const html = app.hnsNameLink("mercenary", "mercenary");
  assert.equal(html.includes("shakeshift"), false);
  assert.equal(
    html,
    '<a href="/hns-topology/names.html?filter=stage%3Aservice_blocked&amp;q=mercenary">mercenary</a>'
  );
}

{
  const app = loadApp("");
  const html = app.nameserverCell({nameserver: "ns1.skyinclude."});
  assert.equal(html.includes("search=text"), true);
  assert.equal(html.includes("filter=delegated_names"), true);
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
}

{
  const app = loadApp("");
  const html = app.hostDirectoryPanel({
    row_count: 1,
    rows: [
      {
        root_name: "crewball",
        host: "jaron.crewball",
        url: "https://jaron.crewball/",
        evidence_confidence: "dane_verified",
        dane_status: "valid",
        https_status: "working",
        checked_at: "2026-07-06T00:00:00Z"
      }
    ]
  });
  assert.equal(html.includes("Live HNS Hosts"), true);
  assert.equal(html.includes("https://jaron.crewball/"), true);
  assert.equal(html.includes("status-ok"), true);
  assert.equal(html.includes("names.html?q=crewball&amp;host=jaron.crewball"), true);
}

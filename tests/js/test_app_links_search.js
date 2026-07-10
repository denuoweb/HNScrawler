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
  const html = app.snapshot({
    active_names: 100,
    expired_names: 5,
    tlsa_present_names: 2,
    tlsa_evidence_names: 33,
    strict_hns_ready: 10,
    compliance_stage_counts: {
      tlsa_present: 0,
      tlsa_gap: 7,
      missing_glue: 3
    }
  });
  assert.equal(html.includes('<span class="label">TLSA observed</span><span class="value">2</span>'), true);
  assert.equal(html.includes("33 roots have stored TLSA probes"), true);
  assert.equal(html.includes("names.html?filter=tlsa_present_names"), true);
  assert.equal(html.includes("stage%3Atlsa_present"), false);
}

{
  const app = loadApp("");
  const commands = app.targetProbeCommands("secure", "192.0.2.53");
  assert.equal(commands.includes("dig @192.0.2.53 _443._tcp.secure. TLSA +norecurse +dnssec"), true);
  assert.equal(commands.includes("dig @192.0.2.53 _443._tcp.www.secure. TLSA +norecurse +dnssec"), true);
}

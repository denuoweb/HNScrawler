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
      {stage: "tlsa_gap", count: 7, filter_link: "names.html?filter=stage:tlsa_gap"}
    ]
  });
  assert.equal(html.includes("Static Compliance Pipeline"), true);
  assert.equal(html.includes("Active names"), false);
  assert.equal(html.includes("stage:tlsa_gap"), true);
}

{
  const app = loadApp("");
  const commands = app.targetProbeCommands("secure", "192.0.2.53");
  assert.equal(commands.includes("dig @192.0.2.53 _443._tcp.secure. TLSA +norecurse +dnssec"), true);
  assert.equal(commands.includes("dig @192.0.2.53 _443._tcp.www.secure. TLSA +norecurse +dnssec"), true);
}

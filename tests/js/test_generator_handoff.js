const assert = require("node:assert/strict");

const handoff = require("../../src/hns_topology/site_assets/generator_handoff.js");

function queryParams(url) {
  const parsed = new URL(url, "https://report.example");
  return Object.fromEntries(parsed.searchParams.entries());
}

assert.deepEqual(handoff.SUPPORTED_PARAMS, [
  "domain",
  "domain_type",
  "intent",
  "mode",
  "nameserver",
  "ns4",
  "ns6",
  "a",
  "aaaa",
  "port",
  "dnskey",
  "pem",
  "cert"
]);

{
  const url = handoff.buildUrl(
    {
      name: "secure",
      onchain_class: "DNSSEC_CANDIDATE",
      ns_names: ["ns1.secure"],
      glue4: ["198.51.100.2"],
      glue6: ["2001:db8::2"]
    },
    {intent: "generate_tlsa"}
  );

  assert.equal(
    url,
    "/dane-generator/?domain=secure%2F&domain_type=hns&intent=generate_tlsa&mode=delegated&nameserver=ns1.secure&ns4=198.51.100.2&ns6=2001%3Adb8%3A%3A2"
  );
  assert.deepEqual(queryParams(url), {
    domain: "secure/",
    domain_type: "hns",
    intent: "generate_tlsa",
    mode: "delegated",
    nameserver: "ns1.secure",
    ns4: "198.51.100.2",
    ns6: "2001:db8::2"
  });
}

{
  const params = handoff.handoffParams(
    {
      name: "direct",
      onchain_class: "DIRECT_SYNTH",
      record_types: ["SYNTH4"],
      first_synth4: "203.0.113.10"
    },
    {intent: "synth_setup"}
  );

  assert.equal(handoff.inferMode({
    onchain_class: "DIRECT_SYNTH",
    record_types: ["SYNTH4"]
  }), "synth");
  assert.deepEqual(params, {
    domain: "direct/",
    domain_type: "hns",
    intent: "synth_setup",
    mode: "synth",
    ns4: "203.0.113.10"
  });
}

{
  const url = handoff.buildUrl(
    {
      domain: "example.com",
      domain_type: "dns",
      mode: "delegated",
      nameserver: "ns1.example.com.",
      a_records: ["192.0.2.44"],
      aaaa_records: ["2001:db8::44"],
      service_port: 443,
      dnskey_records: ["257 3 13 abc"],
      certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
      cert_der: "base64-der"
    },
    {base: "/dane-generator/?source=audit", intent: "review", cert: "sha256-cert"}
  );

  assert.equal(url.startsWith("/dane-generator/?source=audit&"), true);
  assert.deepEqual(queryParams(url), {
    source: "audit",
    domain: "example.com",
    domain_type: "dns",
    intent: "review",
    mode: "delegated",
    nameserver: "ns1.example.com.",
    a: "192.0.2.44",
    aaaa: "2001:db8::44",
    port: "443",
    dnskey: "257 3 13 abc",
    pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
    cert: "sha256-cert"
  });
}

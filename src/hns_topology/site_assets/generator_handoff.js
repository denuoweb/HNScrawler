(function registerGeneratorHandoff(root, factory) {
  const api = factory(root);
  if (typeof module === "object" && module.exports) module.exports = api;
  root.DaneGeneratorHandoff = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function generatorHandoffFactory(root) {
  const DEFAULT_BASE = "/dane-generator/";
  const SUPPORTED_PARAMS = [
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
  ];

  function buildUrl(row = {}, options = {}) {
    const base = textValue(options.base) || textValue(root.__DANE_GENERATOR_BASE__) || DEFAULT_BASE;
    const params = handoffParams(row, options);
    const query = new URLSearchParams();
    for (const key of SUPPORTED_PARAMS) {
      if (params[key] !== undefined && params[key] !== null && String(params[key]).trim() !== "") {
        query.set(key, String(params[key]));
      }
    }
    const separator = base.includes("?") ? "&" : "?";
    return `${base}${separator}${query.toString()}`;
  }

  function handoffParams(row = {}, options = {}) {
    const domainType = firstText(options.domain_type, row.domain_type, "hns");
    const params = {
      domain: normalizeDomain(firstText(options.domain, row.domain, row.name), domainType),
      domain_type: domainType,
      intent: firstText(options.intent, row.intent),
      mode: firstText(options.mode, row.mode, inferMode(row)),
      nameserver: firstText(options.nameserver, row.nameserver, firstValue(row.ns_names), row.first_ns),
      ns4: firstText(
        options.ns4,
        row.ns4,
        firstValue(row.synth4),
        firstValue(row.glue4),
        row.first_synth4,
        row.first_glue4
      ),
      ns6: firstText(
        options.ns6,
        row.ns6,
        firstValue(row.synth6),
        firstValue(row.glue6),
        row.first_synth6,
        row.first_glue6
      ),
      a: firstText(options.a, row.a, firstValue(row.a_records), row.first_a),
      aaaa: firstText(options.aaaa, row.aaaa, firstValue(row.aaaa_records), row.first_aaaa),
      port: firstText(options.port, row.port, row.service_port),
      dnskey: firstText(options.dnskey, row.dnskey, firstValue(row.dnskey_records)),
      pem: firstText(options.pem, row.pem, row.cert_pem, row.certificate_pem),
      cert: firstText(options.cert, row.cert, row.cert_der, row.certificate_der)
    };
    return Object.fromEntries(
      Object.entries(params).filter(([, value]) => value !== undefined && value !== null && String(value).trim() !== "")
    );
  }

  function inferMode(row) {
    return hasSynth(row) && row.onchain_class === "DIRECT_SYNTH" ? "synth" : "delegated";
  }

  function normalizeDomain(domain, domainType) {
    const text = textValue(domain);
    if (!text) return "";
    if (domainType === "hns" && !text.endsWith("/") && !text.includes("://")) return `${text}/`;
    return text;
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

  function hasRecordType(row, type) {
    return Array.isArray(row.record_types) && row.record_types.includes(type);
  }

  function firstText(...values) {
    for (const value of values) {
      const text = textValue(value);
      if (text) return text;
    }
    return "";
  }

  function firstValue(value) {
    if (Array.isArray(value)) {
      for (const item of value) {
        const text = textValue(item);
        if (text) return text;
      }
      return "";
    }
    return textValue(value);
  }

  function textValue(value) {
    if (value === undefined || value === null) return "";
    return String(value).trim();
  }

  return {
    DEFAULT_BASE,
    SUPPORTED_PARAMS,
    buildUrl,
    handoffParams,
    inferMode
  };
});

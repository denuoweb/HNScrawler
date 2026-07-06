# DANE-Compatible Report Site

The report site should eventually be served from an HNS name that validates through the path the report itself measures:

```text
HNS proof
  -> NS/GLUE/DS
  -> authoritative DNSSEC
  -> TLSA
  -> HTTPS certificate or SPKI match
```

## DNS Requirements

1. Publish HNS resource records with nameserver delegation.
2. Include GLUE4/GLUE6 when strict HNS clients need direct bootstrap to the authoritative nameserver.
3. Optionally include `TXT "hnsdns=1;ns=...;doh=https://.../dns-query"` when the delegated nameserver also serves RFC 8484 authoritative DoH.
4. Include DS in the HNS resource for the signed child zone.
5. Sign the authoritative zone with DNSSEC.
6. Publish TLSA at `_443._tcp.<site>` and, if used, `_443._tcp.www.<site>`.
7. Serve HTTPS with the certificate or SPKI that the TLSA record identifies.

## Current Production Shape

The current website VM uses nginx:

- VM: `denuoweb-vm`
- project: `denuo-web-site`
- zone: `us-west1-b`
- server names: `denuoweb`, `www.denuoweb`
- certificate: `/etc/ssl/denuoweb/denuoweb.crt`
- key: `/etc/ssl/denuoweb/denuoweb.key`
- report path: `/var/www/denuoweb/hns-topology`
- report target: `/mnt/hns-topology/site`

The private key stays on the VM. Do not copy it into this repository or into generated public artifacts.

## TLSA Profile

For web DANE, start with `3 1 1` where possible:

- usage `3`: DANE-EE
- selector `1`: subjectPublicKeyInfo
- matching type `1`: SHA-256

This keeps the TLSA record small and binds the service to the presented public key. RFC 6698 defines the TLSA wire fields. RFC 7671 provides operational guidance and symbolic names for DANE usage, selector, and matching type values.

Generate candidate TLSA records from the live VM certificate:

```bash
scripts/gcloud-print-site-tlsa.sh
```

You can also generate or verify records from any local certificate file:

```bash
hns-topology tlsa-from-cert --cert /etc/ssl/denuoweb/denuoweb.crt --site denuoweb
hns-topology verify-tlsa --cert /etc/ssl/denuoweb/denuoweb.crt --record '_443._tcp.denuoweb. 300 IN TLSA 3 1 1 <hex>'
```

The script prints fully qualified records for `_443._tcp.<site>.` and `_443._tcp.www.<site>.` by default. Override these when needed:

```bash
DANE_SITE_NAME=reports.denuoweb DANE_INCLUDE_WWW=0 scripts/gcloud-print-site-tlsa.sh
```

The output is a DNS-zone input. It is not proof that the record is published or DNSSEC-signed.

## Publication Order

1. Configure the authoritative zone for the HNS name.
2. Sign the zone and extract the DS record for the HNS resource.
3. Publish HNS `NS`, `GLUE4`/`GLUE6`, and `DS` records.
4. Publish A/AAAA records for `denuoweb` and `www.denuoweb`, as applicable.
5. Publish TLSA `3 1 1` records generated from the live certificate.
6. Wait at least one TTL window.
7. Verify strict HNS resolution, DNSSEC, TLSA, and HTTPS before describing the report site as DANE-compatible.

## Rotation

When rotating keys:

1. Publish TLSA for the current key and the next key.
2. Wait for old TTLs to age out.
3. Deploy the new HTTPS key/certificate.
4. Verify with Denuo Browser and an independent DANE validator.
5. Remove the old TLSA after another TTL window.

## Verification Checklist

- HNS resource contains expected NS/GLUE/DS.
- Authoritative DNS answers UDP and TCP.
- DNSSEC validates from HNS DS to child DNSKEY.
- TLSA owner name is correct.
- TLSA association matches the live HTTPS certificate/SPKI.
- nginx serves the report from the attached artifact disk path.
- The report site loads in strict HNS mode.

## References

- HSD resource records: https://hsd-dev.org/guides/resource-records.html
- HSD API docs: https://hsd-dev.org/api-docs/
- RFC 6698: https://datatracker.ietf.org/doc/html/rfc6698
- RFC 7671: https://datatracker.ietf.org/doc/html/rfc7671

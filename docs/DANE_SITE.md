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
3. Include DS in the HNS resource for the signed child zone.
4. Sign the authoritative zone with DNSSEC.
5. Publish TLSA at `_443._tcp.<site>` and, if used, `_443._tcp.www.<site>`.
6. Serve HTTPS with the certificate or SPKI that the TLSA record identifies.

## TLSA Profile

For web DANE, start with `3 1 1` where possible:

- usage `3`: DANE-EE
- selector `1`: subjectPublicKeyInfo
- matching type `1`: SHA-256

This keeps the TLSA record small and binds the service to the presented public key. RFC 6698 defines the TLSA wire fields. RFC 7671 provides operational guidance and symbolic names for DANE usage, selector, and matching type values.

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
- The report site loads in strict HNS mode.

## References

- HSD resource records: https://hsd-dev.org/guides/resource-records.html
- HSD API docs: https://hsd-dev.org/api-docs/
- RFC 6698: https://datatracker.ietf.org/doc/html/rfc6698
- RFC 7671: https://datatracker.ietf.org/doc/html/rfc7671


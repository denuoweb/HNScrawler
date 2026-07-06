# Failure Taxonomy

Failure reasons are stable lowercase identifiers. They should not be renamed casually because exported data and external analysis may depend on them.

| Reason | Meaning |
| --- | --- |
| `missing_glue` | The HNS resource delegates to nameservers but lacks usable GLUE4/GLUE6 for strict HNS bootstrap. |
| `nameserver_unreachable_udp` | Authoritative nameserver did not answer UDP DNS within timeout. |
| `nameserver_unreachable_tcp` | Authoritative nameserver did not answer TCP DNS within timeout. |
| `no_a_or_aaaa` | No apex or `www` A/AAAA address was found from the configured resolution path. |
| `dnssec_missing` | Expected DNSSEC data was absent. |
| `dnssec_bogus` | DNSSEC validation failed. |
| `ds_dnskey_mismatch` | Parent DS did not match child DNSKEY. |
| `rrsig_expired` | DNSSEC signature was expired at check time. |
| `tlsa_missing` | No TLSA record was found for the checked HTTPS owner names. |
| `tlsa_wrong_owner` | TLSA data exists under an owner name that does not match the checked endpoint. |
| `stale_tlsa_spki_mismatch` | TLSA association data no longer matches the HTTPS certificate or SPKI. |
| `https_connect_failed` | TCP/TLS connection to HTTPS failed. |
| `certificate_expired` | HTTPS reached the origin, but the presented certificate is past its validity window. |
| `certificate_mismatch` | HTTPS connected but WebPKI certificate validation failed and no matching TLSA record cleared the failure. |
| `doh_fallback_only` | Name appears to work only through a fallback resolver path. |
| `malformed_resource` | HNS resource data could not be decoded into expected records. |
| `unknown_error` | The checker failed in a way that needs a narrower taxonomy entry. |

New failure reasons should be added only when they change user-facing diagnosis or materially improve analysis.

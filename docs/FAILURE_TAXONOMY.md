# Failure Taxonomy

Failure reasons are stable lowercase identifiers. They should not be renamed casually because exported data and external analysis may depend on them.

| Reason | Meaning |
| --- | --- |
| `missing_glue` | The HNS resource delegates to nameservers but lacks usable direct GLUE4/GLUE6 for strict HNS bootstrap. Exported `ns_handoff_*` diagnostics can still show an indirect NS-hostname probe path. |
| `nameserver_unreachable_udp` | Authoritative nameserver did not answer UDP DNS within timeout. |
| `nameserver_unreachable_tcp` | Authoritative nameserver did not answer TCP DNS within timeout. |
| `no_a_or_aaaa` | No A/AAAA address was found for the checked host from the configured resolution path. |
| `dnssec_missing` | Expected DNSSEC data was absent. |
| `dnssec_bogus` | DNSSEC validation failed. |
| `ds_dnskey_mismatch` | Parent DS did not match child DNSKEY. |
| `rrsig_expired` | DNSSEC signature was expired at check time. |
| `tlsa_missing` | No TLSA record was found at `_443._tcp.<host>` for the checked HTTPS host. |
| `tlsa_wrong_owner` | TLSA data exists under an owner name that does not match the checked host endpoint. |
| `stale_tlsa_spki_mismatch` | TLSA association data no longer matches the HTTPS certificate or SPKI. |
| `https_connect_failed` | TCP/TLS connection to HTTPS failed. |
| `certificate_expired` | HTTPS reached the origin, but the presented certificate is past its validity window. |
| `certificate_mismatch` | HTTPS connected but WebPKI certificate validation failed and no matching TLSA record cleared the failure. |
| `doh_fallback_only` | Name appears to work only through a fallback resolver path. |
| `malformed_resource` | HNS resource data could not be decoded into expected records. |
| `unknown_error` | The checker failed in a way that needs a narrower taxonomy entry. |

A root-level failure reason does not prove that no live host exists below the root. For example, `crewball` apex can have `no_a_or_aaaa` while `jaron.crewball` is still a live host. New failure reasons should be added only when they change user-facing diagnosis or materially improve analysis.

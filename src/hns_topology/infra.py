from __future__ import annotations

NON_ACTIONABLE_PROVIDER_TYPES = ("default_parking", "public_resolver")

BULK_DEFAULT_RESOURCE_IPS: dict[str, dict[str, str]] = {
    "44.231.6.183": {
        "role": "bulk_default_glue",
        "label": "Namebase/default glue cluster",
        "source": "WWW 2024 BNS collision study Table 8",
    },
    "54.214.136.246": {
        "role": "bulk_default_glue",
        "label": "Namebase/default glue cluster",
        "source": "WWW 2024 BNS collision study Table 8",
    },
    "34.123.215.203": {
        "role": "bulk_default_glue",
        "label": "High-frequency shared glue cluster",
        "source": "WWW 2024 BNS collision study Table 8",
    },
    "45.79.95.228": {
        "role": "bulk_default_glue",
        "label": "High-frequency shared glue cluster",
        "source": "WWW 2024 BNS collision study Table 8",
    },
    "45.79.214.114": {
        "role": "bulk_default_glue",
        "label": "High-frequency shared glue cluster",
        "source": "WWW 2024 BNS collision study Table 8",
    },
}

KNOWN_HNS_RESOLVERS: tuple[dict[str, str | bool], ...] = (
    {
        "ip": "194.50.5.27",
        "provider": "Nathan.Woodburn/",
        "transport": "plain_dns",
        "hnsdoh_software": True,
        "source": "https://welcome.hnsdoh.com/",
    },
    {
        "ip": "139.177.195.185",
        "provider": "HNS Canada",
        "transport": "plain_dns",
        "hnsdoh_software": True,
        "source": "https://welcome.hnsdoh.com/",
    },
    {
        "ip": "172.233.46.92",
        "provider": "Nathan.Woodburn/",
        "transport": "plain_dns",
        "hnsdoh_software": True,
        "source": "https://welcome.hnsdoh.com/",
    },
    {
        "ip": "172.105.120.203",
        "provider": "Nathan.Woodburn/",
        "transport": "plain_dns",
        "hnsdoh_software": True,
        "source": "https://welcome.hnsdoh.com/",
    },
    {
        "ip": "51.24.7.1",
        "provider": "Easy HNS",
        "transport": "plain_dns",
        "hnsdoh_software": True,
        "source": "https://welcome.hnsdoh.com/",
    },
    {
        "ip": "194.50.5.26",
        "provider": "Nathan.Woodburn/",
        "transport": "plain_dns",
        "hnsdoh_software": False,
        "source": "https://welcome.hnsdoh.com/",
    },
    {
        "ip": "194.50.5.28",
        "provider": "Nathan.Woodburn/",
        "transport": "plain_dns",
        "hnsdoh_software": False,
        "source": "https://welcome.hnsdoh.com/",
    },
    {
        "ip": "139.144.68.241",
        "provider": "HNS DNS",
        "transport": "plain_dns",
        "hnsdoh_software": False,
        "source": "https://welcome.hnsdoh.com/",
    },
    {
        "ip": "139.144.68.242",
        "provider": "HNS DNS",
        "transport": "plain_dns",
        "hnsdoh_software": False,
        "source": "https://welcome.hnsdoh.com/",
    },
    {
        "ip": "2a01:7e01:e002:c300::",
        "provider": "HNS DNS",
        "transport": "plain_dns",
        "hnsdoh_software": False,
        "source": "https://welcome.hnsdoh.com/",
    },
    {
        "ip": "2a01:7e01:e002:c500::",
        "provider": "HNS DNS",
        "transport": "plain_dns",
        "hnsdoh_software": False,
        "source": "https://welcome.hnsdoh.com/",
    },
)

KNOWN_HNS_RESOLVER_IPS = {str(item["ip"]) for item in KNOWN_HNS_RESOLVERS}


def resource_ip_role(ip: str) -> dict[str, str]:
    normalized = str(ip).strip().lower()
    if normalized in BULK_DEFAULT_RESOURCE_IPS:
        return BULK_DEFAULT_RESOURCE_IPS[normalized]
    if normalized in KNOWN_HNS_RESOLVER_IPS:
        return {
            "role": "public_hns_resolver",
            "label": "Known public HNS recursive resolver",
            "source": "https://welcome.hnsdoh.com/",
        }
    return {"role": "unknown", "label": "", "source": ""}

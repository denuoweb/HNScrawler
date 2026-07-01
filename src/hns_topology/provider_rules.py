from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .classifier import normalize_name, normalize_ns
from .models import ResourceSummary


@dataclass(frozen=True)
class ProviderRule:
    provider_key: str
    provider_type: str
    priority: int
    ns_suffixes: tuple[str, ...] = ()
    ns_regexes: tuple[str, ...] = ()
    ip_prefixes: tuple[str, ...] = ()
    self_hosted: bool = False
    compiled_ns_regexes: tuple[re.Pattern[str], ...] = field(
        init=False, repr=False, compare=False
    )
    ip_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "compiled_ns_regexes",
            tuple(re.compile(pattern) for pattern in self.ns_regexes),
        )
        object.__setattr__(
            self,
            "ip_networks",
            tuple(ipaddress.ip_network(prefix) for prefix in self.ip_prefixes),
        )

    @property
    def ns_pattern(self) -> str:
        parts: list[str] = []
        if self.self_hosted:
            parts.append("self_hosted")
        parts.extend(f"suffix:{suffix}" for suffix in self.ns_suffixes)
        parts.extend(f"regex:{pattern}" for pattern in self.ns_regexes)
        return ",".join(parts)

    @property
    def ip_pattern(self) -> str:
        return ",".join(f"cidr:{prefix}" for prefix in self.ip_prefixes)


class ProviderRules:
    def __init__(
        self,
        rules: list[ProviderRule],
        default_provider_key: str = "unknown/custom",
        *,
        version: int = 0,
        source_path: str = "",
        content_hash: str = "",
    ):
        self.rules = sorted(rules, key=lambda rule: rule.priority)
        self.default_provider_key = default_provider_key
        self.version = version
        self.source_path = source_path
        self.content_hash = content_hash
        self.provider_types = {
            rule.provider_key: rule.provider_type for rule in self.rules
        } | {default_provider_key: "unknown"}
        self.provider_patterns = {
            rule.provider_key: {
                "ns_pattern": rule.ns_pattern,
                "ip_pattern": rule.ip_pattern,
            }
            for rule in self.rules
        } | {default_provider_key: {"ns_pattern": "", "ip_pattern": ""}}

    @classmethod
    def from_file(cls, path: str | Path) -> ProviderRules:
        source_path = Path(path)
        text = source_path.read_text(encoding="utf-8")
        data = json.loads(text)
        rules = [
            ProviderRule(
                provider_key=item["provider_key"],
                provider_type=item.get("provider_type", "unknown"),
                priority=int(item.get("priority", 1000)),
                ns_suffixes=tuple(normalize_ns(ns) for ns in item.get("ns_suffixes", [])),
                ns_regexes=tuple(item.get("ns_regexes", [])),
                ip_prefixes=tuple(item.get("ip_prefixes", [])),
                self_hosted=bool(item.get("self_hosted", False)),
            )
            for item in data.get("rules", [])
        ]
        return cls(
            rules,
            data.get("default_provider_key", "unknown/custom"),
            version=int(data.get("version", 0)),
            source_path=str(source_path),
            content_hash=hashlib.sha256(text.encode()).hexdigest(),
        )

    @classmethod
    def empty(cls) -> ProviderRules:
        return cls([])

    def provenance(self) -> dict[str, str | int]:
        return {
            "provider_rules_version": self.version,
            "provider_rules_path": self.source_path,
            "provider_rules_hash": self.content_hash,
        }

    def match(self, name: str, summary: ResourceSummary) -> str:
        normalized_name = normalize_name(name)
        for rule in self.rules:
            if rule.self_hosted and _is_self_hosted(normalized_name, summary.ns_names):
                return rule.provider_key
            if rule.ns_suffixes and _matches_ns_suffix(summary.ns_names, rule.ns_suffixes):
                return rule.provider_key
            if rule.compiled_ns_regexes and _matches_ns_regex(
                summary.ns_names, rule.compiled_ns_regexes
            ):
                return rule.provider_key
            if rule.ip_networks and _matches_ip(summary, rule.ip_networks):
                return rule.provider_key
        return self.default_provider_key


def _is_self_hosted(name: str, ns_names: list[str]) -> bool:
    suffix = "." + name
    return any(ns == name or ns.endswith(suffix) for ns in ns_names)


def _matches_ns_suffix(ns_names: list[str], suffixes: tuple[str, ...]) -> bool:
    for ns in ns_names:
        for suffix in suffixes:
            if ns == suffix or ns.endswith("." + suffix):
                return True
    return False


def _matches_ns_regex(ns_names: list[str], regexes: tuple[re.Pattern[str], ...]) -> bool:
    return any(pattern.search(ns) for pattern in regexes for ns in ns_names)


def _matches_ip(
    summary: ResourceSummary,
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    for value in [*summary.glue4, *summary.glue6, *summary.synth4, *summary.synth6]:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if any(address in network for network in networks):
            return True
    return False

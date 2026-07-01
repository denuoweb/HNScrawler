from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
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


class ProviderRules:
    def __init__(self, rules: list[ProviderRule], default_provider_key: str = "unknown/custom"):
        self.rules = sorted(rules, key=lambda rule: rule.priority)
        self.default_provider_key = default_provider_key
        self.provider_types = {
            rule.provider_key: rule.provider_type for rule in self.rules
        } | {default_provider_key: "unknown"}

    @classmethod
    def from_file(cls, path: str | Path) -> ProviderRules:
        with Path(path).open("r", encoding="utf-8") as handle:
            data = json.load(handle)
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
        return cls(rules, data.get("default_provider_key", "unknown/custom"))

    @classmethod
    def empty(cls) -> ProviderRules:
        return cls([])

    def match(self, name: str, summary: ResourceSummary) -> str:
        normalized_name = normalize_name(name)
        for rule in self.rules:
            if rule.self_hosted and _is_self_hosted(normalized_name, summary.ns_names):
                return rule.provider_key
            if rule.ns_suffixes and _matches_ns_suffix(summary.ns_names, rule.ns_suffixes):
                return rule.provider_key
            if rule.ns_regexes and _matches_ns_regex(summary.ns_names, rule.ns_regexes):
                return rule.provider_key
            if rule.ip_prefixes and _matches_ip(summary, rule.ip_prefixes):
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


def _matches_ns_regex(ns_names: list[str], regexes: tuple[str, ...]) -> bool:
    return any(re.search(pattern, ns) for pattern in regexes for ns in ns_names)


def _matches_ip(summary: ResourceSummary, prefixes: tuple[str, ...]) -> bool:
    networks = [ipaddress.ip_network(prefix) for prefix in prefixes]
    for value in [*summary.glue4, *summary.glue6, *summary.synth4, *summary.synth6]:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if any(address in network for network in networks):
            return True
    return False


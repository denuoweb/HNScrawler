from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def build_verification_plan(row: Mapping[str, Any]) -> dict[str, Any] | None:
    name = _name(row)
    if not name or _truthy(row.get("expired")):
        return None
    server, server_field = _direct_server(row)
    if server:
        return _direct_plan(name, server, server_field, row)
    if row.get("ns_handoff_bootstrap_ip") and row.get("ns_handoff_ns"):
        return _indirect_handoff_plan(name, row)
    return None


def verification_csv_rows(rows: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in rows:
        plan = build_verification_plan(row)
        if plan is None:
            continue
        for index, command in enumerate(plan["commands"], start=1):
            output.append(
                {
                    "name": plan["name"],
                    "mode": plan["mode"],
                    "sequence": index,
                    "purpose": command["purpose"],
                    "label": command["label"],
                    "qname": command["qname"],
                    "rrtype": command["rrtype"],
                    "transport": command["transport"],
                    "command": command["command"],
                    "server": command.get("server") or "",
                    "server_field": plan.get("server_field") or "",
                    "nameserver": plan.get("nameserver") or "",
                    "requires": command.get("requires") or "",
                    "note": command.get("note") or plan.get("note") or "",
                }
            )
    return output


def _indirect_handoff_plan(name: str, row: Mapping[str, Any]) -> dict[str, Any]:
    bootstrap = str(row["ns_handoff_bootstrap_ip"]).strip()
    ns_host = _fqdn(str(row["ns_handoff_ns"]))
    root = str(row.get("ns_handoff_root") or "").strip()
    return {
        "name": name,
        "mode": "indirect_ns_handoff",
        "server": bootstrap,
        "server_field": row.get("ns_handoff_bootstrap_field") or "",
        "nameserver": ns_host,
        "ns_handoff_root": root,
        "note": "Resolve the nameserver hostname through its HNS root first, then replace <resolved-ns-ip> with that address for target-zone probes. This is diagnostic evidence, not direct parent-side GLUE.",
        "commands": (
            _nameserver_resolution_commands(bootstrap, ns_host)
            + _transport_discovery_commands(bootstrap, ns_host)
            + _target_probe_commands(name, "<resolved-ns-ip>", requires="resolved nameserver A/AAAA address")
        ),
    }


def _direct_plan(name: str, server: str, server_field: str, row: Mapping[str, Any] | None = None) -> dict[str, Any]:
    row = row or {}
    ns_host = _direct_nameserver(row)
    return {
        "name": name,
        "mode": "direct_bootstrap",
        "server": server,
        "server_field": server_field,
        "nameserver": ns_host,
        "note": "Query the HNS-proven bootstrap address directly. Network-level port 53 blocking can still prevent these commands from completing from some client networks.",
        "commands": _transport_discovery_commands(server, ns_host) + _target_probe_commands(name, server),
    }


def _nameserver_resolution_commands(server: str, ns_host: str) -> list[dict[str, Any]]:
    return [
        _dig_command(
            server,
            ns_host,
            rrtype,
            label=f"Resolve delegated nameserver {rrtype}",
            purpose="nameserver_resolution",
            transport=transport,
        )
        for rrtype in ("A", "AAAA")
        for transport in ("udp53", "tcp53")
    ]


def _transport_discovery_commands(server: str, ns_host: str) -> list[dict[str, Any]]:
    if not ns_host:
        return []
    qname = f"_dns.{ns_host}"
    return [
        _dig_command(
            server,
            qname,
            "SVCB",
            label="Authoritative DoH SVCB discovery",
            purpose="transport_discovery",
            transport=transport,
            note="RFC 9461 _dns SVCB can advertise an RFC 8484 authoritative DoH endpoint for networks where port 53 fails.",
        )
        for transport in ("udp53", "tcp53")
    ]


def _target_probe_commands(name: str, server: str, *, requires: str = "") -> list[dict[str, Any]]:
    probes = (
        (f"{name}.", "A", "Origin A address"),
        (f"{name}.", "AAAA", "Origin AAAA address"),
        (f"_443._tcp.{name}.", "TLSA", "HTTPS TLSA"),
        (f"_443._tcp.www.{name}.", "TLSA", "HTTPS www TLSA"),
        (f"{name}.", "DNSKEY", "DNSKEY"),
    )
    return [
        _dig_command(
            server,
            qname,
            rrtype,
            label=f"{label} probe",
            purpose="target_zone_probe",
            transport=transport,
            requires=requires,
        )
        for qname, rrtype, label in probes
        for transport in ("udp53", "tcp53")
    ]


def _dig_command(
    server: str,
    qname: str,
    rrtype: str,
    *,
    label: str,
    purpose: str,
    transport: str,
    requires: str = "",
    note: str = "",
) -> dict[str, Any]:
    tcp_flag = " +tcp" if transport == "tcp53" else ""
    transport_label = "TCP 53" if transport == "tcp53" else "UDP 53"
    return {
        "label": f"{label} ({transport_label})",
        "purpose": purpose,
        "qname": qname,
        "rrtype": rrtype,
        "transport": transport,
        "command": f"dig @{server} {qname} {rrtype}{tcp_flag} +norecurse +dnssec",
        "server": server,
        "requires": requires,
        "note": note,
    }


def _direct_server(row: Mapping[str, Any]) -> tuple[str, str]:
    for key, field in (
        ("synth4", "SYNTH4"),
        ("first_synth4", "SYNTH4"),
        ("glue4", "GLUE4"),
        ("first_glue4", "GLUE4"),
        ("synth6", "SYNTH6"),
        ("first_synth6", "SYNTH6"),
        ("glue6", "GLUE6"),
        ("first_glue6", "GLUE6"),
    ):
        value = _first_text(row.get(key))
        if value:
            return value, field
    return "", ""


def _direct_nameserver(row: Mapping[str, Any]) -> str:
    ns = _first_text(row.get("ns_names")) or _first_text(row.get("first_ns"))
    return _fqdn(ns) if ns else ""


def _name(row: Mapping[str, Any]) -> str:
    return str(row.get("name") or "").strip().lower().rstrip(".")


def _fqdn(value: str) -> str:
    text = value.strip().lower().rstrip(".")
    return f"{text}." if text else ""


def _first_text(value: Any) -> str:
    if isinstance(value, list):
        for item in value:
            text = str(item or "").strip()
            if text:
                return text
        return ""
    return str(value or "").strip()


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return bool(value)

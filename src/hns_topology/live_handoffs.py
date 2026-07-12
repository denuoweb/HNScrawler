from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from .jsonutil import dumps_json
from .live_db import HNS_HANDOFF_NOT_BEFORE_META_KEY, get_live_meta, set_live_meta
from .ns_handoff import HANDOFF_COHORT_MAX_MEMBERS, HANDOFF_COHORT_MIN_MEMBERS
from .timeutil import utc_now

HANDOFF_GROUP_INDEX_META_KEY = "hns_handoff_groups.source_signature"
HANDOFF_GROUP_FORMAT = "hns-handoff-cohorts-v1"


def refresh_hns_handoff_groups(
    conn: sqlite3.Connection,
    *,
    topology_site: str | Path,
    min_members: int = HANDOFF_COHORT_MIN_MEMBERS,
    max_members: int = HANDOFF_COHORT_MAX_MEMBERS,
) -> dict[str, Any]:
    """Import bounded HNS-delegation cohorts exported by the indexer."""

    source = Path(topology_site) / "data" / "hns-handoff-groups.json"
    if not source.is_file():
        raise FileNotFoundError(f"HNS handoff cohort export does not exist: {source}")
    signature = _source_signature(source)
    if get_live_meta(conn, HANDOFF_GROUP_INDEX_META_KEY) == signature:
        count = int(conn.execute("SELECT COUNT(*) FROM hns_handoff_groups").fetchone()[0])
        return {"indexed": False, "groups": count, "source_signature": signature}

    payload = _json_object(source.read_text(encoding="utf-8"))
    if payload.get("format") != HANDOFF_GROUP_FORMAT:
        raise ValueError(f"unexpected HNS handoff cohort format in {source}")

    minimum = max(1, min_members)
    maximum = max(minimum, max_members)
    groups: list[tuple[str, str, str, str, int, int, str, str, str]] = []
    for group in _json_list(payload.get("groups")):
        item = _import_group(
            group,
            signature=signature,
            minimum=minimum,
            maximum=maximum,
            priority=False,
        )
        if item is not None:
            groups.append(item)
    for group in _json_list(payload.get("ds_priority_groups")):
        item = _import_group(
            group,
            signature=signature,
            minimum=1,
            maximum=None,
            priority=True,
        )
        if item is not None:
            groups.append(item)

    with conn:
        conn.execute("DELETE FROM hns_handoff_groups")
        conn.executemany(
            """
            INSERT INTO hns_handoff_groups(
              nameserver, root_name, bootstrap_ip, bootstrap_field, priority, member_count,
              members_json, source_signature, indexed_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            groups,
        )
        set_live_meta(conn, HANDOFF_GROUP_INDEX_META_KEY, signature)
        # A new artifact can introduce a route that was absent during the
        # previous empty pass, so do not leave it behind the weekly tier gate.
        set_live_meta(conn, HNS_HANDOFF_NOT_BEFORE_META_KEY, "")
    return {
        "indexed": True,
        "groups": len(groups),
        "ds_priority_groups": sum(1 for group in groups if group[4]),
        "source_signature": signature,
    }


def _import_group(
    group: dict[str, Any],
    *,
    signature: str,
    minimum: int,
    maximum: int | None,
    priority: bool,
) -> tuple[str, str, str, str, int, int, str, str, str] | None:
    nameserver = _name(group.get("nameserver"))
    root_name = _name(group.get("root_name"))
    bootstrap_field = str(group.get("bootstrap_field") or "").strip().lower()
    addresses = _names(group.get("bootstrap_addresses"))
    bootstrap_ip = addresses[0] if len(addresses) == 1 else ""
    members = _members(group.get("members"))
    member_count = _integer(group.get("member_count"))
    if (
        not nameserver
        or not root_name
        or not bootstrap_ip
        or not bootstrap_field
        or member_count < minimum
        or (maximum is not None and member_count > maximum)
        or len(members) != member_count
    ):
        return None
    if priority and any(not bool(member["has_ds"]) for member in members):
        return None
    return (
        nameserver,
        root_name,
        bootstrap_ip,
        bootstrap_field,
        int(priority),
        member_count,
        dumps_json(members),
        signature,
        utc_now(),
    )


def hns_handoff_group_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT nameserver, root_name, bootstrap_ip, bootstrap_field, priority, member_count, members_json
        FROM hns_handoff_groups
        ORDER BY
          priority DESC,
          CASE WHEN member_count BETWEEN 2 AND 100 THEN 0 ELSE 1 END,
          member_count DESC,
          nameserver,
          root_name,
          bootstrap_ip,
          bootstrap_field
        """
    )
    return [
        {
            "nameserver": str(row["nameserver"]),
            "root_name": str(row["root_name"]),
            "bootstrap_ip": str(row["bootstrap_ip"]),
            "bootstrap_field": str(row["bootstrap_field"]),
            "priority": bool(row["priority"]),
            "member_count": int(row["member_count"]),
            "members": _members(row["members_json"]),
        }
        for row in rows
    ]


def _source_signature(source: Path) -> str:
    stat = source.stat()
    digest = hashlib.sha256()
    digest.update(source.name.encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(stat.st_size).encode("ascii"))
    digest.update(b"\0")
    digest.update(str(stat.st_mtime_ns).encode("ascii"))
    return digest.hexdigest()


def _json_object(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _json_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({_name(item) for item in value if _name(item)})


def _members(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    members = _json_list(value)
    normalized: list[dict[str, Any]] = []
    for member in members:
        name = _name(member.get("name"))
        if not name:
            continue
        normalized.append(
            {
                "name": name,
                "provider_guess": str(member.get("provider_guess") or "unknown/custom"),
                "provider_type": str(member.get("provider_type") or "unknown"),
                "resource_hash": str(member.get("resource_hash") or ""),
                "last_seen_height": _integer_or_none(member.get("last_seen_height")),
                "ns_names": _names(member.get("ns_names")),
                "ds_records": [
                    item for item in _json_list(member.get("ds_records")) if isinstance(item, dict)
                ],
                "has_ds": bool(member.get("has_ds")),
            }
        )
    return sorted(normalized, key=lambda item: str(item["name"]))


def _name(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _integer(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _integer_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None

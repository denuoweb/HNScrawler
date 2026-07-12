from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from .jsonutil import dumps_json
from .live_db import get_live_meta, set_live_meta
from .timeutil import utc_now

DELEGATION_INDEX_META_KEY = "delegation_groups.source_signature"
DEFAULT_MIN_MEMBERS = 5
DEFAULT_MAX_MEMBERS = 250


def refresh_delegation_groups(
    conn: sqlite3.Connection,
    *,
    topology_site: str | Path,
    min_members: int = DEFAULT_MIN_MEMBERS,
    max_members: int = DEFAULT_MAX_MEMBERS,
) -> dict[str, Any]:
    shard_dir = Path(topology_site) / "data" / "nameservers" / "shards"
    shards = sorted(shard_dir.glob("*.jsonl"))
    if not shards:
        raise FileNotFoundError(f"nameserver shards do not exist: {shard_dir}")
    signature = _source_signature(shards)
    if get_live_meta(conn, DELEGATION_INDEX_META_KEY) == signature:
        count = int(conn.execute("SELECT COUNT(*) FROM delegation_groups").fetchone()[0])
        return {"indexed": False, "groups": count, "source_signature": signature}

    groups: list[tuple[str, int, str, str, str]] = []
    for shard in shards:
        with shard.open(encoding="utf-8") as handle:
            for line in handle:
                item = _json_object(line)
                nameserver = str(item.get("n") or "").strip().lower().rstrip(".")
                member_count = _integer(item.get("c"))
                roots = _member_roots(item.get("r"))
                if (
                    not nameserver
                    or member_count < max(1, min_members)
                    or member_count > max(max(1, min_members), max_members)
                    or len(roots) != member_count
                ):
                    continue
                groups.append((nameserver, member_count, dumps_json(roots), signature, utc_now()))

    with conn:
        conn.execute("DELETE FROM delegation_groups")
        conn.executemany(
            """
            INSERT INTO delegation_groups(
              nameserver, member_count, member_roots_json, source_signature, indexed_at
            ) VALUES(?, ?, ?, ?, ?)
            """,
            groups,
        )
        set_live_meta(conn, DELEGATION_INDEX_META_KEY, signature)
    return {"indexed": True, "groups": len(groups), "source_signature": signature}


def delegation_group_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT nameserver, member_count, member_roots_json
        FROM delegation_groups
        ORDER BY
          CASE WHEN member_count BETWEEN 5 AND 100 THEN 0 ELSE 1 END,
          member_count DESC,
          nameserver
        """
    )
    return [
        {
            "nameserver": str(row["nameserver"]),
            "member_count": int(row["member_count"]),
            "member_roots": _member_roots(row["member_roots_json"]),
        }
        for row in rows
    ]


def _source_signature(shards: list[Path]) -> str:
    digest = hashlib.sha256()
    for shard in shards:
        stat = shard.stat()
        digest.update(shard.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(stat.st_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(stat.st_mtime_ns).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _json_object(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _member_roots(value: Any) -> list[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    if not isinstance(value, list):
        return []
    return sorted({str(item).strip().lower().rstrip(".") for item in value if str(item).strip()})


def _integer(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

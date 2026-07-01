from __future__ import annotations

import gzip
import json
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .db import connect, get_meta, table_count
from .exporter import build_summary
from .models import FAILURE_REASONS

REQUIRED_TABLES = {
    "snapshot_meta",
    "names",
    "resource_summary",
    "live_status",
    "provider_summary",
    "block_history",
    "changed_name_rollbacks",
}

REQUIRED_META_KEYS = (
    "generated_at",
    "last_indexed_height",
    "last_indexed_tip_hash",
    "hsd_chain",
    "hsd_version",
    "crawler_version",
    "source_type",
    "provider_rules_version",
    "provider_rules_hash",
    "provider_rules_path",
)

REQUIRED_PUBLIC_FILES = (
    "index.html",
    "faq.html",
    "providers.html",
    "classes.html",
    "names.html",
    "broken.html",
    "dane.html",
    "styles.css",
    "app.js",
    "data/summary.json",
    "data/providers.json",
    "data/classes.json",
    "data/faq_answers.json",
    "data/names.json",
    "data/names.csv",
    "data/broken.json",
    "data/dane.json",
    "data/topology.sqlite.gz",
)

PUBLIC_JSON_FILES = tuple(path for path in REQUIRED_PUBLIC_FILES if path.endswith(".json"))
FORBIDDEN_PUBLIC_SUFFIXES = (".key", ".pem")


@dataclass(frozen=True)
class ReleaseCheck:
    name: str
    ok: bool
    detail: str


def validate_release(
    *,
    db_path: str | Path,
    public_dir: str | Path | None = None,
    require_live_checks: bool = False,
) -> list[ReleaseCheck]:
    checks: list[ReleaseCheck] = []
    db = Path(db_path)
    if not db.exists():
        return [ReleaseCheck("database_exists", False, f"{db} does not exist")]

    try:
        with connect(db) as conn:
            _validate_database(conn, checks, require_live_checks=require_live_checks)
            summary = build_summary(conn)
    except Exception as exc:
        return [ReleaseCheck("database_open", False, f"{type(exc).__name__}: {exc}")]

    if public_dir is not None:
        _validate_public_artifacts(Path(public_dir), summary, checks)
    return checks


def validate_public_release(
    *,
    public_dir: str | Path,
    require_live_checks: bool = False,
) -> list[ReleaseCheck]:
    checks: list[ReleaseCheck] = []
    public = Path(public_dir)
    checks.append(ReleaseCheck("public_dir_exists", public.is_dir(), str(public)))
    if not public.is_dir():
        return checks

    gz_path = public / "data/topology.sqlite.gz"
    checks.append(
        ReleaseCheck(
            "public_topology_sqlite_gz_present",
            gz_path.is_file(),
            str(gz_path),
        )
    )
    if not gz_path.is_file():
        _validate_public_artifacts(public, {}, checks, include_public_dir_check=False)
        return checks

    with tempfile.NamedTemporaryFile(prefix="hns-topology-public-", suffix=".sqlite") as handle:
        try:
            with gzip.open(gz_path, "rb") as src:
                shutil.copyfileobj(src, handle)
            handle.flush()
            with connect(handle.name) as conn:
                _validate_database(conn, checks, require_live_checks=require_live_checks)
                summary = build_summary(conn)
        except Exception as exc:
            checks.append(
                ReleaseCheck(
                    "public_topology_sqlite_gz_open",
                    False,
                    f"{type(exc).__name__}: {exc}",
                )
            )
            summary = {}

    _validate_public_artifacts(public, summary, checks, include_public_dir_check=False)
    return checks


def release_is_valid(checks: list[ReleaseCheck]) -> bool:
    return all(check.ok for check in checks)


def _validate_database(
    conn: sqlite3.Connection,
    checks: list[ReleaseCheck],
    *,
    require_live_checks: bool,
) -> None:
    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    checks.append(ReleaseCheck("sqlite_integrity", integrity == "ok", str(integrity)))

    tables = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    }
    missing_tables = sorted(REQUIRED_TABLES - tables)
    checks.append(
        ReleaseCheck(
            "required_tables",
            not missing_tables,
            "present" if not missing_tables else ", ".join(missing_tables),
        )
    )
    if missing_tables:
        return

    total = table_count(conn, "SELECT COUNT(*) FROM names")
    active = table_count(conn, "SELECT COUNT(*) FROM names WHERE expired = 0")
    expired = table_count(conn, "SELECT COUNT(*) FROM names WHERE expired = 1")
    checks.append(ReleaseCheck("nonempty_names", total > 0, f"{total} names"))
    checks.append(
        ReleaseCheck(
            "active_expired_total",
            active + expired == total,
            f"active={active} expired={expired} total={total}",
        )
    )

    missing_resources = table_count(
        conn,
        """
        SELECT COUNT(*)
        FROM names n
        LEFT JOIN resource_summary rs ON rs.name = n.name
        WHERE rs.name IS NULL
        """,
    )
    checks.append(
        ReleaseCheck(
            "resource_rows_cover_names",
            missing_resources == 0,
            f"{missing_resources} names without resource_summary",
        )
    )

    provider_rows = table_count(conn, "SELECT COUNT(*) FROM provider_summary")
    checks.append(ReleaseCheck("provider_summary_present", provider_rows > 0, f"{provider_rows} rows"))

    invalid_failures = table_count(
        conn,
        f"""
        SELECT COUNT(*)
        FROM live_status
        WHERE failure_reason IS NOT NULL
          AND failure_reason NOT IN ({",".join("?" for _ in FAILURE_REASONS)})
        """,
        tuple(FAILURE_REASONS),
    )
    checks.append(
        ReleaseCheck(
            "failure_taxonomy",
            invalid_failures == 0,
            f"{invalid_failures} invalid failure_reason rows",
        )
    )

    _validate_metadata(conn, checks)

    if require_live_checks:
        live_rows = table_count(conn, "SELECT COUNT(*) FROM live_status")
        live_started = bool(get_meta(conn, "live_check_started_at", ""))
        live_finished = bool(get_meta(conn, "live_check_finished_at", ""))
        checks.append(ReleaseCheck("live_status_present", live_rows > 0, f"{live_rows} rows"))
        checks.append(
            ReleaseCheck(
                "live_check_timestamps",
                live_started and live_finished,
                f"started={live_started} finished={live_finished}",
            )
        )


def _validate_metadata(conn: sqlite3.Connection, checks: list[ReleaseCheck]) -> None:
    missing = [key for key in REQUIRED_META_KEYS if not get_meta(conn, key, "")]
    checks.append(
        ReleaseCheck(
            "required_snapshot_meta",
            not missing,
            "present" if not missing else ", ".join(missing),
        )
    )

    source_type = get_meta(conn, "source_type", "")
    if source_type in {"fixture", "jsonl"}:
        source_ok = bool(get_meta(conn, "source_file_hash", ""))
        source_detail = "source_file_hash present" if source_ok else "missing source_file_hash"
    elif source_type == "hsd_rpc":
        source_ok = bool(get_meta(conn, "source_rpc_url", ""))
        source_detail = "source_rpc_url present" if source_ok else "missing source_rpc_url"
    else:
        source_ok = False
        source_detail = f"unknown source_type={source_type!r}"
    checks.append(ReleaseCheck("source_provenance", source_ok, source_detail))

    height = get_meta(conn, "last_indexed_height", "")
    rules_version = get_meta(conn, "provider_rules_version", "")
    checks.append(ReleaseCheck("height_is_integer", _is_nonnegative_int(height), str(height)))
    checks.append(
        ReleaseCheck(
            "provider_rules_version_is_integer",
            _is_nonnegative_int(rules_version),
            str(rules_version),
        )
    )


def _validate_public_artifacts(
    public_dir: Path,
    summary: dict[str, Any],
    checks: list[ReleaseCheck],
    *,
    include_public_dir_check: bool = True,
) -> None:
    if include_public_dir_check:
        checks.append(
            ReleaseCheck(
                "public_dir_exists",
                public_dir.is_dir(),
                str(public_dir),
            )
        )
    if not public_dir.is_dir():
        return

    missing = [relative for relative in REQUIRED_PUBLIC_FILES if not (public_dir / relative).is_file()]
    checks.append(
        ReleaseCheck(
            "required_public_files",
            not missing,
            "present" if not missing else ", ".join(missing),
        )
    )

    for relative in PUBLIC_JSON_FILES:
        path = public_dir / relative
        if path.exists():
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                checks.append(ReleaseCheck(f"json:{relative}", False, f"{type(exc).__name__}: {exc}"))
            else:
                checks.append(ReleaseCheck(f"json:{relative}", True, "valid JSON"))

    summary_path = public_dir / "data/summary.json"
    if summary_path.exists() and summary:
        exported = json.loads(summary_path.read_text(encoding="utf-8"))
        mismatches = [
            key
            for key in ("total_names", "active_names", "expired_names", "last_indexed_height")
            if exported.get(key) != summary.get(key)
        ]
        checks.append(
            ReleaseCheck(
                "summary_matches_database",
                not mismatches,
                "matched" if not mismatches else ", ".join(mismatches),
            )
        )

    gz_path = public_dir / "data/topology.sqlite.gz"
    if gz_path.exists() and summary:
        checks.append(_validate_gzipped_sqlite(gz_path, expected_names=int(summary["total_names"])))

    forbidden = [
        str(path.relative_to(public_dir))
        for path in public_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in FORBIDDEN_PUBLIC_SUFFIXES
    ]
    checks.append(
        ReleaseCheck(
            "no_private_key_artifacts",
            not forbidden,
            "none" if not forbidden else ", ".join(forbidden[:10]),
        )
    )


def _validate_gzipped_sqlite(gz_path: Path, *, expected_names: int) -> ReleaseCheck:
    with tempfile.NamedTemporaryFile(prefix="hns-topology-validate-", suffix=".sqlite") as handle:
        try:
            with gzip.open(gz_path, "rb") as src:
                shutil.copyfileobj(src, handle)
            handle.flush()
            with sqlite3.connect(handle.name) as conn:
                quick_check = conn.execute("PRAGMA quick_check").fetchone()[0]
                names = conn.execute("SELECT COUNT(*) FROM names").fetchone()[0]
            exported_size = Path(handle.name).stat().st_size
        except Exception as exc:
            return ReleaseCheck("topology_sqlite_gz", False, f"{type(exc).__name__}: {exc}")
    ok = quick_check == "ok" and names == expected_names
    return ReleaseCheck(
        "topology_sqlite_gz",
        ok,
        f"quick_check={quick_check} names={names}/{expected_names} bytes={exported_size}",
    )


def _is_nonnegative_int(value: str | None) -> bool:
    if value is None:
        return False
    try:
        return int(value) >= 0
    except ValueError:
        return False

from __future__ import annotations

import csv
import gzip
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .db import connect, get_meta, table_count
from .exporter import build_summary
from .fileutil import file_sha256
from .verification import build_verification_plan

REQUIRED_TABLES = {
    "snapshot_meta",
    "names",
    "resource_summary",
    "resource_ip",
    "provider_summary",
    "dns_evidence",
    "tlsa_evidence_summary",
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
    "names.html",
    "styles.css",
    "generator_handoff.js",
    "app.js",
    "data/summary.json",
    "data/manifest.json",
    "data/names-pages.json",
    "data/overview-pages.json",
    "data/hns-handoff-groups.json",
)

PUBLIC_JSON_FILES = tuple(path for path in REQUIRED_PUBLIC_FILES if path.endswith(".json"))
FORBIDDEN_PUBLIC_SUFFIXES = (".key", ".pem")
REQUIRED_MANIFEST_ARTIFACTS = (
    "summary.json",
    "overview-pages.json",
    "names-pages.json",
    "hns-handoff-groups.json",
)
OPTIONAL_MANIFEST_ARTIFACTS = (
    "names.json",
    "names.csv",
    "verification.csv",
    "topology.sqlite.gz",
)


@dataclass(frozen=True)
class ReleaseCheck:
    name: str
    ok: bool
    detail: str


def validate_release(
    *,
    db_path: str | Path,
    public_dir: str | Path | None = None,
    min_indexed_height: int = 0,
) -> list[ReleaseCheck]:
    checks: list[ReleaseCheck] = []
    db = Path(db_path)
    if not db.exists():
        return [ReleaseCheck("database_exists", False, f"{db} does not exist")]

    try:
        with connect(db) as conn:
            _validate_database(
                conn,
                checks,
                min_indexed_height=min_indexed_height,
            )
            summary = build_summary(conn)
    except Exception as exc:
        return [ReleaseCheck("database_open", False, f"{type(exc).__name__}: {exc}")]

    if public_dir is not None:
        _validate_public_artifacts(Path(public_dir), summary, checks)
    return checks


def validate_public_release(
    *,
    public_dir: str | Path,
    min_indexed_height: int = 0,
) -> list[ReleaseCheck]:
    checks: list[ReleaseCheck] = []
    public = Path(public_dir)
    checks.append(ReleaseCheck("public_dir_exists", public.is_dir(), str(public)))
    if not public.is_dir():
        return checks

    summary = _load_public_summary(public, checks)
    if summary:
        _validate_public_summary_metadata(
            summary,
            checks,
            min_indexed_height=min_indexed_height,
        )

    _validate_public_artifacts(public, summary, checks, include_public_dir_check=False)
    return checks


def release_is_valid(checks: list[ReleaseCheck]) -> bool:
    return all(check.ok for check in checks)


def _load_public_summary(public: Path, checks: list[ReleaseCheck]) -> dict[str, Any]:
    summary_path = public / "data/summary.json"
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except Exception as exc:
        checks.append(ReleaseCheck("public_summary_open", False, f"{type(exc).__name__}: {exc}"))
        return {}
    if not isinstance(summary, dict):
        checks.append(ReleaseCheck("public_summary_open", False, "summary is not an object"))
        return {}
    checks.append(ReleaseCheck("public_summary_open", True, "valid JSON"))
    return summary


def _validate_public_summary_metadata(
    summary: dict[str, Any],
    checks: list[ReleaseCheck],
    *,
    min_indexed_height: int,
) -> None:
    missing = [key for key in REQUIRED_META_KEYS if not summary.get(key)]
    checks.append(
        ReleaseCheck(
            "required_snapshot_meta",
            not missing,
            "present" if not missing else ", ".join(missing),
        )
    )

    source_type = str(summary.get("source_type") or "")
    if source_type in {"fixture", "jsonl"}:
        source_ok = bool(summary.get("source_file_hash"))
        source_detail = "source_file_hash present" if source_ok else "missing source_file_hash"
    elif source_type == "hsd_rpc":
        source_ok = bool(summary.get("source_rpc_url"))
        source_detail = "source_rpc_url present" if source_ok else "missing source_rpc_url"
    else:
        source_ok = False
        source_detail = f"unknown source_type={source_type!r}"
    checks.append(ReleaseCheck("source_provenance", source_ok, source_detail))

    height = summary.get("last_indexed_height")
    rules_version = summary.get("provider_rules_version")
    checks.append(ReleaseCheck("height_is_integer", _is_nonnegative_int_value(height), str(height)))
    if min_indexed_height > 0:
        checks.append(
            ReleaseCheck(
                "minimum_indexed_height",
                _is_nonnegative_int_value(height) and int(height) >= min_indexed_height,
                f"height={height or 'missing'} min={min_indexed_height}",
            )
        )
    checks.append(
        ReleaseCheck(
            "provider_rules_version_is_integer",
            _is_nonnegative_int_value(rules_version),
            str(rules_version),
        )
    )


def _validate_database(
    conn: sqlite3.Connection,
    checks: list[ReleaseCheck],
    *,
    min_indexed_height: int,
) -> None:
    integrity = conn.execute("PRAGMA quick_check").fetchone()[0]
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

    _validate_metadata(conn, checks, min_indexed_height=min_indexed_height)


def _validate_metadata(
    conn: sqlite3.Connection,
    checks: list[ReleaseCheck],
    *,
    min_indexed_height: int,
) -> None:
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
    if min_indexed_height > 0:
        checks.append(
            ReleaseCheck(
                "minimum_indexed_height",
                _is_nonnegative_int(height) and int(height) >= min_indexed_height,
                f"height={height or 'missing'} min={min_indexed_height}",
            )
        )
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

    manifest_path = public_dir / "data/manifest.json"
    if manifest_path.exists():
        _validate_export_manifest(manifest_path, summary, checks)

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
    try:
        uncompressed_bytes = 0
        with gzip.open(gz_path, "rb") as src:
            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                uncompressed_bytes += len(chunk)
    except Exception as exc:
        return ReleaseCheck("topology_sqlite_gz", False, f"{type(exc).__name__}: {exc}")
    ok = uncompressed_bytes > 0 and expected_names > 0
    return ReleaseCheck(
        "topology_sqlite_gz",
        ok,
        f"gzip_ok=true expected_names={expected_names} uncompressed_bytes={uncompressed_bytes}",
    )


def _validate_export_manifest(
    manifest_path: Path,
    summary: dict[str, Any],
    checks: list[ReleaseCheck],
) -> None:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        checks.append(ReleaseCheck("manifest_open", False, f"{type(exc).__name__}: {exc}"))
        return

    checks.append(
        ReleaseCheck(
            "manifest_version",
            manifest.get("manifest_version") == 1,
            str(manifest.get("manifest_version")),
        )
    )

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        checks.append(ReleaseCheck("manifest_artifacts", False, "artifacts is not a list"))
        return

    by_path = {
        item.get("path"): item
        for item in artifacts
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    required_artifacts = list(REQUIRED_MANIFEST_ARTIFACTS)
    export_meta = manifest.get("export") if isinstance(manifest.get("export"), dict) else {}
    if export_meta.get("download_artifacts_included") is True:
        required_artifacts.extend(OPTIONAL_MANIFEST_ARTIFACTS)
    missing = [relative for relative in required_artifacts if relative not in by_path]
    checks.append(
        ReleaseCheck(
            "manifest_required_artifacts",
            not missing,
            "present" if not missing else ", ".join(missing),
        )
    )

    errors: list[str] = []
    for relative, item in by_path.items():
        if _is_unsafe_manifest_path(relative):
            errors.append(f"{relative}: unsafe path")
            continue
        path = manifest_path.parent / relative
        if not path.is_file():
            errors.append(f"{relative}: missing")
            continue
        expected_bytes = item.get("bytes")
        actual_bytes = path.stat().st_size
        if expected_bytes != actual_bytes:
            errors.append(f"{relative}: bytes {actual_bytes}!={expected_bytes}")
            continue
        expected_hash = item.get("sha256")
        actual_hash = file_sha256(path)
        if expected_hash != actual_hash:
            errors.append(f"{relative}: sha256 mismatch")

    checks.append(
        ReleaseCheck(
            "manifest_artifacts",
            not errors,
            "matched" if not errors else "; ".join(errors[:10]),
        )
    )

    if summary:
        manifest_summary = manifest.get("summary") if isinstance(manifest.get("summary"), dict) else {}
        manifest_snapshot = manifest.get("snapshot") if isinstance(manifest.get("snapshot"), dict) else {}
        mismatches = [
            key
            for key in ("total_names", "active_names", "expired_names", "last_indexed_height")
            if manifest_summary.get(key) != summary.get(key)
        ]
        if manifest_snapshot.get("height") != summary.get("last_indexed_height"):
            mismatches.append("snapshot.height")
        if manifest_snapshot.get("tip_hash") != summary.get("last_indexed_tip_hash"):
            mismatches.append("snapshot.tip_hash")
        if manifest_snapshot.get("provider_rules_hash") != summary.get("provider_rules_hash"):
            mismatches.append("snapshot.provider_rules_hash")
        checks.append(
            ReleaseCheck(
                "manifest_snapshot",
                not mismatches,
                "matched" if not mismatches else ", ".join(mismatches),
            )
        )
        _validate_export_counts(manifest_path, manifest, summary, checks, by_path)


def _validate_export_counts(
    manifest_path: Path,
    manifest: dict[str, Any],
    summary: dict[str, Any],
    checks: list[ReleaseCheck],
    manifest_artifacts: dict[str, dict[str, Any]],
) -> None:
    export_meta = manifest.get("export") if isinstance(manifest.get("export"), dict) else {}
    names_limit = export_meta.get("names_limit")
    names_total = export_meta.get("names_total_count")
    names_exported = export_meta.get("names_exported_count")
    names_truncated = export_meta.get("names_truncated")
    expected_total = int(summary["total_names"])
    expected_exported = None
    expected_truncated = None
    if isinstance(names_limit, int):
        expected_exported = expected_total if names_limit <= 0 else min(expected_total, names_limit)
        expected_truncated = False if names_limit <= 0 else expected_total > names_limit

    mismatches: list[str] = []
    if names_total != expected_total:
        mismatches.append(f"names_total_count={names_total}!={expected_total}")
    if expected_exported is None:
        mismatches.append(f"names_limit={names_limit!r} is invalid")
    elif names_exported != expected_exported:
        mismatches.append(f"names_exported_count={names_exported}!={expected_exported}")
    if expected_truncated is not None and names_truncated != expected_truncated:
        mismatches.append(f"names_truncated={names_truncated}!={expected_truncated}")

    checks.append(
        ReleaseCheck(
            "manifest_export_counts",
            not mismatches,
            "matched" if not mismatches else "; ".join(mismatches),
        )
    )

    if expected_exported is None:
        return

    names_pages_path = manifest_path.parent / "names-pages.json"
    row_mismatches: list[str] = []
    try:
        names_pages = json.loads(names_pages_path.read_text(encoding="utf-8"))
        names_all = names_pages["collections"]["all"]
        page_rows = _count_paginated_rows(manifest_path.parent, names_all)
        verification_expected_rows = _expected_verification_csv_rows(manifest_path.parent, names_all)
    except Exception as exc:
        row_mismatches.append(f"names-pages.json: {type(exc).__name__}")
        verification_expected_rows = None
    else:
        if names_all.get("row_count") != expected_exported:
            row_mismatches.append(f"names-pages row_count={names_all.get('row_count')}!={expected_exported}")
        if page_rows != expected_exported:
            row_mismatches.append(f"names page rows={page_rows}!={expected_exported}")
        _validate_row_evidence_paths(manifest_path.parent, names_all, manifest_artifacts, checks)

    checks.append(
        ReleaseCheck(
            "names_export_rows",
            not row_mismatches,
            "matched" if not row_mismatches else "; ".join(row_mismatches),
        )
    )

    if export_meta.get("download_artifacts_included") is True:
        _validate_download_export_counts(
            manifest_path,
            expected_exported,
            verification_expected_rows,
            checks,
        )


def _validate_download_export_counts(
    manifest_path: Path,
    expected_exported: int,
    verification_expected_rows: int | None,
    checks: list[ReleaseCheck],
) -> None:
    names_json_path = manifest_path.parent / "names.json"
    names_csv_path = manifest_path.parent / "names.csv"
    verification_csv_path = manifest_path.parent / "verification.csv"
    row_mismatches: list[str] = []
    try:
        names_json = json.loads(names_json_path.read_text(encoding="utf-8"))
        json_rows = len(names_json) if isinstance(names_json, list) else None
    except Exception as exc:
        row_mismatches.append(f"names.json: {type(exc).__name__}")
    else:
        if json_rows != expected_exported:
            row_mismatches.append(f"names.json rows={json_rows}!={expected_exported}")

    try:
        with names_csv_path.open(newline="", encoding="utf-8") as handle:
            csv_rows = sum(1 for _ in csv.DictReader(handle))
    except Exception as exc:
        row_mismatches.append(f"names.csv: {type(exc).__name__}")
    else:
        if csv_rows != expected_exported:
            row_mismatches.append(f"names.csv rows={csv_rows}!={expected_exported}")

    try:
        with verification_csv_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            required_columns = {
                "name",
                "mode",
                "sequence",
                "purpose",
                "label",
                "qname",
                "rrtype",
                "transport",
                "command",
                "server",
            }
            missing_columns = required_columns - set(reader.fieldnames or [])
            verification_rows = sum(1 for _ in reader)
    except Exception as exc:
        row_mismatches.append(f"verification.csv: {type(exc).__name__}")
    else:
        if missing_columns:
            row_mismatches.append(f"verification.csv missing columns={','.join(sorted(missing_columns))}")
        if verification_expected_rows is not None and verification_rows != verification_expected_rows:
            row_mismatches.append(
                f"verification.csv rows={verification_rows}!={verification_expected_rows}"
            )

    checks.append(
        ReleaseCheck(
            "download_export_rows",
            not row_mismatches,
            "matched" if not row_mismatches else "; ".join(row_mismatches),
        )
    )


def _expected_verification_csv_rows(data_dir: Path, collection: dict[str, Any]) -> int:
    total = 0
    for row in _iter_paginated_rows(data_dir, collection):
        plan = build_verification_plan(row)
        if plan is not None:
            total += len(plan["commands"])
    return total


def _validate_row_evidence_paths(
    data_dir: Path,
    collection: dict[str, Any],
    manifest_artifacts: dict[str, dict[str, Any]],
    checks: list[ReleaseCheck],
) -> None:
    errors: list[str] = []
    try:
        for row in _iter_paginated_rows(data_dir, collection):
            row_name = str(row.get("name") or "")
            for column, prefix in (
                ("dns_evidence_path", "dns-evidence/"),
            ):
                value = row.get(column)
                if not value:
                    continue
                if not isinstance(value, str):
                    errors.append(f"{row_name}:{column} is not a string")
                    continue
                if _is_unsafe_manifest_path(value) or not value.startswith(prefix) or not value.endswith(".json"):
                    errors.append(f"{row_name}:{column} unsafe path {value!r}")
                    continue
                if value not in manifest_artifacts:
                    errors.append(f"{row_name}:{column} {value} missing from manifest")
                    continue
                path = data_dir / value
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except Exception as exc:
                    errors.append(f"{row_name}:{column} {value}: {type(exc).__name__}")
                    continue
                if not isinstance(payload, dict):
                    errors.append(f"{row_name}:{column} {value}: payload is not an object")
                    continue
                if payload.get("name") != row_name:
                    errors.append(f"{row_name}:{column} {value}: name={payload.get('name')!r}")
                if not isinstance(payload.get("observations"), list):
                    errors.append(f"{row_name}:{column} {value}: observations is not a list")
    except Exception as exc:
        errors.append(f"names-pages evidence scan: {type(exc).__name__}")

    checks.append(
        ReleaseCheck(
            "row_evidence_paths",
            not errors,
            "matched" if not errors else "; ".join(errors[:10]),
        )
    )


def _count_paginated_rows(data_dir: Path, collection: dict[str, Any]) -> int:
    path_template = collection["path_template"]
    page_count = int(collection.get("page_count") or 0)
    total = 0
    for page in range(1, page_count + 1):
        path = data_dir / path_template.replace("{page}", str(page))
        payload = json.loads(path.read_text(encoding="utf-8"))
        rows = payload.get("rows")
        if not isinstance(rows, list):
            raise ValueError(f"{path}: rows is not a list")
        total += len(rows)
    return total


def _iter_paginated_rows(data_dir: Path, collection: dict[str, Any]):
    path_template = collection["path_template"]
    page_count = int(collection.get("page_count") or 0)
    collection_columns = collection.get("columns")
    for page in range(1, page_count + 1):
        path = data_dir / path_template.replace("{page}", str(page))
        payload = json.loads(path.read_text(encoding="utf-8"))
        rows = payload.get("rows")
        if not isinstance(rows, list):
            raise ValueError(f"{path}: rows is not a list")
        columns = payload.get("columns") or collection_columns
        for row in rows:
            if isinstance(row, dict):
                yield row
            elif isinstance(row, list) and isinstance(columns, list):
                if len(row) != len(columns):
                    raise ValueError(f"{path}: compact row has {len(row)} values for {len(columns)} columns")
                yield dict(zip(columns, row, strict=True))
            else:
                raise ValueError(f"{path}: unsupported row shape")


def _is_unsafe_manifest_path(relative: str) -> bool:
    path = Path(relative)
    return path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts)


def _is_nonnegative_int(value: str | None) -> bool:
    if value is None:
        return False
    try:
        return int(value) >= 0
    except ValueError:
        return False


def _is_nonnegative_int_value(value: Any) -> bool:
    if value is None:
        return False
    try:
        return int(value) >= 0
    except (TypeError, ValueError):
        return False

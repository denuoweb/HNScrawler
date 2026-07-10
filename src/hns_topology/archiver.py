from __future__ import annotations

import gzip
import json
import sqlite3
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .db import get_meta
from .exporter import build_summary, gzip_sqlite, write_json
from .fileutil import file_sha256
from .timeutil import utc_now


@dataclass(frozen=True)
class ArchiveResult:
    manifest_path: Path
    site_tarball_path: Path
    sqlite_backup_path: Path


@dataclass(frozen=True)
class ArchiveCheck:
    name: str
    ok: bool
    detail: str


def archive_release(
    conn: sqlite3.Connection,
    *,
    db_path: str | Path,
    public_dir: str | Path,
    out_dir: str | Path,
    keep: int | None = None,
    prefix: str = "hns-topology",
) -> ArchiveResult:
    public = Path(public_dir)
    if not public.is_dir():
        raise FileNotFoundError(f"public directory not found: {public}")

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    height = _safe_slug(get_meta(conn, "last_indexed_height", "unknown") or "unknown")
    created_at = utc_now()
    stamp = _safe_slug(created_at)
    base = _unique_base(out, f"{prefix}-height-{height}-{stamp}")

    site_tarball = out / f"{base}-site.tar.gz"
    sqlite_backup = out / f"{base}-topology.sqlite.gz"
    manifest_path = out / f"{base}-manifest.json"

    _tar_public(public, site_tarball)
    gzip_sqlite(db_path, sqlite_backup)

    manifest = {
        "archive_created_at": created_at,
        "crawler_version": __version__,
        "snapshot": {
            "height": get_meta(conn, "last_indexed_height"),
            "tip_hash": get_meta(conn, "last_indexed_tip_hash"),
            "generated_at": get_meta(conn, "generated_at"),
            "source_type": get_meta(conn, "source_type"),
            "source_file_hash": get_meta(conn, "source_file_hash"),
            "source_rpc_url": get_meta(conn, "source_rpc_url"),
            "provider_rules_hash": get_meta(conn, "provider_rules_hash"),
            "provider_rules_version": get_meta(conn, "provider_rules_version"),
        },
        "summary": build_summary(conn),
        "artifacts": [
            _artifact_entry(site_tarball),
            _artifact_entry(sqlite_backup),
        ],
    }
    write_json(manifest_path, manifest)

    if keep is not None:
        prune_archives(out, prefix=prefix, keep=keep)

    return ArchiveResult(
        manifest_path=manifest_path,
        site_tarball_path=site_tarball,
        sqlite_backup_path=sqlite_backup,
    )


def validate_archive_manifest(manifest_path: str | Path) -> list[ArchiveCheck]:
    manifest_file = Path(manifest_path)
    checks = [
        ArchiveCheck("archive_manifest_exists", manifest_file.is_file(), str(manifest_file))
    ]
    if not manifest_file.is_file():
        return checks

    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except Exception as exc:
        checks.append(ArchiveCheck("archive_manifest_json", False, f"{type(exc).__name__}: {exc}"))
        return checks
    checks.append(ArchiveCheck("archive_manifest_json", True, "valid JSON"))

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        checks.append(ArchiveCheck("archive_artifacts", False, "artifacts is not a list"))
        return checks

    errors: list[str] = []
    artifact_paths: dict[str, Path] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("file"), str):
            errors.append("invalid artifact entry")
            continue
        filename = artifact["file"]
        if _is_unsafe_artifact_name(filename):
            errors.append(f"{filename}: unsafe artifact name")
            continue
        path = manifest_file.parent / filename
        artifact_paths[filename] = path
        if not path.is_file():
            errors.append(f"{filename}: missing")
            continue
        actual_bytes = path.stat().st_size
        if artifact.get("bytes") != actual_bytes:
            errors.append(f"{filename}: bytes {actual_bytes}!={artifact.get('bytes')}")
            continue
        actual_hash = file_sha256(path)
        if artifact.get("sha256") != actual_hash:
            errors.append(f"{filename}: sha256 mismatch")

    checks.append(
        ArchiveCheck(
            "archive_artifacts",
            not errors,
            "matched" if not errors else "; ".join(errors[:10]),
        )
    )

    site_tarball = _artifact_by_suffix(artifact_paths, "-site.tar.gz")
    sqlite_backup = _artifact_by_suffix(artifact_paths, "-topology.sqlite.gz")
    site_tarball_present = site_tarball is not None and site_tarball.is_file()
    sqlite_backup_present = sqlite_backup is not None and sqlite_backup.is_file()
    checks.append(
        ArchiveCheck(
            "archive_site_tarball_present",
            site_tarball_present,
            str(site_tarball) if site_tarball else "missing",
        )
    )
    checks.append(
        ArchiveCheck(
            "archive_sqlite_backup_present",
            sqlite_backup_present,
            str(sqlite_backup) if sqlite_backup else "missing",
        )
    )

    if site_tarball_present:
        checks.append(_validate_site_tarball(site_tarball))
    if sqlite_backup_present:
        expected_names = _manifest_total_names(manifest)
        checks.append(_validate_sqlite_backup(sqlite_backup, expected_names=expected_names))
    return checks


def archive_is_valid(checks: list[ArchiveCheck]) -> bool:
    return all(check.ok for check in checks)


def prune_archives(out_dir: str | Path, *, prefix: str = "hns-topology", keep: int) -> None:
    if keep < 1:
        return
    out = Path(out_dir)
    manifests = sorted(
        out.glob(f"{prefix}-height-*-manifest.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for manifest in manifests[keep:]:
        for artifact in _manifest_artifacts(manifest):
            artifact_path = out / artifact
            if artifact_path.is_file():
                artifact_path.unlink()
        manifest.unlink(missing_ok=True)


def _tar_public(public_dir: Path, out_path: Path) -> None:
    with tarfile.open(out_path, "w:gz") as archive:
        archive.add(public_dir, arcname="public", recursive=True)


def _artifact_entry(path: Path) -> dict[str, Any]:
    return {
        "file": path.name,
        "sha256": file_sha256(path),
        "bytes": path.stat().st_size,
    }


def _manifest_artifacts(manifest_path: Path) -> list[str]:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list):
        return []
    files = []
    for artifact in artifacts:
        if isinstance(artifact, dict) and isinstance(artifact.get("file"), str):
            files.append(artifact["file"])
    return files


def _artifact_by_suffix(artifact_paths: dict[str, Path], suffix: str) -> Path | None:
    for filename, path in artifact_paths.items():
        if filename.endswith(suffix):
            return path
    return None


def _validate_site_tarball(path: Path) -> ArchiveCheck:
    required = {
        "public/index.html",
        "public/data/manifest.json",
        "public/data/names-pages.json",
    }
    try:
        with tarfile.open(path, "r:gz") as archive:
            names = set(archive.getnames())
    except Exception as exc:
        return ArchiveCheck("archive_site_tarball", False, f"{type(exc).__name__}: {exc}")

    unsafe = [name for name in names if _is_unsafe_tar_name(name)]
    missing = sorted(required - names)
    ok = not unsafe and not missing
    details = []
    if unsafe:
        details.append(f"unsafe={unsafe[:5]}")
    if missing:
        details.append(f"missing={missing}")
    return ArchiveCheck(
        "archive_site_tarball",
        ok,
        "required files present" if ok else "; ".join(details),
    )


def _validate_sqlite_backup(path: Path, *, expected_names: int | None) -> ArchiveCheck:
    with tempfile.NamedTemporaryFile(prefix="hns-topology-archive-", suffix=".sqlite") as handle:
        try:
            with gzip.open(path, "rb") as src:
                handle.write(src.read())
            handle.flush()
            with sqlite3.connect(handle.name) as conn:
                quick_check = conn.execute("PRAGMA quick_check").fetchone()[0]
                names = conn.execute("SELECT COUNT(*) FROM names").fetchone()[0]
        except Exception as exc:
            return ArchiveCheck("archive_sqlite_backup", False, f"{type(exc).__name__}: {exc}")
    names_ok = expected_names is None or names == expected_names
    ok = quick_check == "ok" and names_ok
    expected_detail = "unknown" if expected_names is None else str(expected_names)
    return ArchiveCheck(
        "archive_sqlite_backup",
        ok,
        f"quick_check={quick_check} names={names}/{expected_detail}",
    )


def _manifest_total_names(manifest: dict[str, Any]) -> int | None:
    summary = manifest.get("summary")
    if not isinstance(summary, dict):
        return None
    value = summary.get("total_names")
    if not isinstance(value, int):
        return None
    return value


def _is_unsafe_artifact_name(filename: str) -> bool:
    path = Path(filename)
    return path.is_absolute() or len(path.parts) != 1 or any(part in {"", ".", ".."} for part in path.parts)


def _is_unsafe_tar_name(name: str) -> bool:
    path = Path(name)
    return path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts)


def _unique_base(out_dir: Path, base: str) -> str:
    candidate = base
    counter = 2
    while any(out_dir.glob(f"{candidate}-*")):
        candidate = f"{base}-{counter}"
        counter += 1
    return candidate


def _safe_slug(value: str) -> str:
    return "".join(char if char.isalnum() else "-" for char in value).strip("-") or "unknown"

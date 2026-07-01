from __future__ import annotations

import hashlib
import json
import sqlite3
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .db import get_meta
from .exporter import build_summary, gzip_sqlite, write_json
from .timeutil import utc_now


@dataclass(frozen=True)
class ArchiveResult:
    manifest_path: Path
    site_tarball_path: Path
    sqlite_backup_path: Path


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
        "sha256": _file_sha256(path),
        "bytes": path.stat().st_size,
    }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _unique_base(out_dir: Path, base: str) -> str:
    candidate = base
    counter = 2
    while any(out_dir.glob(f"{candidate}-*")):
        candidate = f"{base}-{counter}"
        counter += 1
    return candidate


def _safe_slug(value: str) -> str:
    return "".join(char if char.isalnum() else "-" for char in value).strip("-") or "unknown"

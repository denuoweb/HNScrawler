from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import tempfile
from importlib import resources
from pathlib import Path
from typing import Any

from .jsonutil import dumps_pretty
from .live_db import (
    candidate_plan,
    directory_rows,
    get_live_meta,
    latest_probe_run,
    live_summary_counts,
)
from .timeutil import utc_now

LIVE_BASE_PATH = "/hns-live/"
REQUIRED_LIVE_FILES = (
    "index.html",
    "styles.css",
    "app.js",
    "data/summary.json",
    "data/sites.json",
    "data/manifest.json",
)


def export_live_site(conn: sqlite3.Connection, out_dir: str | Path) -> dict[str, Any]:
    out = Path(out_dir)
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{out.name}.live-tmp-", dir=out.parent))
    staging.chmod(0o755)
    try:
        summary = _export_into(conn, staging)
        errors = validate_live_site(staging)
        if errors:
            raise RuntimeError(f"live site validation failed: {', '.join(errors)}")
        _replace_tree(staging, out)
        staging = None
        return summary
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def validate_live_site(public_dir: str | Path) -> list[str]:
    public = Path(public_dir)
    errors = [relative for relative in REQUIRED_LIVE_FILES if not (public / relative).is_file()]
    if errors:
        return [f"missing:{relative}" for relative in errors]
    try:
        summary = json.loads((public / "data/summary.json").read_text(encoding="utf-8"))
        sites = json.loads((public / "data/sites.json").read_text(encoding="utf-8"))
        manifest = json.loads((public / "data/manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid_json:{type(exc).__name__}"]
    rows = sites.get("rows") if isinstance(sites, dict) else None
    if not isinstance(rows, list):
        errors.append("sites_rows:not_list")
        rows = []
    if int(summary.get("directory_count") or 0) != len(rows):
        errors.append("directory_count:mismatch")
    for item in manifest.get("artifacts", []):
        relative = str(item.get("path") or "")
        path = public / "data" / relative
        if not path.is_file():
            errors.append(f"manifest_missing:{relative}")
            continue
        if int(item.get("bytes") or -1) != path.stat().st_size:
            errors.append(f"manifest_bytes:{relative}")
        if str(item.get("sha256") or "") != _sha256(path):
            errors.append(f"manifest_sha256:{relative}")
    return errors


def _export_into(conn: sqlite3.Connection, out: Path) -> dict[str, Any]:
    data_dir = out / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    rows = directory_rows(conn)
    counts = live_summary_counts(conn)
    plan = candidate_plan(conn)
    latest_run = latest_probe_run(conn)
    generated_at = utc_now()
    https_count = sum(1 for row in rows if row["category"] == "https")
    http_only_count = sum(1 for row in rows if row["category"] == "http_only")
    summary = {
        "generated_at": generated_at,
        "topology_synced_at": get_live_meta(conn, "topology_synced_at"),
        "topology_generated_at": get_live_meta(conn, "topology_generated_at"),
        "topology_height": _int_or_none(get_live_meta(conn, "topology_height")),
        "topology_tip_hash": get_live_meta(conn, "topology_tip_hash"),
        "directory_count": len(rows),
        "online_count": https_count + http_only_count,
        "https_count": https_count,
        "http_only_count": http_only_count,
        "repair_count": sum(1 for row in rows if row["category"] == "repair"),
        "degraded_count": sum(1 for row in rows if row["listing_state"] == "degraded"),
        "status_counts": counts,
        "candidate_plan": plan,
        "latest_probe_run": latest_run,
    }
    sites = {
        "generated_at": generated_at,
        "row_count": len(rows),
        "rows": rows,
    }
    _write_json(data_dir / "summary.json", summary)
    _write_json(data_dir / "sites.json", sites)
    _copy_assets(out)
    (out / "index.html").write_text(_html(), encoding="utf-8")
    manifest = {
        "generated_at": generated_at,
        "artifacts": [_artifact(data_dir, relative) for relative in ("summary.json", "sites.json")],
    }
    _write_json(data_dir / "manifest.json", manifest)
    return summary


def _copy_assets(out: Path) -> None:
    assets = resources.files("hns_topology").joinpath("live_site_assets")
    for asset in ("styles.css", "app.js"):
        shutil.copyfile(assets.joinpath(asset), out / asset)


def _html() -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HNS Websites Online</title>
  <base href="{LIVE_BASE_PATH}">
  <link rel="stylesheet" href="{LIVE_BASE_PATH}styles.css">
</head>
<body>
  <header class="topbar">
    <h1>HNS Websites Online</h1>
    <nav aria-label="Directory navigation">
      <a href="/hns-topology/index.html">Domain Directory</a>
      <a class="active" href="{LIVE_BASE_PATH}">Websites Online</a>
      <a href="/hns-topology/names.html">Root Diagnostics</a>
    </nav>
  </header>
  <main id="app"><section class="loading">Loading live website data...</section></main>
  <script src="{LIVE_BASE_PATH}app.js"></script>
</body>
</html>
"""


def _replace_tree(staging: Path, out: Path) -> None:
    backup: Path | None = None
    if out.exists() or out.is_symlink():
        backup = Path(tempfile.mkdtemp(prefix=f".{out.name}.live-old-", dir=out.parent))
        backup.rmdir()
        out.rename(backup)
    try:
        staging.rename(out)
    except Exception:
        if backup is not None and not out.exists():
            backup.rename(out)
        raise
    if backup is not None:
        if backup.is_dir() and not backup.is_symlink():
            shutil.rmtree(backup)
        else:
            backup.unlink(missing_ok=True)


def _artifact(data_dir: Path, relative: str) -> dict[str, Any]:
    path = data_dir / relative
    return {
        "path": relative,
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.write_text(dumps_pretty(value), encoding="utf-8")


def _int_or_none(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

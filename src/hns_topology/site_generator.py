from __future__ import annotations

import shutil
import tempfile
from importlib import resources
from pathlib import Path

from .exporter import export_all

PAGES = {
    "index.html": ("overview", "HNS Domain Directory"),
    "names.html": ("names", "HNS Root Diagnostics"),
}
SITE_BASE_PATH = "/hns-topology/"


def generate_site(
    conn,
    *,
    db_path: str | Path,
    out_dir: str | Path,
    names_limit: int = 0,
    include_downloads: bool = False,
) -> None:
    out = Path(out_dir)
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{out.name}.tmp-", dir=out.parent))
    staging.chmod(0o755)
    try:
        _generate_site_into(
            conn,
            db_path=db_path,
            out_dir=staging,
            names_limit=names_limit,
            include_downloads=include_downloads,
        )
        _replace_tree(staging, out)
        staging = None
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def _generate_site_into(
    conn,
    *,
    db_path: str | Path,
    out_dir: Path,
    names_limit: int,
    include_downloads: bool,
) -> None:
    out = out_dir
    data_dir = out / "data"
    out.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    export_all(
        conn,
        db_path=db_path,
        out_dir=data_dir,
        names_limit=names_limit,
        include_downloads=include_downloads,
    )
    _copy_assets(out)
    for filename, (page, title) in PAGES.items():
        (out / filename).write_text(_html(page=page, title=title), encoding="utf-8")


def _replace_tree(staging: Path, out: Path) -> None:
    backup: Path | None = None
    if out.exists() or out.is_symlink():
        backup = Path(tempfile.mkdtemp(prefix=f".{out.name}.old-", dir=out.parent))
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


def _copy_assets(out: Path) -> None:
    assets = resources.files("hns_topology").joinpath("site_assets")
    for asset in ("styles.css", "generator_handoff.js", "app.js"):
        source = assets.joinpath(asset)
        shutil.copyfile(source, out / asset)


def _html(*, page: str, title: str) -> str:
    nav = "\n".join(
        f'<a href="{SITE_BASE_PATH}{filename}" data-nav="{name}">{label}</a>'
        for filename, (name, label) in [
            ("index.html", ("overview", "Domain Directory")),
            ("names.html", ("names", "Root Diagnostics")),
        ]
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <base href="{SITE_BASE_PATH}">
  <link rel="stylesheet" href="{SITE_BASE_PATH}styles.css">
</head>
<body data-page="{page}">
  <header class="topbar">
    <div>
      <h1>{title}</h1>
    </div>
    <nav>{nav}</nav>
  </header>
  <main id="app">
    <section class="loading">Loading snapshot data...</section>
  </main>
  <script src="{SITE_BASE_PATH}generator_handoff.js"></script>
  <script src="{SITE_BASE_PATH}app.js"></script>
</body>
</html>
"""

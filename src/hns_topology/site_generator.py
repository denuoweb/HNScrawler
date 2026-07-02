from __future__ import annotations

import shutil
from importlib import resources
from pathlib import Path

from .exporter import export_all

PAGES = {
    "index.html": ("overview", "HNS Topology"),
    "faq.html": ("faq", "Topology FAQ"),
    "providers.html": ("providers", "Provider Dominance"),
    "classes.html": ("classes", "On-Chain Classes"),
    "names.html": ("names", "Names"),
    "broken.html": ("broken", "Broken Paths"),
    "dane.html": ("dane", "DANE"),
}


def generate_site(conn, *, db_path: str | Path, out_dir: str | Path, names_limit: int = 5000) -> None:
    out = Path(out_dir)
    data_dir = out / "data"
    out.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    export_all(conn, db_path=db_path, out_dir=data_dir, names_limit=names_limit)
    _copy_assets(out)
    for filename, (page, title) in PAGES.items():
        (out / filename).write_text(_html(page=page, title=title), encoding="utf-8")


def _copy_assets(out: Path) -> None:
    assets = resources.files("hns_topology").joinpath("site_assets")
    for asset in ("styles.css", "app.js"):
        source = assets.joinpath(asset)
        shutil.copyfile(source, out / asset)


def _html(*, page: str, title: str) -> str:
    nav = "\n".join(
        f'<a href="{filename}" data-nav="{name}">{label}</a>'
        for filename, (name, label) in [
            ("index.html", ("overview", "Overview")),
            ("faq.html", ("faq", "FAQ")),
            ("providers.html", ("providers", "Providers")),
            ("classes.html", ("classes", "Classes")),
            ("names.html", ("names", "Names")),
            ("broken.html", ("broken", "Broken")),
            ("dane.html", ("dane", "DANE")),
        ]
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <link rel="stylesheet" href="styles.css">
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
  <script src="app.js"></script>
</body>
</html>
"""

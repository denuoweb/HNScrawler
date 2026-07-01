import gzip
import hashlib
import io
import json
import sqlite3
import tarfile
from pathlib import Path

from hns_topology.archiver import archive_is_valid, archive_release, validate_archive_manifest
from hns_topology.db import connect
from hns_topology.indexer import bootstrap_from_fixture
from hns_topology.provider_rules import ProviderRules
from hns_topology.site_generator import generate_site

FIXTURE = Path("tests/fixtures/sample_hsd_names.json")


def test_archive_release_writes_manifest_site_tarball_and_sqlite_backup(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    public_dir = tmp_path / "public"
    archive_dir = tmp_path / "archives"
    rules = ProviderRules.from_file("configs/provider_rules.json")

    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=public_dir)
        result = archive_release(conn, db_path=db_path, public_dir=public_dir, out_dir=archive_dir)

    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    artifacts = {item["file"]: item for item in manifest["artifacts"]}

    assert result.site_tarball_path.name in artifacts
    assert result.sqlite_backup_path.name in artifacts
    assert manifest["snapshot"]["height"] == "123456"
    assert manifest["summary"]["total_names"] == 9
    checks = validate_archive_manifest(result.manifest_path)
    assert archive_is_valid(checks), [check for check in checks if not check.ok]

    for path in [result.site_tarball_path, result.sqlite_backup_path]:
        assert artifacts[path.name]["bytes"] == path.stat().st_size
        assert artifacts[path.name]["sha256"] == file_sha256(path)

    with tarfile.open(result.site_tarball_path, "r:gz") as archive:
        names = set(archive.getnames())
    assert "public/index.html" in names
    assert "public/data/summary.json" in names

    sqlite_path = tmp_path / "restored.sqlite"
    with gzip.open(result.sqlite_backup_path, "rb") as src, sqlite_path.open("wb") as dst:
        dst.write(src.read())
    with sqlite3.connect(sqlite_path) as conn:
        names_count = conn.execute("SELECT COUNT(*) FROM names").fetchone()[0]
    assert names_count == 9


def test_validate_archive_manifest_catches_missing_artifact(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    public_dir = tmp_path / "public"
    archive_dir = tmp_path / "archives"
    rules = ProviderRules.from_file("configs/provider_rules.json")

    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=public_dir)
        result = archive_release(conn, db_path=db_path, public_dir=public_dir, out_dir=archive_dir)

    result.sqlite_backup_path.unlink()
    checks = validate_archive_manifest(result.manifest_path)

    assert not archive_is_valid(checks)
    failed = {check.name: check.detail for check in checks if not check.ok}
    assert "archive_artifacts" in failed
    assert result.sqlite_backup_path.name in failed["archive_artifacts"]


def test_validate_archive_manifest_catches_unsafe_site_tarball(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    public_dir = tmp_path / "public"
    archive_dir = tmp_path / "archives"
    rules = ProviderRules.from_file("configs/provider_rules.json")

    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=public_dir)
        result = archive_release(conn, db_path=db_path, public_dir=public_dir, out_dir=archive_dir)

    with tarfile.open(result.site_tarball_path, "w:gz") as archive:
        payload = b"x"
        info = tarfile.TarInfo("../evil")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))

    checks = validate_archive_manifest(result.manifest_path)

    assert not archive_is_valid(checks)
    failed = {check.name: check.detail for check in checks if not check.ok}
    assert "archive_site_tarball" in failed
    assert "unsafe" in failed["archive_site_tarball"]


def test_archive_release_prunes_older_archives(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    public_dir = tmp_path / "public"
    archive_dir = tmp_path / "archives"
    rules = ProviderRules.from_file("configs/provider_rules.json")

    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=public_dir)
        first = archive_release(conn, db_path=db_path, public_dir=public_dir, out_dir=archive_dir)
        second = archive_release(conn, db_path=db_path, public_dir=public_dir, out_dir=archive_dir, keep=1)

    assert not first.manifest_path.exists()
    assert not first.site_tarball_path.exists()
    assert not first.sqlite_backup_path.exists()
    assert second.manifest_path.exists()
    assert second.site_tarball_path.exists()
    assert second.sqlite_backup_path.exists()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

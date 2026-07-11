import subprocess
from pathlib import Path


def test_nightly_scripts_parse_as_bash():
    for script in [
        Path("scripts/full-nightly-job.sh"),
        Path("scripts/gcloud-run-indexer-pipeline.sh"),
        Path("scripts/run-live-directory.sh"),
        Path("scripts/setup-live-directory-service.sh"),
        Path("scripts/configure-live-directory-nginx.sh"),
        Path("scripts/publish-hns-topology-navigation.sh"),
        Path("scripts/gcloud-deploy-live-directory.sh"),
    ]:
        subprocess.run(["bash", "-n", str(script)], check=True)


def test_full_nightly_stops_hsd_before_site_generation():
    script = Path("scripts/full-nightly-job.sh").read_text(encoding="utf-8")

    assert 'START_HSD_FOR_UPDATES="${START_HSD_FOR_UPDATES:-1}"' in script
    assert 'STOP_HSD_AFTER_UPDATES="${STOP_HSD_AFTER_UPDATES:-1}"' in script
    assert "trap cleanup_hsd EXIT" in script
    assert '\nstart_hsd_for_update\nif [ "$CHECK_HSD_READY" = "1" ]; then' in script
    assert "\nscripts/run-incremental.sh\nstop_hsd_after_update\nscripts/generate-site.sh" in script


def test_exporter_has_no_standalone_dane_page_builders():
    exporter = Path("src/hns_topology/exporter.py").read_text(encoding="utf-8")

    for removed_builder in [
        "def build_dane(",
        "def build_dane_rows(",
        "def write_dane_pages(",
        "def _write_dane_pages_streamed(",
        "DANE_FILTERS =",
    ]:
        assert removed_builder not in exporter


def test_live_directory_is_not_called_by_existing_build_or_publish_scripts():
    existing_pipeline_scripts = [
        "scripts/full-nightly-job.sh",
        "scripts/generate-site.sh",
        "scripts/gcloud-run-indexer-pipeline.sh",
        "scripts/publish-indexer-site.sh",
        "scripts/publish-site.sh",
    ]

    for path in existing_pipeline_scripts:
        script = Path(path).read_text(encoding="utf-8")
        assert "run-live-directory" not in script
        assert "hns-live-directory" not in script


def test_large_legacy_schema_cleanup_is_not_called_by_existing_pipelines():
    for path in (
        "scripts/full-nightly-job.sh",
        "scripts/generate-site.sh",
        "scripts/gcloud-run-indexer-pipeline.sh",
        "scripts/publish-indexer-site.sh",
        "scripts/publish-site.sh",
    ):
        script = Path(path).read_text(encoding="utf-8")
        assert "cleanup-legacy-schema" not in script


def test_live_directory_runner_uses_web_vm_snapshot_and_separate_state():
    runner = Path("scripts/run-live-directory.sh").read_text(encoding="utf-8")
    setup = Path("scripts/setup-live-directory-service.sh").read_text(encoding="utf-8")

    assert 'TOPOLOGY_DB="${TOPOLOGY_DB:-/mnt/hns-topology/topology.sqlite}"' in runner
    assert 'LIVE_DB="${LIVE_DB:-$LIVE_ROOT/data/live.sqlite}"' in runner
    assert '.venv/bin/hns-live-directory "${args[@]}"' in runner
    assert "OnUnitActiveSec=1d" in setup
    assert "hns-live-directory.timer" in setup
    assert "configure-live-directory-nginx.sh" in setup
    assert "publish-hns-topology-navigation.sh" in setup


def test_topology_navigation_publisher_renders_both_entry_pages():
    publisher = Path("scripts/publish-hns-topology-navigation.sh").read_text(encoding="utf-8")

    assert '_html(page="overview", title="HNS Domain Directory")' in publisher
    assert '_html(page="names", title="HNS Root Diagnostics")' in publisher
    assert '"$TOPOLOGY_SITE_DIR/names.html"' in publisher


def test_live_directory_nginx_config_serves_the_directory_root_explicitly():
    snippet = Path("deploy/nginx/hns-live-directory.conf").read_text(encoding="utf-8")
    setup = Path("scripts/configure-live-directory-nginx.sh").read_text(encoding="utf-8")

    assert "location = /hns-live/" in snippet
    assert "try_files /hns-live/index.html =404" in snippet
    assert "location ^~ /hns-live/" in snippet
    assert "hns.denuoweb.com" in setup

import json
import stat
from pathlib import Path

from hns_topology.compliance import COMPLIANCE_STAGES
from hns_topology.db import (
    RESOURCE_IP_INDEX_META_KEY,
    RESOURCE_IP_INDEX_VERSION,
    connect,
    get_meta,
    set_meta,
    upsert_live_status,
)
from hns_topology.exporter import build_summary
from hns_topology.indexer import (
    UnpaginatedGetNamesError,
    bootstrap_from_fixture,
    bootstrap_from_hsd,
    bootstrap_from_jsonl,
    extract_changed_name_refs_from_block,
    find_reorg_mismatch,
    index_changed_names,
    reclassify_existing_names,
    rollback_reorg,
)
from hns_topology.models import FAILURE_REASONS, LiveStatus
from hns_topology.provider_rules import ProviderRules
from hns_topology.site_generator import generate_site
from hns_topology.validator import release_is_valid, validate_public_release, validate_release

FIXTURE = Path("tests/fixtures/sample_hsd_names.json")
JSONL_FIXTURE = Path("tests/fixtures/sample_hsd_names.jsonl")


class FakeHsdClient:
    def __init__(self, *, block_hashes: dict[int, str], resources: dict[str, dict]):
        self.block_hashes = block_hashes
        self.resources = resources

    def call(self, method: str, params: list):
        if method == "getnameinfo":
            name = params[0]
            return {
                "name": name,
                "nameHash": f"hash-{name}",
                "state": "CLOSED",
                "renewal": 123000,
            }
        raise AssertionError(f"unexpected method {method}")

    def get_name_resource(self, name: str):
        return self.resources[name]

    def get_name_by_hash(self, name_hash: str):
        return None

    def get_block_hash(self, height: int) -> str:
        return self.block_hashes[height]


class FakeBootstrapHsdClient:
    url = "http://127.0.0.1:12037"

    def __init__(self):
        self.get_names_calls = 0

    def get_blockchain_info(self):
        return {
            "blocks": 123456,
            "bestblockhash": "hash-tip",
            "chain": "main",
            "version": "fake-hsd",
        }

    def get_names(self):
        self.get_names_calls += 1
        return [
            {
                "name": "direct",
                "nameHash": "hash-direct",
                "state": "CLOSED",
                "renewal": 123000,
            }
        ]

    def get_name_resource(self, name: str):
        return {"records": [{"type": "SYNTH4", "address": "203.0.113.10"}]}


def test_fixture_bootstrap_builds_expected_counts(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        count = bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        summary = build_summary(conn)
        resource_ip_count = conn.execute("SELECT COUNT(*) FROM resource_ip").fetchone()[0]
        resource_ip_version = get_meta(conn, RESOURCE_IP_INDEX_META_KEY)
        resource_ip_indexes = {row["name"] for row in conn.execute("PRAGMA index_list(resource_ip)")}
        namebase_provider = conn.execute(
            "SELECT ns_pattern, ip_pattern FROM provider_summary WHERE provider_key = ?",
            ("namebase/default",),
        ).fetchone()

    assert count == 9
    assert summary["total_names"] == 9
    assert summary["active_names"] == 8
    assert summary["direct_ip_records"] == 1
    assert summary["synth_nameserver_records"] == 1
    assert summary["delegated_names"] == 4
    assert summary["delegated_with_glue"] == 2
    assert summary["delegated_no_glue"] == 2
    assert summary["default_provider_names"] == 1
    assert summary["ds_records"] == 1
    assert summary["strict_hns_ready"] == 3
    assert summary["needs_dane"] == 1
    assert summary["needs_fix"] == 2
    assert [item["stage"] for item in summary["compliance_stages"]] == list(COMPLIANCE_STAGES)
    assert summary["compliance_stage_counts"] == {
        "dane_verified": 0,
        "tlsa_gap": 1,
        "stale_tlsa": 0,
        "dnssec_broken": 0,
        "missing_glue": 1,
        "bootstrap_ready": 2,
        "resolver_fallback": 0,
        "service_blocked": 0,
        "non_actionable": 4,
    }
    compliance_stages = {item["stage"]: item for item in summary["compliance_stages"]}
    assert compliance_stages["tlsa_gap"]["filter"] == "stage:tlsa_gap"
    assert compliance_stages["tlsa_gap"]["filter_link"] == "names.html?filter=stage:tlsa_gap"
    assert "TLSA" in compliance_stages["tlsa_gap"]["definition"]
    next_actions = {item["key"]: item for item in summary["next_actions"]}
    assert next_actions["generate_tlsa"]["count"] == 1
    assert next_actions["generate_tlsa"]["stage"] == "tlsa_gap"
    assert next_actions["generate_tlsa"]["filter"] == "stage:tlsa_gap"
    assert next_actions["generate_tlsa"]["filter_link"] == "names.html?filter=stage:tlsa_gap"
    assert next_actions["generate_tlsa"]["generator_intent"] == "generate_tlsa"
    assert next_actions["fix_ns_glue"]["count"] == 1
    assert next_actions["fix_ns_glue"]["stage"] == "missing_glue"
    assert next_actions["fix_ns_glue"]["filter"] == "stage:missing_glue"
    assert next_actions["fix_ns_glue"]["generator_intent"] == "missing_glue"
    assert next_actions["plan_dnssec_dane"]["count"] == 2
    assert next_actions["plan_dnssec_dane"]["stage"] == "bootstrap_ready"
    assert summary["source_type"] == "fixture"
    assert summary["source_file_hash"]
    assert summary["provider_rules_version"] == 4
    assert summary["provider_rules_hash"]
    explainers = {item["key"]: item for item in summary["overview_explainers"]}
    assert explainers["direct_ip_records"]["filter_link"] == "names.html?filter=direct_ip_records"
    assert explainers["needs_dane"]["count"] == 1
    assert "matching HTTPS TLSA" in explainers["needs_dane"]["definition"]
    assert explainers["needs_fix"]["count"] == 2
    assert "examples" not in summary["broken"]
    assert {item["failure_reason"] for item in summary["broken"]["reasons"]} == set(FAILURE_REASONS)
    assert {item["ip"] for item in summary["top_resource_ips"]} >= {
        "198.51.100.2",
        "198.51.100.3",
        "203.0.113.10",
    }
    assert {item["nameserver"] for item in summary["top_nameservers"]} >= {
        "ns1.delegated",
        "ns1.external.example",
        "ns1.namebase.io",
    }
    assert any(item["ip"] == "194.50.5.27" for item in summary["known_hns_resolvers"])
    assert namebase_provider["ns_pattern"] == "suffix:namebase.io,suffix:parking.namebase.io"
    assert namebase_provider["ip_pattern"] == ""
    assert resource_ip_count == 5
    assert resource_ip_version == RESOURCE_IP_INDEX_VERSION
    assert "idx_resource_ip_ip_name" in resource_ip_indexes


def test_generate_site_writes_requested_artifacts(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    (out / "data/dane-pages/all").mkdir(parents=True)
    (out / "providers.html").write_text("old providers page", encoding="utf-8")
    (out / "faq.html").write_text("old faq page", encoding="utf-8")
    (out / "data/providers.json").write_text("{}", encoding="utf-8")
    (out / "data/faq_answers.json").write_text("[]", encoding="utf-8")
    (out / "data/dane-pages/all/page-1.json").write_text("{}", encoding="utf-8")
    (out / "data/unknown-old-file.json").write_text("{}", encoding="utf-8")
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=out)

    for relative in [
        "index.html",
        "names.html",
        "styles.css",
        "generator_handoff.js",
        "app.js",
        "data/summary.json",
        "data/manifest.json",
        "data/names-pages.json",
        "data/ip-addresses/198.51.100.2.json",
        "data/ip-addresses/203.0.113.10.json",
        "data/ip-addresses/2001%3Adb8%3A%3A10.json",
    ]:
        assert (out / relative).exists()
    assert stat.S_IMODE(out.stat().st_mode) == 0o755
    for relative in [
        "providers.html",
        "broken.html",
        "faq.html",
        "dane.html",
        "data/providers.json",
        "data/faq_answers.json",
        "data/broken.json",
        "data/classes.json",
        "data/names.json",
        "data/names.csv",
        "data/topology.sqlite.gz",
        "data/dane.json",
        "data/dane-pages.json",
        "data/dane-pages/all/page-1.json",
        "data/unknown-old-file.json",
        "classes.html",
    ]:
        assert not (out / relative).exists()

    manifest = json.loads((out / "data/manifest.json").read_text(encoding="utf-8"))
    manifest_artifacts = {item["path"]: item for item in manifest["artifacts"]}
    summary = json.loads((out / "data/summary.json").read_text(encoding="utf-8"))
    providers = summary["providers"]
    names_pages = json.loads((out / "data/names-pages.json").read_text(encoding="utf-8"))
    names_page_rows = json.loads((out / "data/names-pages/all/page-1.json").read_text(encoding="utf-8"))["rows"]
    provider_postings_page = json.loads(
        (
            out
            / "data"
            / names_pages["collections"]["provider:namebase/default"]["path_template"].replace("{page}", "1")
        ).read_text(encoding="utf-8")
    )
    delegated_ip_index = json.loads((out / "data/ip-addresses/198.51.100.2.json").read_text(encoding="utf-8"))
    direct_ip_index = json.loads((out / "data/ip-addresses/203.0.113.10.json").read_text(encoding="utf-8"))
    direct_ipv6_index = json.loads(
        (out / "data/ip-addresses/2001%3Adb8%3A%3A10.json").read_text(encoding="utf-8")
    )
    delegated_ip_page = json.loads(
        (out / "data" / delegated_ip_index["path_template"].replace("{page}", "1")).read_text(encoding="utf-8")
    )
    direct_ip_page = json.loads(
        (out / "data" / direct_ip_index["path_template"].replace("{page}", "1")).read_text(encoding="utf-8")
    )
    direct_ipv6_page = json.loads(
        (out / "data" / direct_ipv6_index["path_template"].replace("{page}", "1")).read_text(encoding="utf-8")
    )
    names_page_names = [row["name"] for row in names_page_rows]
    direct_row = next(row for row in names_page_rows if row["name"] == "direct")
    namebase_provider = next(item for item in providers if item["provider_key"] == "namebase/default")
    assert manifest["manifest_version"] == 1
    assert manifest["snapshot"]["height"] == 123456
    assert manifest["summary"]["total_names"] == 9
    assert manifest["export"]["names_limit"] == 0
    assert manifest["export"]["names_total_count"] == 9
    assert manifest["export"]["names_exported_count"] == 9
    assert manifest["export"]["names_truncated"] is False
    assert manifest["export"]["download_artifacts_included"] is False
    assert "summary.json" in manifest_artifacts
    assert "faq_answers.json" not in manifest_artifacts
    assert "providers.json" not in manifest_artifacts
    assert "classes.json" not in manifest_artifacts
    assert "broken.json" not in manifest_artifacts
    assert "names-pages.json" in manifest_artifacts
    assert "names-pages/all/page-1.json" in manifest_artifacts
    assert "ip-addresses/198.51.100.2.json" in manifest_artifacts
    assert "ip-addresses/198.51.100.2/page-1.json" in manifest_artifacts
    assert "ip-addresses/203.0.113.10.json" in manifest_artifacts
    assert "ip-addresses/203.0.113.10/page-1.json" in manifest_artifacts
    assert "ip-addresses/2001%3Adb8%3A%3A10.json" in manifest_artifacts
    assert "ip-addresses/2001%3Adb8%3A%3A10/page-1.json" in manifest_artifacts
    assert "dane-pages.json" not in manifest_artifacts
    assert "names.json" not in manifest_artifacts
    assert "names.csv" not in manifest_artifacts
    assert "topology.sqlite.gz" not in manifest_artifacts
    assert names_pages["collections"]["all"]["row_count"] == 9
    assert names_pages["collections"]["all"]["page_count"] == 1
    assert names_pages["collections"]["all"]["row_source"] == "rows"
    assert names_pages["row_store"]["path_template"] == names_pages["collections"]["all"]["path_template"]
    assert names_page_names == sorted(names_page_names)
    assert "dane_rows" not in names_pages["collections"]
    assert "missing_glue" not in names_pages["collections"]
    assert "stale_tlsa" not in names_pages["collections"]
    assert "dane_working" not in names_pages["collections"]
    assert "doh_fallback_required" not in names_pages["collections"]
    assert "provider_type:self_hosted" not in names_pages["collections"]
    assert names_pages["collections"]["ds_records"]["row_count"] == 1
    assert names_pages["collections"]["strict_hns_ready"]["row_count"] == 3
    assert names_pages["collections"]["needs_dane"]["row_count"] == 1
    assert names_pages["collections"]["needs_fix"]["row_count"] == 2
    assert names_pages["collections"]["stage:tlsa_gap"]["row_count"] == 1
    assert names_pages["collections"]["stage:missing_glue"]["row_count"] == 1
    assert names_pages["collections"]["stage:bootstrap_ready"]["row_count"] == 2
    assert names_pages["collections"]["stage:non_actionable"]["row_count"] == 4
    assert names_pages["collections"]["stage:bootstrap_ready"]["row_source"] == "postings"
    assert names_pages["collections"]["provider:namebase/default"]["row_count"] == 1
    assert names_pages["collections"]["provider:namebase/default"]["row_source"] == "postings"
    assert provider_postings_page["row_encoding"] == "ordinal"
    assert provider_postings_page["rows"] == [6]
    assert "namebase__slash__default" in names_pages["collections"]["provider:namebase/default"]["path_template"]
    assert (out / "data" / names_pages["collections"]["provider:namebase/default"]["path_template"].replace("{page}", "1")).exists()
    assert "tlsa_status" in names_page_rows[0]
    assert "compliance_stage" in names_page_rows[0]
    assert "provider_type" in names_page_rows[0]
    assert "checked_at" in names_page_rows[0]
    assert direct_row["compliance_stage"] == "bootstrap_ready"
    assert direct_row["resource_version"] == 0
    assert direct_row["raw_size"] > 0
    assert direct_row["resource_hash"]
    assert direct_row["last_seen_height"] == 123456
    assert delegated_ip_index["ip"] == "198.51.100.2"
    assert delegated_ip_index["row_count"] == 1
    assert delegated_ip_index["page_count"] == 1
    assert delegated_ip_index["row_detail"] == "ip_matches"
    assert delegated_ip_index["columns"] == ["name", "field_mask"]
    assert delegated_ip_index["field_map"] == {"1": "GLUE4", "2": "GLUE6", "4": "SYNTH4", "8": "SYNTH6"}
    assert delegated_ip_index["field_counts"] == {"GLUE4": 1}
    assert delegated_ip_index["default_field_mask"] == 1
    assert delegated_ip_page["row_encoding"] == "name"
    assert delegated_ip_page["field_mask"] == 1
    assert delegated_ip_page["rows"] == ["delegated"]
    assert direct_ip_index["ip"] == "203.0.113.10"
    assert direct_ip_index["row_count"] == 1
    assert direct_ip_index["page_count"] == 1
    assert direct_ip_index["row_detail"] == "ip_matches"
    assert direct_ip_index["columns"] == ["name", "field_mask"]
    assert direct_ip_index["field_counts"] == {"SYNTH4": 1}
    assert direct_ip_index["default_field_mask"] == 4
    assert direct_ip_page["row_encoding"] == "name"
    assert direct_ip_page["field_mask"] == 4
    assert direct_ip_page["rows"] == ["direct"]
    assert direct_ipv6_index["ip"] == "2001:db8::10"
    assert direct_ipv6_index["field_counts"] == {"SYNTH6": 1}
    assert direct_ipv6_index["default_field_mask"] == 8
    assert direct_ipv6_page["row_encoding"] == "name"
    assert direct_ipv6_page["field_mask"] == 8
    assert direct_ipv6_page["rows"] == ["direct"]
    assert "classes" in summary
    assert "broken" in summary
    assert "top_resource_ips" in summary
    assert "top_nameservers" in summary
    assert "known_hns_resolvers" in summary
    assert "examples" not in summary["broken"]
    assert "next_actions" in summary
    assert {item["filter"] for item in summary["next_actions"]} <= set(names_pages["collections"])
    assert {item["key"] for item in summary["next_actions"]} == {
        "generate_tlsa",
        "fix_ns_glue",
        "plan_dnssec_dane",
    }
    assert namebase_provider["ns_pattern"] == "suffix:namebase.io,suffix:parking.namebase.io"

    checks = validate_release(db_path=db_path, public_dir=out)
    assert release_is_valid(checks), [check for check in checks if not check.ok]

    public_checks = validate_public_release(public_dir=out)
    assert release_is_valid(public_checks), [check for check in public_checks if not check.ok]


def test_certificate_expired_stage_overrides_tlsa_gap(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        upsert_live_status(
            conn,
            LiveStatus(
                name="secure",
                dns_reachable="reachable",
                dnssec_status="unknown",
                tlsa_status="missing",
                dane_status="unknown",
                https_status="tls_unverified",
                strict_hns_status="fallback_only",
                doh_fallback_status="required",
                failure_reason="certificate_expired",
                checked_at="2026-07-06T00:00:00Z",
                next_check_at="2026-07-13T00:00:00Z",
            ),
        )
        generate_site(conn, db_path=db_path, out_dir=out)

    summary = json.loads((out / "data/summary.json").read_text(encoding="utf-8"))
    rows = json.loads((out / "data/names-pages/all/page-1.json").read_text(encoding="utf-8"))["rows"]
    secure = next(row for row in rows if row["name"] == "secure")

    assert secure["failure_reason"] == "certificate_expired"
    assert secure["compliance_stage"] == "service_blocked"
    assert summary["compliance_stage_counts"]["service_blocked"] == 1


def test_generate_site_requires_current_resource_ip_index_and_preserves_existing_output(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=out)
        sentinel = out / "existing-release-marker.txt"
        sentinel.write_text("existing release", encoding="utf-8")
        conn.execute("DELETE FROM snapshot_meta WHERE key = ?", ("resource_ip_index_version",))
        conn.commit()

        try:
            generate_site(conn, db_path=db_path, out_dir=out)
        except RuntimeError as exc:
            assert "rebuild-resource-ip" in str(exc)
        else:
            raise AssertionError("expected stale resource_ip guard")

    assert sentinel.read_text(encoding="utf-8") == "existing release"
    assert not list(tmp_path.glob(".public.tmp-*"))


def test_generate_site_can_include_download_artifacts(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=out, include_downloads=True)

    manifest = json.loads((out / "data/manifest.json").read_text(encoding="utf-8"))
    manifest_artifacts = {item["path"]: item for item in manifest["artifacts"]}

    assert manifest["export"]["download_artifacts_included"] is True
    assert (out / "data/names.json").exists()
    assert (out / "data/names.csv").exists()
    assert (out / "data/topology.sqlite.gz").exists()
    assert "names.json" in manifest_artifacts
    assert "names.csv" in manifest_artifacts
    assert "topology.sqlite.gz" in manifest_artifacts

    checks = validate_release(db_path=db_path, public_dir=out)
    assert release_is_valid(checks), [check for check in checks if not check.ok]


def test_generate_site_records_limited_names_export_counts(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=out, names_limit=3)

    manifest = json.loads((out / "data/manifest.json").read_text(encoding="utf-8"))
    names_pages = json.loads((out / "data/names-pages.json").read_text(encoding="utf-8"))
    names_page_rows = json.loads((out / "data/names-pages/all/page-1.json").read_text(encoding="utf-8"))["rows"]

    assert manifest["export"]["names_limit"] == 3
    assert manifest["export"]["names_total_count"] == 9
    assert manifest["export"]["names_exported_count"] == 3
    assert manifest["export"]["names_truncated"] is True
    assert names_pages["collections"]["all"]["row_count"] == 3
    assert len(names_page_rows) == 3
    assert not (out / "data/names.json").exists()
    assert not (out / "data/names.csv").exists()

    checks = validate_release(db_path=db_path, public_dir=out)
    assert release_is_valid(checks), [check for check in checks if not check.ok]


def test_compact_names_pages_include_generator_handoff_fields(tmp_path, monkeypatch):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    monkeypatch.setattr("hns_topology.exporter.DETAILED_NAME_COLLECTION_ROW_LIMIT", 0)
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=out)

    names_pages = json.loads((out / "data/names-pages.json").read_text(encoding="utf-8"))
    collection = names_pages["collections"]["all"]
    page = json.loads((out / "data" / collection["path_template"].replace("{page}", "1")).read_text(encoding="utf-8"))
    columns = page["columns"]
    rows = [dict(zip(columns, row, strict=True)) for row in page["rows"]]
    delegated = next(row for row in rows if row["name"] == "delegated")
    direct = next(row for row in rows if row["name"] == "direct")

    assert collection["row_detail"] == "compact"
    for key in (
        "first_ns",
        "first_glue4",
        "first_glue6",
        "first_synth4",
        "first_synth6",
        "compliance_stage",
        "https_status",
        "strict_hns_status",
        "doh_fallback_status",
        "raw_size",
        "resource_version",
        "resource_hash",
        "last_seen_height",
        "updated_at",
        "checked_at",
    ):
        assert key in columns
    assert delegated["first_ns"] == "ns1.delegated"
    assert delegated["first_glue4"] == "198.51.100.2"
    assert delegated["compliance_stage"] == "bootstrap_ready"
    assert direct["first_synth4"] == "203.0.113.10"
    assert direct["compliance_stage"] == "bootstrap_ready"
    assert direct["resource_version"] == 0
    assert direct["raw_size"] > 0


def test_release_validator_catches_missing_artifacts(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=out)

    (out / "data/summary.json").unlink()
    checks = validate_release(db_path=db_path, public_dir=out)

    assert not release_is_valid(checks)
    failed = {check.name: check.detail for check in checks if not check.ok}
    assert "required_public_files" in failed


def test_release_validator_catches_manifest_checksum_mismatch(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=out)

    (out / "data/names-pages.json").write_text("{}\n", encoding="utf-8")
    checks = validate_release(db_path=db_path, public_dir=out)

    assert not release_is_valid(checks)
    failed = {check.name: check.detail for check in checks if not check.ok}
    assert "manifest_artifacts" in failed
    assert "names-pages.json" in failed["manifest_artifacts"]


def test_release_validator_catches_manifest_export_count_mismatch(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=out, names_limit=3)

    manifest_path = out / "data/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["export"]["names_exported_count"] = 2
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    checks = validate_release(db_path=db_path, public_dir=out)

    assert not release_is_valid(checks)
    failed = {check.name: check.detail for check in checks if not check.ok}
    assert "manifest_export_counts" in failed
    assert "names_exported_count=2!=3" in failed["manifest_export_counts"]


def test_public_validator_uses_summary_metadata(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=out)

    summary_path = out / "data/summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["last_indexed_height"] = 1
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    checks = validate_public_release(public_dir=out)

    assert not release_is_valid(checks)
    failed = {check.name: check.detail for check in checks if not check.ok}
    assert "manifest_artifacts" in failed
    assert "manifest_snapshot" in failed


def test_release_validator_enforces_live_check_gate(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=out)

    checks = validate_release(db_path=db_path, public_dir=out, require_live_checks=True)

    assert not release_is_valid(checks)
    failed = {check.name: check.detail for check in checks if not check.ok}
    assert "live_status_present" in failed
    assert "live_check_timestamps" in failed


def test_release_validator_requires_live_check_run_metadata(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        upsert_live_status(
            conn,
            LiveStatus(
                name="direct",
                dns_reachable="reachable",
                dnssec_status="not_delegated",
                tlsa_status="missing",
                dane_status="unknown",
                https_status="working",
                strict_hns_status="working",
                doh_fallback_status="not_required",
                failure_reason=None,
                checked_at="2026-01-01T00:00:00Z",
                next_check_at="2026-01-08T00:00:00Z",
            ),
        )
        set_meta(conn, "live_check_started_at", "2026-01-01T00:00:00Z")
        set_meta(conn, "live_check_finished_at", "2026-01-01T00:01:00Z")
        conn.commit()
        generate_site(conn, db_path=db_path, out_dir=out)

    checks = validate_release(db_path=db_path, public_dir=out, require_live_checks=True)

    assert not release_is_valid(checks)
    failed = {check.name: check.detail for check in checks if not check.ok}
    assert "live_check_config" in failed
    assert "live_check_counts" in failed


def test_release_validators_enforce_min_indexed_height(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=out)

    db_checks = validate_release(
        db_path=db_path,
        public_dir=out,
        min_indexed_height=300000,
    )
    public_checks = validate_public_release(
        public_dir=out,
        min_indexed_height=300000,
    )

    assert not release_is_valid(db_checks)
    assert not release_is_valid(public_checks)
    assert "minimum_indexed_height" in {check.name for check in db_checks if not check.ok}
    assert "minimum_indexed_height" in {check.name for check in public_checks if not check.ok}


def test_jsonl_bootstrap_streams_names_and_records_provenance(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        count = bootstrap_from_jsonl(conn, jsonl_path=JSONL_FIXTURE, rules=rules)
        summary = build_summary(conn)

    assert count == 2
    assert summary["active_names"] == 2
    assert summary["direct_ip_records"] == 1
    assert summary["synth_nameserver_records"] == 1
    assert summary["delegated_no_glue"] == 1
    assert summary["source_type"] == "jsonl"
    assert summary["source_file_hash"]
    assert summary["hsd_version"] == "fixture-jsonl"


def test_compact_jsonl_bootstrap_uses_summarized_rows(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    jsonl_path = tmp_path / "compact.jsonl"
    rows = [
        {
            "snapshot_meta": {
                "height": 222222,
                "tip_hash": "compact-tip",
                "chain": "main",
                "hsd_version": "fixture-compact",
                "source": "hsd_chain_tree_compact",
                "export_format": "compact_summary_v1",
            }
        },
        {
            "compact_name": {
                "name": "direct",
                "name_hash": "hash-direct",
                "state": "CLOSED",
                "renewal_height": 221000,
                "resource_hash": "resource-direct",
                "record_types": ["SYNTH4"],
                "synth4": ["203.0.113.10"],
                "raw_size": 5,
            }
        },
        {
            "compact_name": {
                "name": "delegated",
                "name_hash": "hash-delegated",
                "state": "CLOSED",
                "renewal_height": 221000,
                "resource_hash": "resource-delegated",
                "record_types": ["NS"],
                "ns_names": ["ns1.example."],
                "raw_size": 8,
            }
        },
        {
            "block_history": {
                "height": 222221,
                "block_hash": "previous-block",
                "changed_names": ["direct", "delegated"],
            }
        },
        {
            "compact_name": {
                "name": "expired",
                "name_hash": "hash-expired",
                "state": "CLOSED",
                "renewal_height": 1,
                "expired": True,
                "resource_hash": "resource-expired",
                "record_types": ["SYNTH4"],
                "synth4": ["203.0.113.11"],
                "raw_size": 5,
            }
        },
    ]
    jsonl_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        count = bootstrap_from_jsonl(conn, jsonl_path=jsonl_path, rules=rules, batch_size=1)
        summary = build_summary(conn)
        export_format = conn.execute(
            "SELECT value FROM snapshot_meta WHERE key = 'source_jsonl_format'"
        ).fetchone()
        delegated = conn.execute(
            "SELECT onchain_class FROM names WHERE name = 'delegated'"
        ).fetchone()
        history = conn.execute(
            "SELECT block_hash, changed_names FROM block_history WHERE height = 222221"
        ).fetchone()

    assert count == 3
    assert summary["active_names"] == 2
    assert summary["expired_names"] == 1
    assert summary["direct_ip_records"] == 1
    assert summary["synth_nameserver_records"] == 1
    assert summary["delegated_no_glue"] == 1
    assert summary["last_indexed_height"] == 222222
    assert summary["hsd_version"] == "fixture-compact"
    assert export_format["value"] == "compact_summary_v1"
    assert delegated["onchain_class"] == "DELEGATED_NO_GLUE"
    assert history["block_hash"] == "previous-block"
    assert json.loads(history["changed_names"]) == ["delegated", "direct"]


def test_hsd_bootstrap_requires_limit_or_explicit_unpaginated_opt_in(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    client = FakeBootstrapHsdClient()

    with connect(db_path) as conn:
        try:
            bootstrap_from_hsd(conn, client=client, rules=rules)
        except UnpaginatedGetNamesError:
            pass
        else:
            raise AssertionError("expected unpaginated getnames guard")

    assert client.get_names_calls == 0


def test_hsd_bootstrap_smoke_limit_records_provenance(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    client = FakeBootstrapHsdClient()

    with connect(db_path) as conn:
        count = bootstrap_from_hsd(conn, client=client, rules=rules, limit=1)
        summary = build_summary(conn)

    assert count == 1
    assert client.get_names_calls == 1
    assert summary["source_type"] == "hsd_rpc"
    assert summary["source_rpc_url"] == "http://127.0.0.1:12037"


def test_reclassify_existing_names_applies_new_provider_rules(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    fixture_path = tmp_path / "bulk_fixture.json"
    previous_rules_path = tmp_path / "previous_rules.json"
    fixture_path.write_text(
        json.dumps(
            {
                "chain": "fixture",
                "height": 1,
                "tip_hash": "tip",
                "names": [
                    {
                        "name": "bulk",
                        "nameHash": "hash-bulk",
                        "state": "CLOSED",
                        "renewal": 1,
                        "resource": {
                            "records": [
                                {"type": "NS", "ns": "ns1.bulk."},
                                {"type": "GLUE4", "ns": "ns1.bulk.", "address": "44.231.6.183"},
                            ]
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    previous_rules_path.write_text(
        json.dumps(
            {
                "version": 1,
                "default_provider_key": "unknown/custom",
                "rules": [
                    {
                        "provider_key": "self-hosted",
                        "provider_type": "self_hosted",
                        "priority": 30,
                        "self_hosted": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    previous_rules = ProviderRules.from_file(previous_rules_path)
    current_rules = ProviderRules.from_file("configs/provider_rules.json")

    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=fixture_path, rules=previous_rules)
        before = conn.execute(
            "SELECT provider_guess, onchain_class FROM names WHERE name = 'bulk'"
        ).fetchone()
        result = reclassify_existing_names(conn, rules=current_rules, progress_interval=0)
        after = conn.execute(
            "SELECT provider_guess, onchain_class FROM names WHERE name = 'bulk'"
        ).fetchone()
        provider = conn.execute(
            "SELECT provider_type, names_count FROM provider_summary WHERE provider_key = 'bulk/default'"
        ).fetchone()

    assert before["provider_guess"] == "self-hosted"
    assert before["onchain_class"] == "DELEGATED_WITH_GLUE"
    assert result["scanned"] == 1
    assert result["changed"] == 1
    assert after["provider_guess"] == "bulk/default"
    assert after["onchain_class"] == "PARKED_OR_DEFAULT"
    assert provider["provider_type"] == "default_parking"
    assert provider["names_count"] == 1


def test_extract_changed_name_refs_decodes_raw_names_and_resolves_hashes():
    update_hash = "11" * 32
    open_hash = "22" * 32
    block = {
        "tx": [
            {
                "vout": [
                    {
                        "covenant": {
                            "action": "OPEN",
                            "items": [open_hash, "00000000", "646972656374"],
                        }
                    },
                    {
                        "covenant": {
                            "action": "UPDATE",
                            "items": [update_hash, "01000000", "00"],
                        }
                    },
                ]
            }
        ]
    }

    extraction = extract_changed_name_refs_from_block(
        block,
        name_by_hash=lambda name_hash: "resolved" if name_hash == update_hash else None,
    )

    assert extraction.names == ["direct", "resolved"]
    assert extraction.name_hashes == [update_hash, open_hash]
    assert extraction.unresolved_name_hashes == []
    assert extraction.name_covenant_count == 2
    assert extraction.non_dict_tx_count == 0


def test_extract_changed_name_refs_reports_unresolved_hashes():
    update_hash = "11" * 32
    block = {
        "tx": [
            {
                "vout": [
                    {
                        "covenant": {
                            "action": "UPDATE",
                            "items": [update_hash, "01000000", "00"],
                        }
                    }
                ]
            }
        ]
    }

    extraction = extract_changed_name_refs_from_block(block, name_by_hash=lambda _: None)

    assert extraction.names == []
    assert extraction.name_hashes == [update_hash]
    assert extraction.unresolved_name_hashes == [update_hash]
    assert extraction.name_covenant_count == 1
    assert extraction.non_dict_tx_count == 0


def test_reorg_rollback_restores_previous_compact_rows(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    update_height = 123457
    client = FakeHsdClient(
        block_hashes={update_height: "old-hash"},
        resources={
            "direct": {
                "records": [
                    {"type": "NS", "ns": "ns1.external.example."},
                ]
            }
        },
    )
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        index_changed_names(
            conn,
            client=client,
            rules=rules,
            changed_names=["direct"],
            height=update_height,
            block_hash="old-hash",
        )
        changed = conn.execute("SELECT onchain_class FROM names WHERE name = 'direct'").fetchone()
        changed_resource = conn.execute(
            "SELECT ns_names, synth4 FROM resource_summary WHERE name = 'direct'"
        ).fetchone()

        assert changed["onchain_class"] == "DELEGATED_NO_GLUE"
        assert json.loads(changed_resource["ns_names"]) == ["ns1.external.example"]
        assert json.loads(changed_resource["synth4"]) == []

        reorg_client = FakeHsdClient(block_hashes={update_height: "new-hash"}, resources={})
        mismatch = find_reorg_mismatch(conn, client=reorg_client)
        assert mismatch == {
            "height": update_height,
            "stored_hash": "old-hash",
            "current_hash": "new-hash",
        }

        rollback = rollback_reorg(conn, rules=rules, rollback_height=update_height)
        restored = conn.execute("SELECT onchain_class FROM names WHERE name = 'direct'").fetchone()
        restored_resource = conn.execute(
            "SELECT ns_names, synth4 FROM resource_summary WHERE name = 'direct'"
        ).fetchone()
        remaining_history = conn.execute("SELECT COUNT(*) FROM block_history").fetchone()[0]

    assert rollback["names_restored"] == 1
    assert restored["onchain_class"] == "DIRECT_SYNTH"
    assert json.loads(restored_resource["ns_names"]) == []
    assert json.loads(restored_resource["synth4"]) == ["203.0.113.10"]
    assert remaining_history == 0

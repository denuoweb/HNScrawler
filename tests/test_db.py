import sqlite3

from hns_topology.db import clean_legacy_schema, connect, init_db, recompute_provider_summary


def test_init_db_migrates_previous_schema_and_backfills_resource_flags(tmp_path):
    db_path = tmp_path / "previous.sqlite"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE snapshot_meta (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );

            CREATE TABLE names (
              name TEXT PRIMARY KEY,
              name_hash TEXT NOT NULL,
              expired INTEGER DEFAULT 0,
              record_types TEXT,
              onchain_class TEXT,
              provider_guess TEXT
            );

            CREATE TABLE resource_summary (
              name TEXT PRIMARY KEY,
              ns_names TEXT,
              glue4 TEXT,
              glue6 TEXT,
              synth4 TEXT,
              synth6 TEXT,
              ds_records TEXT,
              tlsa_records TEXT,
              tlsa_cert_not_valid_after TEXT,
              tlsa_cert_expired INTEGER DEFAULT 0,
              raw_size INTEGER,
              resource_hash TEXT
            );

            CREATE TABLE live_status (
              name TEXT PRIMARY KEY,
              strict_hns_status TEXT,
              dane_status TEXT
            );

            CREATE TABLE provider_summary (
              provider_key TEXT PRIMARY KEY,
              names_count INTEGER,
              likely_website_count INTEGER,
              updated_at TEXT
            );

            CREATE TABLE dns_evidence (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              qname TEXT NOT NULL,
              rrtype TEXT NOT NULL,
              status TEXT NOT NULL,
              flags TEXT,
              answer_json TEXT NOT NULL DEFAULT '[]',
              captured_at TEXT NOT NULL
            );

            CREATE TABLE changed_name_rollbacks (
              height INTEGER NOT NULL,
              name TEXT NOT NULL,
              previous_resource_hash TEXT,
              previous_classification TEXT,
              previous_live_status TEXT,
              block_hash_at_height TEXT NOT NULL,
              captured_at TEXT NOT NULL,
              PRIMARY KEY(height, name)
            );
            """
        )
        conn.execute(
            """
            INSERT INTO names(name, name_hash, expired, record_types, onchain_class, provider_guess)
            VALUES('previous', 'hash-previous', 0, '["TXT"]', 'UNKNOWN_OTHER', 'unknown/custom')
            """
        )
        conn.execute(
            """
            INSERT INTO resource_summary(
              name, ns_names, glue4, glue6, synth4, synth6, ds_records, tlsa_records,
              tlsa_cert_not_valid_after, tlsa_cert_expired, raw_size, resource_hash
            )
            VALUES(
              'previous', '["ns1.previous"]', '["203.0.113.7"]', '[]', '[]', '[]',
              '[{"digest": "abc"}]', '[]', NULL, 0, 123, 'resource-hash'
            )
            """
        )
        conn.execute(
            """
            INSERT INTO live_status(name, strict_hns_status, dane_status)
            VALUES('previous', 'working', 'valid')
            """
        )
        conn.execute(
            """
            INSERT INTO dns_evidence(
              name, qname, rrtype, status, flags, answer_json, captured_at
            ) VALUES(
              'previous', '_443._tcp.previous.', 'TLSA', 'ok', 'QR AA',
              '["_443._tcp.previous. 300 IN TLSA 3 1 1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]',
              '2026-01-01T00:00:00Z'
            )
            """
        )

    with connect(db_path) as conn:
        init_db(conn)
        legacy_columns_before = {
            row["name"] for row in conn.execute("PRAGMA table_info(resource_summary)")
        }
        assert "tlsa_records" in legacy_columns_before
        assert clean_legacy_schema(conn) is True
        assert clean_legacy_schema(conn) is False
        tables = {
            table: {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            for table in (
                "names",
                "resource_summary",
                "provider_summary",
                "dns_evidence",
                "tlsa_evidence_summary",
                "changed_name_rollbacks",
            )
        }
        table_names = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        flags = conn.execute(
            """
            SELECT has_ds, has_ns, has_glue, has_synth, has_txt,
                   resource_version
            FROM resource_summary
            WHERE name = 'previous'
            """
        ).fetchone()
        recompute_provider_summary(
            conn,
            {"unknown/custom": "unknown"},
            "2026-01-01T00:00:00Z",
            {"unknown/custom": {"ns_pattern": "manual", "ip_pattern": "cidr:203.0.113.0/24"}},
        )
        provider = conn.execute(
            """
            SELECT provider_type, ns_pattern, ip_pattern, names_count, likely_website_count
            FROM provider_summary
            WHERE provider_key = 'unknown/custom'
            """
        ).fetchone()
        tlsa_summary = conn.execute(
            """
            SELECT has_tlsa, tlsa_records, tlsa_owners, observed_at, checked_at
            FROM tlsa_evidence_summary
            WHERE name = 'previous'
            """
        ).fetchone()

    assert {"state", "renewal_height", "last_seen_height", "updated_at"} <= tables["names"]
    assert {
        "has_ds",
        "has_ns",
        "has_glue",
        "has_synth",
        "has_txt",
        "resource_version",
    } <= tables["resource_summary"]
    assert {"tlsa_records", "tlsa_cert_not_valid_after", "tlsa_cert_expired"}.isdisjoint(
        tables["resource_summary"]
    )
    assert {"provider_type", "ns_pattern", "ip_pattern"} <= tables["provider_summary"]
    assert {"server", "source", "source_id", "authority_json", "additional_json"} <= tables[
        "dns_evidence"
    ]
    assert {"has_tlsa", "tlsa_records", "tlsa_owners", "observed_at", "checked_at"} <= tables[
        "tlsa_evidence_summary"
    ]
    assert "previous_live_status" not in tables["changed_name_rollbacks"]
    assert {"live_status", "host_candidates", "host_live_status", "browser_evidence"}.isdisjoint(
        table_names
    )
    assert dict(flags) == {
        "has_ds": 1,
        "has_ns": 1,
        "has_glue": 1,
        "has_synth": 0,
        "has_txt": 1,
        "resource_version": None,
    }
    assert dict(provider) == {
        "provider_type": "unknown",
        "ns_pattern": "manual",
        "ip_pattern": "cidr:203.0.113.0/24",
        "names_count": 1,
        "likely_website_count": 1,
    }
    assert tlsa_summary["has_tlsa"] == 1
    assert '"owner":"_443._tcp.previous."' in tlsa_summary["tlsa_records"]
    assert tlsa_summary["tlsa_owners"] == '["_443._tcp.previous."]'
    assert tlsa_summary["observed_at"] == "2026-01-01T00:00:00Z"
    assert tlsa_summary["checked_at"] == "2026-01-01T00:00:00Z"

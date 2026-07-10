from __future__ import annotations

import argparse
import json
import re
import sqlite3
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .compliance import compliance_stage_case
from .db import parse_json_columns
from .ns_handoff import (
    NS_HANDOFF_COLUMNS,
    NS_HANDOFF_TABLE,
    drop_temp_ns_handoff_table,
    prepare_temp_ns_handoff_table,
)

NAME_RE = re.compile(r"^[a-z0-9-]{1,63}$")
JSON_COLUMNS = (
    "record_types",
    "ns_names",
    "glue4",
    "glue6",
    "synth4",
    "synth6",
    "ds_records",
    "tlsa_records",
    "tlsa_owners",
)


def _dns_evidence_path_sql() -> str:
    return """
      CASE WHEN EXISTS(
        SELECT 1
        FROM dns_evidence de
        WHERE de.name = n.name
      ) THEN 'dns-evidence/' || n.name || '.json' ELSE NULL END AS dns_evidence_path
    """


def normalize_name(value: str) -> str:
    name = value.strip().lower()
    for prefix in ("hns://", "https://", "http://"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    name = name.split("/", 1)[0].split(".", 1)[0].strip()
    return name


def lookup_name(db_path: str | Path, name: str) -> dict:
    normalized = normalize_name(name)
    if not NAME_RE.fullmatch(normalized):
        return {"found": False, "query": name, "normalized": normalized, "error": "invalid_name"}

    uri = f"file:{Path(db_path).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        prepare_temp_ns_handoff_table(conn, "SELECT ? AS name", (normalized,))
        compliance_stage_sql = compliance_stage_case(
            expired="n.expired",
            provider_type="ps.provider_type",
            has_ds="rs.has_ds",
            has_ns="rs.has_ns",
            has_glue="rs.has_glue",
            has_synth="rs.has_synth",
            has_tlsa="COALESCE(tes.has_tlsa, 0)",
        )
        try:
            row = conn.execute(
                f"""
                SELECT
                  n.name, n.state, n.expired, n.onchain_class, n.provider_guess,
                  COALESCE(ps.provider_type, 'unknown') AS provider_type, n.record_types,
                  rs.ns_names, rs.glue4, rs.glue6, rs.synth4, rs.synth6,
                  rs.ds_records, COALESCE(tes.tlsa_records, '[]') AS tlsa_records,
                  COALESCE(tes.tlsa_owners, '[]') AS tlsa_owners,
                  COALESCE(tes.has_tlsa, 0) AS has_tlsa,
                  tes.observed_at AS tlsa_observed_at, tes.checked_at AS tlsa_checked_at,
                  rs.tlsa_cert_not_valid_after, COALESCE(rs.tlsa_cert_expired, 0) AS tlsa_cert_expired,
                  rs.has_ds,
                  {_ns_handoff_select_columns()},
                  rs.raw_size, rs.resource_version, rs.resource_hash, n.last_seen_height, n.updated_at,
                  {_dns_evidence_path_sql()},
                  {compliance_stage_sql} AS compliance_stage
                FROM names n
                JOIN resource_summary rs ON rs.name = n.name
                LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
                LEFT JOIN tlsa_evidence_summary tes ON tes.name = n.name
                LEFT JOIN {NS_HANDOFF_TABLE} enh ON enh.name = n.name
                WHERE n.name = ?
                LIMIT 1
                """,
                (normalized,),
            ).fetchone()
        finally:
            drop_temp_ns_handoff_table(conn)
        meta = {
            item["key"]: item["value"]
            for item in conn.execute(
                """
                SELECT key, value
                FROM snapshot_meta
                WHERE key IN ('last_indexed_height', 'generated_at')
                """
            )
        }

    if row is None:
        return {
            "found": False,
            "query": name,
            "normalized": normalized,
            "snapshot": meta,
        }
    return {
        "found": True,
        "query": name,
        "normalized": normalized,
        "snapshot": meta,
        "row": _lookup_row(row),
    }


def _lookup_row(row: sqlite3.Row) -> dict:
    parsed = parse_json_columns(dict(row), JSON_COLUMNS)
    if "has_tlsa" in parsed:
        parsed["has_tlsa"] = bool(parsed["has_tlsa"])
    if "tlsa_cert_expired" in parsed:
        parsed["tlsa_cert_expired"] = bool(parsed["tlsa_cert_expired"])
    return parsed


def _ns_handoff_select_columns() -> str:
    return ",\n                  ".join(f"enh.{column}" for column in NS_HANDOFF_COLUMNS)


class LookupHandler(BaseHTTPRequestHandler):
    db_path: Path

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/name", "/hns-topology/api/name"}:
            self._handle_name(parsed.query)
            return
        self._json_response({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)

    def _handle_name(self, query_string: str) -> None:
        params = parse_qs(query_string)
        query = (params.get("name") or [""])[0]
        if not query:
            self._json_response({"found": False, "error": "missing_name"}, status=HTTPStatus.BAD_REQUEST)
            return

        try:
            result = lookup_name(self.db_path, query)
        except sqlite3.Error as exc:
            self._json_response(
                {"found": False, "error": "database_error", "detail": type(exc).__name__},
                status=HTTPStatus.SERVICE_UNAVAILABLE,
            )
            return

        status = HTTPStatus.OK
        if result.get("error") == "invalid_name":
            status = HTTPStatus.BAD_REQUEST
        self._json_response(result, status=status)

    def log_message(self, format: str, *args) -> None:
        return

    def _json_response(self, payload: dict, *, status: HTTPStatus) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "public, max-age=300")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def run_server(*, db_path: str | Path, host: str, port: int) -> None:
    handler = type("ConfiguredLookupHandler", (LookupHandler,), {"db_path": Path(db_path)})
    server = ThreadingHTTPServer((host, port), handler)
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hns-topology-lookup-api")
    parser.add_argument("--db", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args(argv)
    run_server(db_path=args.db, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

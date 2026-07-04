from __future__ import annotations

import argparse
import json
import math
import re
import sqlite3
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .db import parse_json_columns

NAME_RE = re.compile(r"^[a-z0-9-]{1,63}$")
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
IPV6_RE = re.compile(r"^[0-9a-f:.]+$")
JSON_COLUMNS = ("record_types", "ns_names", "glue4", "glue6", "synth4", "synth6", "ds_records")
IP_LOOKUP_COLUMNS = ("name", "fields")
DEFAULT_PAGE_SIZE = 1000


def normalize_name(value: str) -> str:
    name = value.strip().lower()
    for prefix in ("hns://", "https://", "http://"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    name = name.split("/", 1)[0].split(".", 1)[0].strip()
    return name


def normalize_ip(value: str) -> str:
    ip = value.strip().lower()
    if IPV4_RE.fullmatch(ip):
        parts = ip.split(".")
        if all(int(part) <= 255 for part in parts):
            return ".".join(str(int(part)) for part in parts)
    if ":" in ip and IPV6_RE.fullmatch(ip):
        return ip
    return ""


def lookup_name(db_path: str | Path, name: str) -> dict:
    normalized = normalize_name(name)
    if not NAME_RE.fullmatch(normalized):
        return {"found": False, "query": name, "normalized": normalized, "error": "invalid_name"}

    uri = f"file:{Path(db_path).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT
              n.name, n.state, n.expired, n.onchain_class, n.provider_guess,
              COALESCE(ps.provider_type, 'unknown') AS provider_type, n.record_types,
              rs.ns_names, rs.glue4, rs.glue6, rs.synth4, rs.synth6, rs.ds_records, rs.has_ds,
              rs.raw_size, rs.resource_version, rs.resource_hash, n.last_seen_height, n.updated_at,
              CASE WHEN EXISTS(
                SELECT 1
                FROM dns_evidence de
                WHERE de.name = n.name
              ) THEN 'dns-evidence/' || n.name || '.json' ELSE NULL END AS dns_evidence_path,
              ls.dns_reachable, ls.dnssec_status, ls.tlsa_status, ls.dane_status, ls.https_status,
              ls.strict_hns_status, ls.doh_fallback_status, ls.failure_reason, ls.checked_at
            FROM names n
            JOIN resource_summary rs ON rs.name = n.name
            LEFT JOIN live_status ls ON ls.name = n.name
            LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
            WHERE n.name = ?
            LIMIT 1
            """,
            (normalized,),
        ).fetchone()
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
        "row": parse_json_columns(dict(row), JSON_COLUMNS),
    }


def lookup_ip_address(
    db_path: str | Path,
    query: str,
    *,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> dict:
    ip = normalize_ip(query)
    if not ip:
        return {"found": False, "query": query, "ip": ip, "error": "invalid_ip"}

    safe_page_size = min(max(1, int(page_size)), 5000)
    requested_page = max(1, int(page))
    uri = f"file:{Path(db_path).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        row_count = int(
            conn.execute(
                """
                SELECT COUNT(DISTINCT name)
                FROM resource_ip
                WHERE ip = ?
                """,
                (ip,),
            ).fetchone()[0]
            or 0
        )
        page_count = math.ceil(row_count / safe_page_size) if row_count else 0
        safe_page = min(requested_page, page_count) if page_count else 1
        offset = (safe_page - 1) * safe_page_size
        rows = conn.execute(
            """
            WITH page_names AS (
              SELECT name
              FROM resource_ip
              WHERE ip = ?
              GROUP BY name
              ORDER BY name
              LIMIT ?
              OFFSET ?
            )
            SELECT pn.name, group_concat(ri.field) AS fields
            FROM page_names pn
            JOIN resource_ip ri ON ri.name = pn.name AND ri.ip = ?
            GROUP BY pn.name
            ORDER BY pn.name
            """,
            (ip, safe_page_size, offset, ip),
        ).fetchall()
        field_counts = {
            row["field"]: int(row["row_count"] or 0)
            for row in conn.execute(
                """
                SELECT field, COUNT(DISTINCT name) AS row_count
                FROM resource_ip
                WHERE ip = ?
                GROUP BY field
                ORDER BY field
                """,
                (ip,),
            )
        }
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

    return {
        "found": row_count > 0,
        "query": query,
        "ip": ip,
        "snapshot": meta,
        "row_count": row_count,
        "page_size": safe_page_size,
        "page_count": page_count,
        "page": safe_page,
        "row_detail": "ip_matches",
        "columns": list(IP_LOOKUP_COLUMNS),
        "field_counts": field_counts,
        "rows": [
            {
                "name": row["name"],
                "fields": sorted({field for field in str(row["fields"] or "").split(",") if field}),
                "matched_ip": ip,
            }
            for row in rows
        ],
    }


class LookupHandler(BaseHTTPRequestHandler):
    db_path: Path

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/name", "/hns-topology/api/name"}:
            self._handle_name(parsed.query)
            return
        if parsed.path in {"/ip", "/hns-topology/api/ip"}:
            self._handle_ip(parsed.query)
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

    def _handle_ip(self, query_string: str) -> None:
        params = parse_qs(query_string)
        query = (params.get("ip") or [""])[0]
        if not query:
            self._json_response({"found": False, "error": "missing_ip"}, status=HTTPStatus.BAD_REQUEST)
            return
        try:
            page = int((params.get("page") or ["1"])[0])
        except ValueError:
            page = 1
        try:
            result = lookup_ip_address(self.db_path, query, page=page)
        except sqlite3.Error as exc:
            self._json_response(
                {"found": False, "error": "database_error", "detail": type(exc).__name__},
                status=HTTPStatus.SERVICE_UNAVAILABLE,
            )
            return

        status = HTTPStatus.OK
        if result.get("error") == "invalid_ip":
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

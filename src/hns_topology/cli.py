from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .archiver import archive_is_valid, archive_release, validate_archive_manifest
from .classifier import normalize_name
from .dane import (
    build_tlsa_records,
    load_certificate,
    parse_tlsa_zone_line,
    tlsa_record_matches_certificate,
)
from .db import (
    connect,
    get_meta,
    init_db,
    insert_dns_evidence_batch,
    recompute_provider_summary,
    set_meta,
)
from .exporter import export_all
from .hsd_rpc import HsdRpcClient
from .hsd_status import evaluate_hsd_readiness, hsd_is_ready
from .indexer import (
    UnpaginatedGetNamesError,
    bootstrap_from_fixture,
    bootstrap_from_hsd,
    bootstrap_from_jsonl,
    extract_changed_name_refs_from_block,
    find_reorg_mismatch,
    index_changed_names,
    rollback_reorg,
)
from .livecheck import LiveCheckConfig, count_live_check_candidates, run_live_checks
from .lookup_api import run_server
from .models import DnsEvidence
from .provider_rules import ProviderRules
from .site_generator import generate_site
from .timeutil import utc_now
from .validator import release_is_valid, validate_public_release, validate_release

DEFAULT_RULES = Path("configs/provider_rules.json")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hns-topology")
    sub = parser.add_subparsers(required=True)

    init = sub.add_parser("init-db", help="Create or migrate the SQLite schema.")
    init.add_argument("--db", required=True)
    init.set_defaults(func=cmd_init_db)

    fixture = sub.add_parser("bootstrap-fixture", help="Build an index from fixture JSON.")
    fixture.add_argument("--fixture", required=True)
    fixture.add_argument("--db", required=True)
    fixture.add_argument("--rules", default=str(DEFAULT_RULES))
    fixture.add_argument("--limit", type=int)
    fixture.set_defaults(func=cmd_bootstrap_fixture)

    jsonl = sub.add_parser("bootstrap-jsonl", help="Build an index from streaming JSONL.")
    jsonl.add_argument("--jsonl", required=True)
    jsonl.add_argument("--db", required=True)
    jsonl.add_argument("--rules", default=str(DEFAULT_RULES))
    jsonl.add_argument("--height", type=int, default=0)
    jsonl.add_argument("--tip-hash", default="")
    jsonl.add_argument("--chain", default="main")
    jsonl.add_argument("--hsd-version", default="unknown")
    jsonl.add_argument("--limit", type=int)
    jsonl.add_argument("--batch-size", type=int, default=5000)
    jsonl.set_defaults(func=cmd_bootstrap_jsonl)

    bootstrap = sub.add_parser("bootstrap", help="Build an index from HSD RPC.")
    bootstrap.add_argument("--db", required=True)
    bootstrap.add_argument("--rules", default=str(DEFAULT_RULES))
    bootstrap.add_argument("--hsd-rpc-url")
    bootstrap.add_argument("--hsd-api-key")
    bootstrap.add_argument("--limit", type=int)
    bootstrap.add_argument("--allow-unpaginated-getnames", action="store_true")
    bootstrap.set_defaults(func=cmd_bootstrap)

    hsd_status = sub.add_parser("hsd-status", help="Check HSD RPC and sync readiness.")
    hsd_status.add_argument("--hsd-rpc-url")
    hsd_status.add_argument("--hsd-api-key")
    hsd_status.add_argument("--max-block-lag", type=int, default=2)
    hsd_status.add_argument("--min-block-height", type=int, default=0)
    hsd_status.add_argument("--min-verification-progress", type=float, default=0.0)
    hsd_status.add_argument("--max-median-time-age", type=int, default=0)
    hsd_status.add_argument("--allow-remote-rpc", action="store_true")
    hsd_status.set_defaults(func=cmd_hsd_status)

    incremental = sub.add_parser("incremental", help="Index changed names with reorg metadata.")
    incremental.add_argument("--db", required=True)
    incremental.add_argument("--rules", default=str(DEFAULT_RULES))
    incremental.add_argument("--hsd-rpc-url")
    incremental.add_argument("--hsd-api-key")
    incremental.add_argument("--height", type=int)
    incremental.add_argument("--block-hash")
    incremental.add_argument("--changed-names-file")
    incremental.add_argument("--scan-block-height", type=int)
    incremental.add_argument("--reorg-keep-blocks", type=int, default=300)
    incremental.add_argument("--rollback-on-reorg", action="store_true")
    incremental.add_argument("--allow-empty-block-scan", action="store_true")
    incremental.add_argument("--allow-unresolved-name-hashes", action="store_true")
    incremental.add_argument("--catch-up-max-blocks", type=int)
    incremental.add_argument("--catch-up-to-height", type=int)
    incremental.set_defaults(func=cmd_incremental)

    reorg = sub.add_parser("reorg-check", help="Compare recent indexed block hashes with HSD.")
    reorg.add_argument("--db", required=True)
    reorg.add_argument("--rules", default=str(DEFAULT_RULES))
    reorg.add_argument("--hsd-rpc-url")
    reorg.add_argument("--hsd-api-key")
    reorg.add_argument("--rollback", action="store_true")
    reorg.set_defaults(func=cmd_reorg_check)

    live = sub.add_parser("live-check", help="Run rate-limited DNS/DANE/HTTPS checks.")
    live.add_argument("--db", required=True)
    live.add_argument("--rules", default=str(DEFAULT_RULES))
    live.add_argument("--limit", type=int)
    live.add_argument("--concurrency", type=int, default=4)
    live.add_argument("--min-delay-ms", type=int, default=250)
    live.add_argument("--timeout", type=float, default=5.0)
    live.add_argument("--resolver")
    live.add_argument("--priority-name", action="append", default=[])
    live.set_defaults(func=cmd_live_check)

    import_evidence = sub.add_parser(
        "import-dns-evidence",
        help="Import scanner or crowd-sourced DNS evidence JSON.",
    )
    import_evidence.add_argument("--db", required=True)
    import_evidence.add_argument("--file", required=True)
    import_evidence.add_argument("--source", default="crowd")
    import_evidence.add_argument("--source-id", default="")
    import_evidence.set_defaults(func=cmd_import_dns_evidence)

    export = sub.add_parser("export", help="Write JSON/CSV/SQLite.gz artifacts.")
    export.add_argument("--db", required=True)
    export.add_argument("--out", required=True)
    export.add_argument("--names-limit", type=int, default=0)
    export.add_argument("--include-downloads", action="store_true")
    export.set_defaults(func=cmd_export)

    site = sub.add_parser("generate-site", help="Generate static report site.")
    site.add_argument("--db", required=True)
    site.add_argument("--out", required=True)
    site.add_argument("--names-limit", type=int, default=0)
    site.add_argument("--include-downloads", action="store_true")
    site.set_defaults(func=cmd_generate_site)

    lookup_api = sub.add_parser("serve-lookup", help="Serve lookup API.")
    lookup_api.add_argument("--db", required=True)
    lookup_api.add_argument("--host", default="127.0.0.1")
    lookup_api.add_argument("--port", type=int, default=8787)
    lookup_api.set_defaults(func=cmd_serve_lookup)

    validate = sub.add_parser("validate-release", help="Validate DB and static artifacts before publishing.")
    validate.add_argument("--db", required=True)
    validate.add_argument("--public-dir")
    validate.add_argument("--require-live-checks", action="store_true")
    validate.add_argument("--min-indexed-height", type=int, default=0)
    validate.set_defaults(func=cmd_validate_release)

    validate_public = sub.add_parser("validate-public", help="Validate static public artifacts.")
    validate_public.add_argument("--public-dir", required=True)
    validate_public.add_argument("--require-live-checks", action="store_true")
    validate_public.add_argument("--min-indexed-height", type=int, default=0)
    validate_public.set_defaults(func=cmd_validate_public)

    archive = sub.add_parser("archive-release", help="Archive validated site and DB backup.")
    archive.add_argument("--db", required=True)
    archive.add_argument("--public-dir", required=True)
    archive.add_argument("--out-dir", required=True)
    archive.add_argument("--keep", type=int)
    archive.set_defaults(func=cmd_archive_release)

    validate_archive = sub.add_parser("validate-archive", help="Validate release archive artifacts.")
    validate_archive.add_argument("--manifest", required=True)
    validate_archive.set_defaults(func=cmd_validate_archive)

    tlsa = sub.add_parser("tlsa-from-cert", help="Generate TLSA 3 1 1 records from a certificate.")
    tlsa.add_argument("--cert", required=True)
    tlsa.add_argument("--site", required=True)
    tlsa.add_argument("--ttl", type=int, default=300)
    tlsa.add_argument("--include-www", action=argparse.BooleanOptionalAction, default=True)
    tlsa.set_defaults(func=cmd_tlsa_from_cert)

    verify_tlsa = sub.add_parser("verify-tlsa", help="Verify TLSA record text against a certificate.")
    verify_tlsa.add_argument("--cert", required=True)
    verify_tlsa.add_argument("--record", action="append", required=True)
    verify_tlsa.set_defaults(func=cmd_verify_tlsa)

    return parser


def cmd_init_db(args: argparse.Namespace) -> int:
    with connect(args.db) as conn:
        init_db(conn)
    print(f"initialized {args.db}")
    return 0


def cmd_bootstrap_fixture(args: argparse.Namespace) -> int:
    rules = ProviderRules.from_file(args.rules)
    with connect(args.db) as conn:
        count = bootstrap_from_fixture(
            conn,
            fixture_path=args.fixture,
            rules=rules,
            limit=args.limit,
        )
    print(f"indexed {count} fixture names into {args.db}")
    return 0


def cmd_bootstrap_jsonl(args: argparse.Namespace) -> int:
    rules = ProviderRules.from_file(args.rules)
    with connect(args.db) as conn:
        count = bootstrap_from_jsonl(
            conn,
            jsonl_path=args.jsonl,
            rules=rules,
            height=args.height,
            tip_hash=args.tip_hash,
            chain=args.chain,
            hsd_version=args.hsd_version,
            limit=args.limit,
            batch_size=args.batch_size,
        )
    print(f"indexed {count} JSONL names into {args.db}")
    return 0


def cmd_bootstrap(args: argparse.Namespace) -> int:
    rules = ProviderRules.from_file(args.rules)
    client = _client(args)
    allow_unpaginated_getnames = args.allow_unpaginated_getnames or _env_flag(
        "ALLOW_UNPAGINATED_GETNAMES"
    )
    with connect(args.db) as conn:
        try:
            count = bootstrap_from_hsd(
                conn,
                client=client,
                rules=rules,
                limit=args.limit,
                allow_unpaginated_getnames=allow_unpaginated_getnames,
            )
        except UnpaginatedGetNamesError as exc:
            print(str(exc), file=sys.stderr)
            return 2
    print(f"indexed {count} HSD names into {args.db}")
    return 0


def cmd_hsd_status(args: argparse.Namespace) -> int:
    client = _client(args)
    info = client.get_blockchain_info()
    checks = evaluate_hsd_readiness(
        info,
        rpc_url=client.url,
        max_block_lag=args.max_block_lag,
        min_block_height=args.min_block_height,
        min_verification_progress=args.min_verification_progress,
        max_median_time_age=args.max_median_time_age,
        require_local_rpc=not args.allow_remote_rpc,
    )
    for check in checks:
        marker = "ok" if check.ok else "fail"
        print(f"[{marker}] {check.name}: {check.detail}")
    return 0 if hsd_is_ready(checks) else 1


def cmd_incremental(args: argparse.Namespace) -> int:
    rules = ProviderRules.from_file(args.rules)
    client = _client(args)
    changed_names: list[str]
    height = args.height
    block_hash = args.block_hash

    with connect(args.db) as conn:
        init_db(conn)
        mismatch = find_reorg_mismatch(conn, client=client)
        if mismatch is not None:
            print(
                "reorg mismatch at height "
                f"{mismatch['height']}: stored {mismatch['stored_hash']} "
                f"current {mismatch['current_hash']}",
                file=sys.stderr,
            )
            if args.rollback_on_reorg:
                result = rollback_reorg(conn, rules=rules, rollback_height=mismatch["height"])
                print(f"rolled back reorg metadata: {result}")
            return 3

    if args.changed_names_file:
        changed_names = [
            line.strip()
            for line in Path(args.changed_names_file).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    elif args.scan_block_height is not None:
        block = client.get_block_by_height(args.scan_block_height)
        extraction = extract_changed_name_refs_from_block(block, name_by_hash=client.get_name_by_hash)
        changed_names = extraction.names
        height = args.scan_block_height
        block_hash = block.get("hash") or client.get_block_hash(args.scan_block_height)
        allow_unresolved = args.allow_unresolved_name_hashes or _env_flag(
            "ALLOW_UNRESOLVED_NAME_HASHES"
        )
        if extraction.unresolved_name_hashes and not allow_unresolved:
            print(
                "block scan found unresolved name hashes; refusing to record an incomplete "
                "incremental block. Set --allow-unresolved-name-hashes only for a deliberate "
                f"best-effort run. unresolved={extraction.unresolved_name_hashes[:5]}",
                file=sys.stderr,
            )
            return 4
        if extraction.non_dict_tx_count:
            print(
                "block scan did not return detailed transaction objects; refusing to record "
                "an ambiguous incremental block.",
                file=sys.stderr,
            )
            return 4
        allow_empty = args.allow_empty_block_scan or _env_flag("ALLOW_EMPTY_BLOCK_SCAN")
        if not changed_names and not allow_empty:
            print(
                "block scan found no changed names; refusing to record an empty incremental "
                "block unless --allow-empty-block-scan is set for a known-empty block.",
                file=sys.stderr,
            )
            return 4
    else:
        return _cmd_incremental_catch_up(args, client, rules)

    if height is None:
        info = client.get_blockchain_info()
        height = int(info.get("blocks") or 0)
    if block_hash is None:
        block_hash = client.get_block_hash(height)

    with connect(args.db) as conn:
        count = index_changed_names(
            conn,
            client=client,
            rules=rules,
            changed_names=changed_names,
            height=height,
            block_hash=block_hash,
            reorg_keep_blocks=args.reorg_keep_blocks,
        )
    print(f"indexed {count} changed names at height {height}")
    return 0


def _cmd_incremental_catch_up(
    args: argparse.Namespace,
    client: HsdRpcClient,
    rules: ProviderRules,
) -> int:
    with connect(args.db) as conn:
        init_db(conn)
        last_height_raw = get_meta(conn, "last_indexed_height")

    if not last_height_raw:
        print(
            "incremental catch-up requires an existing bootstrap with last_indexed_height",
            file=sys.stderr,
        )
        return 2
    try:
        last_height = int(last_height_raw)
    except ValueError:
        print(f"invalid last_indexed_height: {last_height_raw}", file=sys.stderr)
        return 2

    info = client.get_blockchain_info()
    tip_height = int(info.get("blocks") or info.get("height") or 0)
    to_height = args.catch_up_to_height or tip_height
    if to_height > tip_height:
        print(
            f"catch-up target {to_height} is above HSD tip height {tip_height}",
            file=sys.stderr,
        )
        return 2
    if to_height <= last_height:
        print(f"already indexed through height {last_height}")
        return 0

    max_blocks = args.catch_up_max_blocks
    if max_blocks is None:
        max_blocks = int(os.environ.get("INCREMENTAL_MAX_BLOCKS", "300"))
    block_count = to_height - last_height
    if block_count > max_blocks:
        print(
            f"catch-up would scan {block_count} blocks, above max {max_blocks}. "
            "Increase --catch-up-max-blocks or run a fresh extract-jsonl bootstrap.",
            file=sys.stderr,
        )
        return 5

    allow_unresolved = args.allow_unresolved_name_hashes or _env_flag(
        "ALLOW_UNRESOLVED_NAME_HASHES"
    )
    total_changed = 0
    scanned = 0
    for height in range(last_height + 1, to_height + 1):
        block = client.get_block_by_height(height)
        extraction = extract_changed_name_refs_from_block(block, name_by_hash=client.get_name_by_hash)
        if extraction.non_dict_tx_count:
            print(
                f"block {height} did not return detailed transaction objects; refusing catch-up",
                file=sys.stderr,
            )
            return 4
        if extraction.unresolved_name_hashes and not allow_unresolved:
            print(
                f"block {height} has unresolved name hashes; refusing incomplete catch-up. "
                f"unresolved={extraction.unresolved_name_hashes[:5]}",
                file=sys.stderr,
            )
            return 4
        if extraction.name_covenant_count and not extraction.names:
            print(
                f"block {height} has name covenants but no resolved names; refusing catch-up",
                file=sys.stderr,
            )
            return 4
        block_hash = str(block.get("hash") or client.get_block_hash(height))
        with connect(args.db) as conn:
            count = index_changed_names(
                conn,
                client=client,
                rules=rules,
                changed_names=extraction.names,
                height=height,
                block_hash=block_hash,
                reorg_keep_blocks=args.reorg_keep_blocks,
            )
        total_changed += count
        scanned += 1
    print(f"caught up {scanned} blocks through height {to_height}; indexed {total_changed} names")
    return 0


def cmd_reorg_check(args: argparse.Namespace) -> int:
    rules = ProviderRules.from_file(args.rules)
    client = _client(args)
    with connect(args.db) as conn:
        init_db(conn)
        mismatch = find_reorg_mismatch(conn, client=client)
        if mismatch is None:
            print("no reorg mismatch detected")
            return 0
        print(
            "reorg mismatch at height "
            f"{mismatch['height']}: stored {mismatch['stored_hash']} "
            f"current {mismatch['current_hash']}"
        )
        if not args.rollback:
            return 1
        result = rollback_reorg(conn, rules=rules, rollback_height=mismatch["height"])
        print(f"rolled back compact index to before height {mismatch['height']}: {result}")
        return 0


def cmd_live_check(args: argparse.Namespace) -> int:
    config = LiveCheckConfig(
        timeout=args.timeout,
        concurrency=args.concurrency,
        min_delay_ms=args.min_delay_ms,
        resolver=args.resolver,
    )
    rules = ProviderRules.from_file(args.rules)
    with connect(args.db) as conn:
        init_db(conn)
        candidate_count = count_live_check_candidates(conn)
        started_at = utc_now()
        set_meta(conn, "live_check_started_at", started_at)
        set_meta(conn, "live_check_limit", str(args.limit) if args.limit is not None else "unlimited")
        set_meta(conn, "live_check_candidate_count", str(candidate_count))
        set_meta(conn, "live_check_concurrency", str(config.concurrency))
        set_meta(conn, "live_check_min_delay_ms", str(config.min_delay_ms))
        set_meta(conn, "live_check_timeout_seconds", str(config.timeout))
        set_meta(conn, "live_check_recheck_seconds", str(config.recheck_seconds))
        set_meta(conn, "live_check_resolver", config.resolver or "system")
        count = run_live_checks(
            conn,
            limit=args.limit,
            config=config,
            priority_names=getattr(args, "priority_name", []),
        )
        finished_at = utc_now()
        set_meta(conn, "live_check_checked_count", str(count))
        set_meta(conn, "live_check_finished_at", finished_at)
        recompute_provider_summary(conn, rules.provider_types, finished_at, rules.provider_patterns)
        conn.commit()
    print(f"checked {count} names")
    return 0


def cmd_import_dns_evidence(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.file).read_text(encoding="utf-8"))
    evidence = _dns_evidence_from_payload(
        payload,
        source=args.source,
        source_id=args.source_id,
    )
    with connect(args.db) as conn:
        init_db(conn)
        with conn:
            insert_dns_evidence_batch(conn, evidence)
    print(f"imported {len(evidence)} DNS evidence observations")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    with connect(args.db) as conn:
        init_db(conn)
        export_all(
            conn,
            db_path=args.db,
            out_dir=args.out,
            names_limit=args.names_limit,
            include_downloads=args.include_downloads,
        )
    print(f"exported data to {args.out}")
    return 0


def cmd_generate_site(args: argparse.Namespace) -> int:
    with connect(args.db) as conn:
        init_db(conn)
        generate_site(
            conn,
            db_path=args.db,
            out_dir=args.out,
            names_limit=args.names_limit,
            include_downloads=args.include_downloads,
        )
    print(f"generated site at {args.out}")
    return 0


def cmd_serve_lookup(args: argparse.Namespace) -> int:
    run_server(db_path=args.db, host=args.host, port=args.port)
    return 0


def cmd_validate_release(args: argparse.Namespace) -> int:
    checks = validate_release(
        db_path=args.db,
        public_dir=args.public_dir,
        require_live_checks=args.require_live_checks,
        min_indexed_height=args.min_indexed_height,
    )
    for check in checks:
        marker = "ok" if check.ok else "fail"
        print(f"[{marker}] {check.name}: {check.detail}")
    return 0 if release_is_valid(checks) else 1


def cmd_validate_public(args: argparse.Namespace) -> int:
    checks = validate_public_release(
        public_dir=args.public_dir,
        require_live_checks=args.require_live_checks,
        min_indexed_height=args.min_indexed_height,
    )
    for check in checks:
        marker = "ok" if check.ok else "fail"
        print(f"[{marker}] {check.name}: {check.detail}")
    return 0 if release_is_valid(checks) else 1


def cmd_archive_release(args: argparse.Namespace) -> int:
    with connect(args.db) as conn:
        init_db(conn)
        result = archive_release(
            conn,
            db_path=args.db,
            public_dir=args.public_dir,
            out_dir=args.out_dir,
            keep=args.keep,
        )
    print(f"manifest: {result.manifest_path}")
    print(f"site: {result.site_tarball_path}")
    print(f"sqlite: {result.sqlite_backup_path}")
    return 0


def cmd_validate_archive(args: argparse.Namespace) -> int:
    checks = validate_archive_manifest(args.manifest)
    for check in checks:
        marker = "ok" if check.ok else "fail"
        print(f"[{marker}] {check.name}: {check.detail}")
    return 0 if archive_is_valid(checks) else 1


def cmd_tlsa_from_cert(args: argparse.Namespace) -> int:
    cert = load_certificate(args.cert)
    for record in build_tlsa_records(
        cert,
        site_name=args.site,
        ttl=args.ttl,
        include_www=args.include_www,
    ):
        print(record.to_zone_line())
    return 0


def cmd_verify_tlsa(args: argparse.Namespace) -> int:
    cert = load_certificate(args.cert)
    ok = True
    for line in args.record:
        try:
            record = parse_tlsa_zone_line(line)
        except ValueError as exc:
            print(f"[fail] {line}: {exc}")
            ok = False
            continue
        matched = tlsa_record_matches_certificate(cert, record)
        marker = "ok" if matched else "fail"
        print(
            f"[{marker}] {record.owner}: TLSA "
            f"{record.usage} {record.selector} {record.matching_type}"
        )
        ok = ok and matched
    return 0 if ok else 1


def _client(args: argparse.Namespace) -> HsdRpcClient:
    if args.hsd_rpc_url:
        return HsdRpcClient(args.hsd_rpc_url, args.hsd_api_key)
    return HsdRpcClient.from_env()


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _dns_evidence_from_payload(
    payload,
    *,
    source: str,
    source_id: str,
) -> list[DnsEvidence]:
    documents = payload if isinstance(payload, list) else [payload]
    evidence: list[DnsEvidence] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        name = normalize_name(str(document.get("name") or ""))
        observations = document.get("observations")
        if not isinstance(observations, list):
            observations = [document]
        for item in observations:
            if not isinstance(item, dict):
                continue
            item_name = normalize_name(str(item.get("name") or name))
            if not item_name:
                continue
            qname = _evidence_fqdn(str(item.get("qname") or item_name))
            rrtype = str(item.get("rrtype") or "").upper()
            if not rrtype:
                continue
            evidence.append(
                DnsEvidence(
                    name=item_name,
                    qname=qname,
                    rrtype=rrtype,
                    server=str(item.get("server") or ""),
                    source=str(item.get("source") or source or "crowd"),
                    source_id=str(item.get("source_id") or source_id or ""),
                    status=str(item.get("status") or "ok"),
                    rcode=item.get("rcode"),
                    flags=item.get("flags"),
                    answer=_string_list(item.get("answer")),
                    authority=_string_list(item.get("authority")),
                    additional=_string_list(item.get("additional")),
                    elapsed_ms=_optional_int(item.get("elapsed_ms")),
                    error=item.get("error"),
                    captured_at=str(item.get("captured_at") or utc_now()),
                )
            )
    return evidence


def _string_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None]


def _optional_int(value) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _evidence_fqdn(value: str) -> str:
    text = value.strip().lower()
    return text if text.endswith(".") else f"{text}."

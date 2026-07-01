from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .db import connect, init_db, recompute_provider_summary, set_meta
from .exporter import export_all
from .hsd_rpc import HsdRpcClient
from .hsd_status import evaluate_hsd_readiness, hsd_is_ready
from .indexer import (
    bootstrap_from_fixture,
    bootstrap_from_hsd,
    bootstrap_from_jsonl,
    extract_changed_names_from_block,
    find_reorg_mismatch,
    index_changed_names,
    rollback_reorg,
)
from .livecheck import LiveCheckConfig, run_live_checks
from .provider_rules import ProviderRules
from .site_generator import generate_site
from .timeutil import utc_now
from .validator import release_is_valid, validate_release

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
    jsonl.set_defaults(func=cmd_bootstrap_jsonl)

    bootstrap = sub.add_parser("bootstrap", help="Build an index from HSD RPC.")
    bootstrap.add_argument("--db", required=True)
    bootstrap.add_argument("--rules", default=str(DEFAULT_RULES))
    bootstrap.add_argument("--hsd-rpc-url")
    bootstrap.add_argument("--hsd-api-key")
    bootstrap.add_argument("--limit", type=int)
    bootstrap.set_defaults(func=cmd_bootstrap)

    hsd_status = sub.add_parser("hsd-status", help="Check HSD RPC and sync readiness.")
    hsd_status.add_argument("--hsd-rpc-url")
    hsd_status.add_argument("--hsd-api-key")
    hsd_status.add_argument("--max-block-lag", type=int, default=2)
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
    live.set_defaults(func=cmd_live_check)

    export = sub.add_parser("export", help="Write JSON/CSV/SQLite.gz artifacts.")
    export.add_argument("--db", required=True)
    export.add_argument("--out", required=True)
    export.add_argument("--names-limit", type=int, default=5000)
    export.set_defaults(func=cmd_export)

    site = sub.add_parser("generate-site", help="Generate static report site.")
    site.add_argument("--db", required=True)
    site.add_argument("--out", required=True)
    site.add_argument("--names-limit", type=int, default=5000)
    site.set_defaults(func=cmd_generate_site)

    validate = sub.add_parser("validate-release", help="Validate DB and static artifacts before publishing.")
    validate.add_argument("--db", required=True)
    validate.add_argument("--public-dir")
    validate.add_argument("--require-live-checks", action="store_true")
    validate.set_defaults(func=cmd_validate_release)

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
        )
    print(f"indexed {count} JSONL names into {args.db}")
    return 0


def cmd_bootstrap(args: argparse.Namespace) -> int:
    rules = ProviderRules.from_file(args.rules)
    client = _client(args)
    with connect(args.db) as conn:
        count = bootstrap_from_hsd(conn, client=client, rules=rules, limit=args.limit)
    print(f"indexed {count} HSD names into {args.db}")
    return 0


def cmd_hsd_status(args: argparse.Namespace) -> int:
    client = _client(args)
    info = client.get_blockchain_info()
    checks = evaluate_hsd_readiness(
        info,
        rpc_url=client.url,
        max_block_lag=args.max_block_lag,
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
        changed_names = extract_changed_names_from_block(block)
        height = args.scan_block_height
        block_hash = block.get("hash") or client.get_block_hash(args.scan_block_height)
    else:
        print("incremental requires --changed-names-file or --scan-block-height", file=sys.stderr)
        return 2

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
        started_at = utc_now()
        set_meta(conn, "live_check_started_at", started_at)
        count = run_live_checks(conn, limit=args.limit, config=config)
        finished_at = utc_now()
        set_meta(conn, "live_check_finished_at", finished_at)
        recompute_provider_summary(conn, rules.provider_types, finished_at)
        conn.commit()
    print(f"checked {count} names")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    with connect(args.db) as conn:
        init_db(conn)
        export_all(conn, db_path=args.db, out_dir=args.out, names_limit=args.names_limit)
    print(f"exported data to {args.out}")
    return 0


def cmd_generate_site(args: argparse.Namespace) -> int:
    with connect(args.db) as conn:
        init_db(conn)
        generate_site(conn, db_path=args.db, out_dir=args.out, names_limit=args.names_limit)
    print(f"generated site at {args.out}")
    return 0


def cmd_validate_release(args: argparse.Namespace) -> int:
    checks = validate_release(
        db_path=args.db,
        public_dir=args.public_dir,
        require_live_checks=args.require_live_checks,
    )
    for check in checks:
        marker = "ok" if check.ok else "fail"
        print(f"[{marker}] {check.name}: {check.detail}")
    return 0 if release_is_valid(checks) else 1


def _client(args: argparse.Namespace) -> HsdRpcClient:
    if args.hsd_rpc_url:
        return HsdRpcClient(args.hsd_rpc_url, args.hsd_api_key)
    return HsdRpcClient.from_env()

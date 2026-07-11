from __future__ import annotations

import argparse

from .jsonutil import dumps_pretty
from .live_candidates import sync_topology, sync_topology_if_changed
from .live_db import candidate_plan, connect_live, init_live_db
from .live_exporter import export_live_site, validate_live_site
from .live_runner import ProbeBatchConfig, run_probe_batch


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="hns-live-directory",
        description="Independent HNS HTTP/HTTPS live website directory scanner.",
    )
    sub = result.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Create or migrate the live-directory database.")
    init.add_argument("--db", required=True)
    init.set_defaults(func=cmd_init)

    sync = sub.add_parser(
        "sync", help="Import candidates from a topology snapshot without probing."
    )
    _add_db(sync)
    sync.add_argument("--topology-db", required=True)
    sync.set_defaults(func=cmd_sync)

    plan = sub.add_parser("plan", help="Print candidate and due-queue counts without probing.")
    _add_db(plan)
    plan.set_defaults(func=cmd_plan)

    scan = sub.add_parser("scan", help="Probe a bounded batch of due candidates.")
    _add_db(scan)
    _add_probe_options(scan)
    scan.set_defaults(func=cmd_scan)

    export = sub.add_parser("export", help="Generate the standalone live-directory static site.")
    _add_db(export)
    export.add_argument("--out", required=True)
    export.set_defaults(func=cmd_export)

    validate = sub.add_parser("validate", help="Validate standalone live-directory artifacts.")
    validate.add_argument("--public-dir", required=True)
    validate.set_defaults(func=cmd_validate)

    cycle = sub.add_parser("cycle", help="Sync topology, probe one batch, and publish atomically.")
    _add_db(cycle)
    cycle.add_argument("--topology-db", required=True)
    cycle.add_argument("--out", required=True)
    _add_probe_options(cycle)
    cycle.set_defaults(func=cmd_cycle)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return int(args.func(args))


def cmd_init(args: argparse.Namespace) -> int:
    with connect_live(args.db) as conn:
        init_live_db(conn)
    _print({"initialized": str(args.db)})
    return 0


def cmd_sync(args: argparse.Namespace) -> int:
    with connect_live(args.db) as conn:
        init_live_db(conn)
        result = sync_topology(conn, args.topology_db)
    _print(result)
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    with connect_live(args.db) as conn:
        init_live_db(conn)
        result = candidate_plan(conn)
    _print(result)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    with connect_live(args.db) as conn:
        init_live_db(conn)
        result = run_probe_batch(conn, config=_probe_config(args))
    _print(result)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    with connect_live(args.db) as conn:
        init_live_db(conn)
        summary = export_live_site(conn, args.out)
    _print(summary)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    errors = validate_live_site(args.public_dir)
    _print({"valid": not errors, "errors": errors})
    return 0 if not errors else 1


def cmd_cycle(args: argparse.Namespace) -> int:
    with connect_live(args.db) as conn:
        init_live_db(conn)
        synced = sync_topology_if_changed(conn, args.topology_db)
        before = candidate_plan(conn)
        probed = run_probe_batch(conn, config=_probe_config(args))
        summary = export_live_site(conn, args.out)
    errors = validate_live_site(args.out)
    result = {
        "sync": synced,
        "plan_before": before,
        "probe": probed,
        "directory_count": summary["directory_count"],
        "valid": not errors,
        "errors": errors,
    }
    _print(result)
    return 0 if not errors else 1


def _add_db(command: argparse.ArgumentParser) -> None:
    command.add_argument("--db", required=True)


def _add_probe_options(command: argparse.ArgumentParser) -> None:
    command.add_argument("--limit", type=int, default=100)
    command.add_argument("--concurrency", type=int, default=4)
    command.add_argument("--min-delay-ms", type=int, default=250)
    command.add_argument("--timeout", type=float, default=5.0)
    command.add_argument("--max-nameservers", type=int, default=3)
    command.add_argument("--max-addresses", type=int, default=4)
    command.add_argument("--fallback-resolver")


def _probe_config(args: argparse.Namespace) -> ProbeBatchConfig:
    if args.limit < 0:
        raise SystemExit("--limit must be zero or greater")
    if args.concurrency < 1:
        raise SystemExit("--concurrency must be at least one")
    if args.timeout <= 0:
        raise SystemExit("--timeout must be positive")
    return ProbeBatchConfig(
        limit=None if args.limit == 0 else args.limit,
        concurrency=args.concurrency,
        min_delay_ms=max(0, args.min_delay_ms),
        timeout=args.timeout,
        max_nameservers=max(1, args.max_nameservers),
        max_addresses=max(1, args.max_addresses),
        fallback_resolver=args.fallback_resolver,
    )


def _print(value) -> None:
    print(dumps_pretty(value), end="")


if __name__ == "__main__":
    raise SystemExit(main())

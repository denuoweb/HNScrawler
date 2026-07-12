from __future__ import annotations

import argparse

from .jsonutil import dumps_pretty
from .live_candidates import sync_topology, sync_topology_if_changed
from .live_db import (
    candidate_plan,
    connect_live,
    init_live_db,
    latest_sweep_run,
    sweep_coverage_summary,
)
from .live_delegations import refresh_delegation_groups
from .live_exporter import export_live_site, validate_live_site
from .live_handoffs import refresh_hns_handoff_groups
from .live_probe import DEFAULT_HNS_DOH_URL
from .live_runner import ProbeBatchConfig, run_probe_batch
from .live_sweep import (
    PRIORITY_SWEEP_TIERS,
    SWEEP_TIERS,
    SweepBatchConfig,
    parse_sweep_tiers,
    run_sweep_batch,
)


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

    sweep = sub.add_parser(
        "sweep",
        help="Probe a streamed broad-root batch without materializing roots as candidates.",
    )
    _add_db(sweep)
    sweep.add_argument("--topology-db", required=True)
    _add_sweep_options(sweep)
    sweep.set_defaults(func=cmd_sweep)

    delegation_index = sub.add_parser(
        "index-delegations",
        help="Refresh the compact shared-delegation priority index from topology site shards.",
    )
    _add_db(delegation_index)
    delegation_index.add_argument("--topology-site", required=True)
    delegation_index.add_argument("--min-members", type=int, default=5)
    delegation_index.add_argument("--max-members", type=int, default=250)
    delegation_index.set_defaults(func=cmd_index_delegations)

    handoff_index = sub.add_parser(
        "index-handoffs",
        help="Refresh the compact HNS nameserver-handoff priority index from topology artifacts.",
    )
    _add_db(handoff_index)
    handoff_index.add_argument("--topology-site", required=True)
    handoff_index.add_argument("--min-members", type=int, default=2)
    handoff_index.add_argument("--max-members", type=int, default=250)
    handoff_index.set_defaults(func=cmd_index_handoffs)

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
    cycle.add_argument(
        "--sync-topology",
        action="store_true",
        help="Run the full evidence-candidate topology sync before probing.",
    )
    _add_probe_options(cycle)
    _add_cycle_sweep_options(cycle)
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
        result = {
            **candidate_plan(conn),
            "sweep_coverage": sweep_coverage_summary(conn),
            "latest_sweep_run": latest_sweep_run(conn),
        }
    _print(result)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    with connect_live(args.db) as conn:
        init_live_db(conn)
        result = run_probe_batch(conn, config=_probe_config(args))
    _print(result)
    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    with connect_live(args.db) as conn:
        init_live_db(conn)
        result = run_sweep_batch(
            conn,
            topology_db=args.topology_db,
            config=_sweep_config(args),
        )
    _print(result)
    return 0


def cmd_index_delegations(args: argparse.Namespace) -> int:
    if args.min_members < 1:
        raise SystemExit("--min-members must be at least one")
    if args.max_members < args.min_members:
        raise SystemExit("--max-members must be at least --min-members")
    with connect_live(args.db) as conn:
        init_live_db(conn)
        result = refresh_delegation_groups(
            conn,
            topology_site=args.topology_site,
            min_members=args.min_members,
            max_members=args.max_members,
        )
    _print(result)
    return 0


def cmd_index_handoffs(args: argparse.Namespace) -> int:
    if args.min_members < 1:
        raise SystemExit("--min-members must be at least one")
    if args.max_members < args.min_members:
        raise SystemExit("--max-members must be at least --min-members")
    with connect_live(args.db) as conn:
        init_live_db(conn)
        result = refresh_hns_handoff_groups(
            conn,
            topology_site=args.topology_site,
            min_members=args.min_members,
            max_members=args.max_members,
        )
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
        synced = (
            sync_topology_if_changed(conn, args.topology_db)
            if args.sync_topology
            else {"roots": 0, "candidates": 0, "changed_roots": 0, "skipped": True, "deferred": True}
        )
        before = candidate_plan(conn)
        sweep = run_sweep_batch(
            conn,
            topology_db=args.topology_db,
            config=_cycle_sweep_config(args),
        )
        probed = run_probe_batch(conn, config=_probe_config(args))
        summary = export_live_site(conn, args.out)
    errors = validate_live_site(args.out)
    result = {
        "sync": synced,
        "plan_before": before,
        "probe": probed,
        "sweep": sweep,
        "directory_count": summary["directory_count"],
        "valid": not errors,
        "errors": errors,
    }
    _print(result)
    return 0 if not errors else 1


def _add_db(command: argparse.ArgumentParser) -> None:
    command.add_argument("--db", required=True)


def _add_probe_options(command: argparse.ArgumentParser) -> None:
    command.add_argument("--limit", type=int, default=20)
    command.add_argument("--concurrency", type=int, default=20)
    command.add_argument("--min-delay-ms", type=int, default=100)
    command.add_argument("--timeout", type=float, default=2.0)
    command.add_argument("--max-nameservers", type=int, default=2)
    command.add_argument("--max-addresses", type=int, default=2)
    command.add_argument("--fallback-resolver")
    command.add_argument("--hns-doh-url", default=DEFAULT_HNS_DOH_URL)


def _add_sweep_options(command: argparse.ArgumentParser) -> None:
    command.add_argument("--limit", type=int, default=500)
    command.add_argument("--page-size", type=int, default=1000)
    command.add_argument("--concurrency", type=int, default=50)
    command.add_argument("--min-delay-ms", type=int, default=100)
    command.add_argument("--authority-delay-ms", type=int, default=500)
    command.add_argument("--timeout", type=float, default=2.0)
    command.add_argument("--max-nameservers", type=int, default=2)
    command.add_argument("--max-addresses", type=int, default=2)
    command.add_argument("--fallback-resolver")
    command.add_argument("--hns-doh-url", default=DEFAULT_HNS_DOH_URL)
    command.add_argument("--tiers", default=",".join(SWEEP_TIERS))


def _add_cycle_sweep_options(command: argparse.ArgumentParser) -> None:
    command.add_argument("--sweep-limit", type=int, default=500)
    command.add_argument("--sweep-page-size", type=int, default=1000)
    command.add_argument("--sweep-concurrency", type=int, default=50)
    command.add_argument("--sweep-min-delay-ms", type=int, default=100)
    command.add_argument("--sweep-authority-delay-ms", type=int, default=500)
    command.add_argument("--sweep-timeout", type=float, default=2.0)
    command.add_argument("--sweep-max-nameservers", type=int, default=2)
    command.add_argument("--sweep-max-addresses", type=int, default=2)
    command.add_argument("--sweep-tiers", default=",".join(PRIORITY_SWEEP_TIERS))


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
        hns_doh_url=args.hns_doh_url,
    )


def _sweep_config(args: argparse.Namespace) -> SweepBatchConfig:
    return _build_sweep_config(
        limit=args.limit,
        page_size=args.page_size,
        concurrency=args.concurrency,
        min_delay_ms=args.min_delay_ms,
        authority_delay_ms=args.authority_delay_ms,
        timeout=args.timeout,
        max_nameservers=args.max_nameservers,
        max_addresses=args.max_addresses,
        fallback_resolver=args.fallback_resolver,
        hns_doh_url=args.hns_doh_url,
        tiers=args.tiers,
    )


def _cycle_sweep_config(args: argparse.Namespace) -> SweepBatchConfig:
    return _build_sweep_config(
        limit=args.sweep_limit,
        page_size=args.sweep_page_size,
        concurrency=args.sweep_concurrency,
        min_delay_ms=args.sweep_min_delay_ms,
        authority_delay_ms=args.sweep_authority_delay_ms,
        timeout=args.sweep_timeout,
        max_nameservers=args.sweep_max_nameservers,
        max_addresses=args.sweep_max_addresses,
        fallback_resolver=args.fallback_resolver,
        hns_doh_url=args.hns_doh_url,
        tiers=args.sweep_tiers,
    )


def _build_sweep_config(
    *,
    limit: int,
    page_size: int,
    concurrency: int,
    min_delay_ms: int,
    authority_delay_ms: int,
    timeout: float,
    max_nameservers: int,
    max_addresses: int,
    fallback_resolver: str | None,
    hns_doh_url: str | None,
    tiers: str,
) -> SweepBatchConfig:
    if limit < 0:
        raise SystemExit("--sweep-limit must be zero or greater")
    if page_size < 1:
        raise SystemExit("--sweep-page-size must be at least one")
    if concurrency < 1:
        raise SystemExit("--sweep-concurrency must be at least one")
    if timeout <= 0:
        raise SystemExit("--sweep-timeout must be positive")
    try:
        selected_tiers = parse_sweep_tiers(tiers)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    return SweepBatchConfig(
        limit=None if limit == 0 else limit,
        page_size=page_size,
        concurrency=concurrency,
        min_delay_ms=max(0, min_delay_ms),
        authority_delay_ms=max(0, authority_delay_ms),
        timeout=timeout,
        max_nameservers=max(1, max_nameservers),
        max_addresses=max(1, max_addresses),
        fallback_resolver=fallback_resolver,
        hns_doh_url=hns_doh_url,
        tiers=selected_tiers,
    )


def _print(value) -> None:
    print(dumps_pretty(value), end="")


if __name__ == "__main__":
    raise SystemExit(main())

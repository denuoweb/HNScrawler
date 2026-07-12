from __future__ import annotations

import concurrent.futures
import sqlite3
from dataclasses import dataclass
from typing import Any

from .live_db import (
    begin_probe_run,
    finish_probe_run,
    select_due_candidates,
    store_probe_result,
    upsert_discovered_hosts,
)
from .live_models import ONLINE_CATEGORIES
from .live_probe import DEFAULT_HNS_DOH_URL, ProbeConfig, RateLimiter, probe_host


@dataclass(frozen=True)
class ProbeBatchConfig:
    limit: int | None = 20
    concurrency: int = 20
    min_delay_ms: int = 100
    timeout: float = 2.0
    max_nameservers: int = 2
    max_addresses: int = 2
    fallback_resolver: str | None = None
    hns_doh_url: str | None = DEFAULT_HNS_DOH_URL


def run_probe_batch(conn: sqlite3.Connection, *, config: ProbeBatchConfig) -> dict[str, Any]:
    candidates = select_due_candidates(conn, limit=config.limit)
    probe_config = ProbeConfig(
        timeout=config.timeout,
        max_nameservers=config.max_nameservers,
        max_addresses=config.max_addresses,
        fallback_resolver=config.fallback_resolver,
        hns_doh_url=config.hns_doh_url,
    )
    with conn:
        run_id = begin_probe_run(
            conn,
            candidate_count=len(candidates),
            concurrency=max(1, config.concurrency),
            min_delay_ms=max(0, config.min_delay_ms),
            timeout_seconds=config.timeout,
        )
    limiter = RateLimiter(config.min_delay_ms)
    checked = 0
    online = 0
    errors = 0
    discovered = 0
    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, config.concurrency)
        ) as executor:
            future_candidates = {
                executor.submit(
                    probe_host,
                    candidate,
                    config=probe_config,
                    limiter=limiter,
                ): candidate
                for candidate in candidates
            }
            for future in concurrent.futures.as_completed(future_candidates):
                result = future.result()
                with conn:
                    store_probe_result(conn, result)
                    discovered += upsert_discovered_hosts(
                        conn,
                        root_name=result.root_name,
                        hosts=result.discovered_hosts,
                        topology_resource_hash=result.topology_resource_hash,
                        source_detail=f"authoritative response while checking {result.host}",
                    )
                checked += 1
                online += int(result.category in ONLINE_CATEGORIES)
                errors += int(result.failure_reason.startswith("probe_error:"))
        with conn:
            finish_probe_run(
                conn,
                run_id,
                checked_count=checked,
                online_count=online,
                error_count=errors,
            )
    except Exception:
        with conn:
            finish_probe_run(
                conn,
                run_id,
                checked_count=checked,
                online_count=online,
                error_count=errors + 1,
                status="failed",
            )
        raise
    return {
        "run_id": run_id,
        "candidates": len(candidates),
        "checked": checked,
        "online": online,
        "errors": errors,
        "discovered": discovered,
    }

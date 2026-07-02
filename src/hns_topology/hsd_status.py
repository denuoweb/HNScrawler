from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

LOCAL_RPC_HOSTS = {"127.0.0.1", "localhost", "::1"}


@dataclass(frozen=True)
class HsdCheck:
    name: str
    ok: bool
    detail: str


def evaluate_hsd_readiness(
    info: dict[str, Any],
    *,
    rpc_url: str,
    max_block_lag: int = 2,
    min_block_height: int = 0,
    min_verification_progress: float = 0.0,
    max_median_time_age: int = 0,
    require_local_rpc: bool = True,
    now: int | None = None,
) -> list[HsdCheck]:
    blocks = _maybe_int(info.get("blocks") or info.get("height"))
    headers = _maybe_int(info.get("headers"))
    median_time = _maybe_int(info.get("mediantime"))
    verification_progress = _maybe_float(info.get("verificationprogress"))
    ibd = info.get("initialblockdownload")
    best_hash = info.get("bestblockhash") or info.get("hash")
    chain = info.get("chain") or info.get("network")

    checks = [
        _local_rpc_check(rpc_url, require_local_rpc=require_local_rpc),
        HsdCheck("chain_reported", bool(chain), str(chain or "missing")),
        HsdCheck("best_hash_reported", bool(best_hash), str(best_hash or "missing")),
        HsdCheck(
            "blocks_reported",
            blocks is not None and blocks >= 0,
            "missing" if blocks is None else str(blocks),
        ),
    ]

    if min_block_height > 0:
        checks.append(
            HsdCheck(
                "minimum_block_height",
                blocks is not None and blocks >= min_block_height,
                f"blocks={blocks if blocks is not None else 'missing'} min={min_block_height}",
            )
        )

    if min_verification_progress > 0:
        checks.append(
            HsdCheck(
                "minimum_verification_progress",
                verification_progress is not None
                and verification_progress >= min_verification_progress,
                "missing"
                if verification_progress is None
                else f"progress={verification_progress:.6f} min={min_verification_progress:.6f}",
            )
        )

    if max_median_time_age > 0:
        current_time = int(time.time()) if now is None else now
        age = None if median_time is None else current_time - median_time
        checks.append(
            HsdCheck(
                "median_time_freshness",
                age is not None and 0 <= age <= max_median_time_age,
                "missing"
                if age is None
                else f"age={age}s max={max_median_time_age}s mediantime={median_time}",
            )
        )

    if headers is None:
        checks.append(HsdCheck("headers_reported", True, "not reported by HSD"))
    else:
        checks.append(HsdCheck("headers_reported", headers >= 0, str(headers)))

    if blocks is not None and headers is not None:
        lag = headers - blocks
        checks.append(
            HsdCheck(
                "block_lag",
                lag <= max_block_lag,
                f"blocks={blocks} headers={headers} lag={lag} max={max_block_lag}",
            )
        )

    if ibd is None:
        checks.append(HsdCheck("initial_block_download", True, "not reported by HSD"))
    else:
        checks.append(HsdCheck("initial_block_download", ibd is False, str(ibd)))

    return checks


def hsd_is_ready(checks: list[HsdCheck]) -> bool:
    return all(check.ok for check in checks)


def _local_rpc_check(rpc_url: str, *, require_local_rpc: bool) -> HsdCheck:
    parsed = urlparse(rpc_url)
    host = parsed.hostname or ""
    if not require_local_rpc:
        return HsdCheck("rpc_local_only", True, f"not required: {host or rpc_url}")
    return HsdCheck(
        "rpc_local_only",
        host in LOCAL_RPC_HOSTS,
        host or "missing host",
    )


def _maybe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _maybe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

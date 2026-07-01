from __future__ import annotations

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
    require_local_rpc: bool = True,
) -> list[HsdCheck]:
    blocks = _maybe_int(info.get("blocks") or info.get("height"))
    headers = _maybe_int(info.get("headers"))
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

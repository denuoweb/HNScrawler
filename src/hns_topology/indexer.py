from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from . import __version__
from .classifier import classify_onchain, normalize_name, summarize_resource
from .db import (
    capture_rollback,
    init_db,
    prune_reorg_metadata,
    recompute_provider_summary,
    record_block_history,
    rollback_to_height,
    set_meta,
    upsert_name,
    upsert_resource,
)
from .hsd_rpc import HsdRpcClient
from .models import NameRecord
from .provider_rules import ProviderRules
from .timeutil import utc_now


class UnpaginatedGetNamesError(RuntimeError):
    pass


def bootstrap_from_hsd(
    conn,
    *,
    client: HsdRpcClient,
    rules: ProviderRules,
    limit: int | None = None,
    allow_unpaginated_getnames: bool = False,
) -> int:
    if limit is None and not allow_unpaginated_getnames:
        raise UnpaginatedGetNamesError(
            "HSD RPC bootstrap uses unpaginated getnames. Set --limit for a smoke run, "
            "use bootstrap-jsonl for production-scale extraction, or pass "
            "--allow-unpaginated-getnames for an intentional full getnames run."
        )
    init_db(conn)
    info = client.get_blockchain_info()
    height = int(info.get("blocks") or info.get("height") or 0)
    tip_hash = str(info.get("bestblockhash") or "")
    names = client.get_names()
    if limit is not None:
        names = names[:limit]

    indexed = 0
    now = utc_now()
    with conn:
        set_meta(conn, "generated_at", now)
        set_meta(conn, "last_indexed_height", str(height))
        set_meta(conn, "last_indexed_tip_hash", tip_hash)
        set_meta(conn, "hsd_chain", str(info.get("chain", "unknown")))
        set_meta(conn, "hsd_version", str(info.get("version", "unknown")))
        set_meta(conn, "crawler_version", __version__)
        set_meta(conn, "source_type", "hsd_rpc")
        set_meta(conn, "source_rpc_url", client.url)
        _set_provider_rule_meta(conn, rules)
        for item in names:
            name = item.get("name")
            if not name:
                continue
            resource = client.get_name_resource(str(name))
            index_one_name(conn, item, resource, rules, height=height, updated_at=now)
            indexed += 1
        recompute_provider_summary(conn, rules.provider_types, now)
    return indexed


def bootstrap_from_fixture(
    conn,
    *,
    fixture_path: str | Path,
    rules: ProviderRules,
    limit: int | None = None,
) -> int:
    init_db(conn)
    with Path(fixture_path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    height = int(data.get("height", 0))
    tip_hash = data.get("tip_hash") or _fixture_tip_hash(data)
    items = data.get("names", [])
    if limit is not None:
        items = items[:limit]

    now = utc_now()
    indexed = 0
    with conn:
        set_meta(conn, "generated_at", now)
        set_meta(conn, "last_indexed_height", str(height))
        set_meta(conn, "last_indexed_tip_hash", tip_hash)
        set_meta(conn, "hsd_chain", data.get("chain", "fixture"))
        set_meta(conn, "hsd_version", data.get("hsd_version", "fixture"))
        set_meta(conn, "crawler_version", __version__)
        set_meta(conn, "source_type", "fixture")
        set_meta(conn, "source_file", str(fixture_path))
        set_meta(conn, "source_file_hash", _file_sha256(fixture_path))
        _set_provider_rule_meta(conn, rules)
        for item in items:
            name_info = {key: value for key, value in item.items() if key != "resource"}
            resource = item.get("resource", {"records": []})
            index_one_name(conn, name_info, resource, rules, height=height, updated_at=now)
            indexed += 1
        recompute_provider_summary(conn, rules.provider_types, now)
    return indexed


def bootstrap_from_jsonl(
    conn,
    *,
    jsonl_path: str | Path,
    rules: ProviderRules,
    height: int = 0,
    tip_hash: str = "",
    chain: str = "main",
    hsd_version: str = "unknown",
    limit: int | None = None,
) -> int:
    init_db(conn)
    now = utc_now()
    indexed = 0
    digest = hashlib.sha256()
    metadata: dict[str, Any] = {}

    with conn:
        set_meta(conn, "generated_at", now)
        set_meta(conn, "last_indexed_height", str(height))
        set_meta(conn, "last_indexed_tip_hash", tip_hash)
        set_meta(conn, "hsd_chain", chain)
        set_meta(conn, "hsd_version", hsd_version)
        set_meta(conn, "crawler_version", __version__)
        set_meta(conn, "source_type", "jsonl")
        set_meta(conn, "source_file", str(jsonl_path))
        _set_provider_rule_meta(conn, rules)

        with Path(jsonl_path).open("rb") as handle:
            for raw_line in handle:
                digest.update(raw_line)
                if limit is not None and indexed >= limit:
                    continue
                line = raw_line.strip()
                if not line:
                    continue
                item = json.loads(line.decode("utf-8"))
                if "snapshot_meta" in item:
                    metadata.update(item["snapshot_meta"])
                    continue
                name_info = item.get("name_info") or {
                    key: value for key, value in item.items() if key != "resource"
                }
                resource = item.get("resource", {"records": []})
                row_height = int(metadata.get("height", height) or 0)
                index_one_name(conn, name_info, resource, rules, height=row_height, updated_at=now)
                indexed += 1

        final_height = int(metadata.get("height", height) or 0)
        set_meta(conn, "last_indexed_height", str(final_height))
        set_meta(conn, "last_indexed_tip_hash", str(metadata.get("tip_hash", tip_hash)))
        set_meta(conn, "hsd_chain", str(metadata.get("chain", chain)))
        set_meta(conn, "hsd_version", str(metadata.get("hsd_version", hsd_version)))
        set_meta(conn, "source_file_hash", digest.hexdigest())
        recompute_provider_summary(conn, rules.provider_types, now)
    return indexed


def index_changed_names(
    conn,
    *,
    client: HsdRpcClient,
    rules: ProviderRules,
    changed_names: Iterable[str],
    height: int,
    block_hash: str,
    reorg_keep_blocks: int = 300,
) -> int:
    now = utc_now()
    indexed = 0
    normalized_names = sorted({normalize_name(name) for name in changed_names if name.strip()})
    with conn:
        for name in normalized_names:
            capture_rollback(
                conn,
                height=height,
                name=name,
                block_hash=block_hash,
                captured_at=now,
            )
            name_info = client.call("getnameinfo", [name])
            resource = client.get_name_resource(name)
            index_one_name(conn, name_info | {"name": name}, resource, rules, height=height, updated_at=now)
            indexed += 1
        record_block_history(
            conn,
            height=height,
            block_hash=block_hash,
            changed_names=normalized_names,
            indexed_at=now,
        )
        set_meta(conn, "last_indexed_height", str(height))
        set_meta(conn, "last_indexed_tip_hash", block_hash)
        set_meta(conn, "generated_at", now)
        set_meta(conn, "crawler_version", __version__)
        _set_provider_rule_meta(conn, rules)
        prune_reorg_metadata(conn, reorg_keep_blocks, height)
        recompute_provider_summary(conn, rules.provider_types, now)
    return indexed


def find_reorg_mismatch(conn, *, client: HsdRpcClient) -> dict[str, Any] | None:
    rows = conn.execute(
        "SELECT height, block_hash FROM block_history ORDER BY height ASC"
    ).fetchall()
    for row in rows:
        height = int(row["height"])
        stored_hash = row["block_hash"]
        current_hash = client.get_block_hash(height)
        if current_hash != stored_hash:
            return {
                "height": height,
                "stored_hash": stored_hash,
                "current_hash": current_hash,
            }
    return None


def rollback_reorg(
    conn,
    *,
    rules: ProviderRules,
    rollback_height: int,
) -> dict[str, Any]:
    now = utc_now()
    with conn:
        result = rollback_to_height(conn, rollback_height=rollback_height, rolled_back_at=now)
        recompute_provider_summary(conn, rules.provider_types, now)
    return result


def extract_changed_names_from_block(block: dict[str, Any]) -> list[str]:
    """Best-effort extraction from decoded HSD block transaction JSON.

    HSD response shapes vary by verbosity and version. This parser only returns
    names that are already decoded as strings in covenant/name fields.
    """
    changed: set[str] = set()
    for tx in block.get("tx", []) or []:
        if not isinstance(tx, dict):
            continue
        outputs = tx.get("outputs") or tx.get("vout") or []
        for output in outputs:
            if not isinstance(output, dict):
                continue
            covenant = output.get("covenant") or {}
            candidates = [
                covenant.get("name"),
                covenant.get("nameString"),
                output.get("name"),
            ]
            for item in covenant.get("items", []) or []:
                if isinstance(item, dict):
                    candidates.extend([item.get("name"), item.get("nameString")])
            for candidate in candidates:
                if isinstance(candidate, str) and candidate:
                    changed.add(normalize_name(candidate))
    return sorted(changed)


def index_one_name(
    conn,
    name_info: dict[str, Any],
    resource: Any,
    rules: ProviderRules,
    *,
    height: int | None,
    updated_at: str,
) -> None:
    name = normalize_name(str(name_info.get("name") or ""))
    if not name:
        return
    summary = summarize_resource(name, resource)
    provider_guess = rules.match(name, summary)
    expired = _is_expired(name_info)
    onchain_class = classify_onchain(summary, expired=expired, provider_guess=provider_guess)
    record = NameRecord(
        name=name,
        name_hash=str(name_info.get("nameHash") or name_info.get("name_hash") or _fallback_name_hash(name)),
        state=name_info.get("state"),
        renewal_height=_maybe_int(name_info.get("renewal") or name_info.get("renewal_height")),
        expired=expired,
        resource_hash=summary.resource_hash,
        record_types=summary.record_types,
        onchain_class=onchain_class,
        provider_guess=provider_guess,
        last_seen_height=height,
        updated_at=updated_at,
    )
    upsert_name(conn, record)
    upsert_resource(conn, summary)


def _is_expired(name_info: dict[str, Any]) -> bool:
    if "expired" in name_info:
        return bool(name_info["expired"])
    stats = name_info.get("stats") or {}
    blocks_until_expire = stats.get("blocksUntilExpire")
    if blocks_until_expire is not None:
        try:
            return int(blocks_until_expire) <= 0
        except (TypeError, ValueError):
            return False
    state = str(name_info.get("state") or "").upper()
    return state in {"EXPIRED", "REVOKED"}


def _fallback_name_hash(name: str) -> str:
    return hashlib.blake2b(name.encode("utf-8"), digest_size=32).hexdigest()


def _maybe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _fixture_tip_hash(data: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()


def _file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _set_provider_rule_meta(conn, rules: ProviderRules) -> None:
    for key, value in rules.provenance().items():
        set_meta(conn, key, str(value))

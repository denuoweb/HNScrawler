from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .classifier import (
    classify_onchain,
    classify_onchain_fields,
    normalize_name,
    normalize_ns,
    summarize_resource,
)
from .db import (
    capture_rollback,
    init_db,
    prune_reorg_metadata,
    recompute_provider_summary,
    record_block_history,
    rollback_to_height,
    set_meta,
    upsert_name,
    upsert_name_rows,
    upsert_resource,
    upsert_resource_rows,
)
from .hsd_rpc import HsdRpcClient
from .models import NameRecord, ResourceSummary
from .provider_rules import ProviderRules
from .timeutil import utc_now


class UnpaginatedGetNamesError(RuntimeError):
    pass


@dataclass(frozen=True)
class ChangedNameExtraction:
    names: list[str]
    name_hashes: list[str]
    unresolved_name_hashes: list[str]
    name_covenant_count: int
    non_dict_tx_count: int


EMPTY_JSON_ARRAY = "[]"


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
        recompute_provider_summary(conn, rules.provider_types, now, rules.provider_patterns)
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
        recompute_provider_summary(conn, rules.provider_types, now, rules.provider_patterns)
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
    batch_size: int = 5000,
) -> int:
    init_db(conn)
    _configure_bulk_import(conn)
    batch_size = max(1, batch_size)
    now = utc_now()
    indexed = 0
    digest = hashlib.sha256()
    metadata: dict[str, Any] = {}
    compact_batch: list[dict[str, Any]] = []

    def flush_compact_batch() -> None:
        nonlocal indexed
        if not compact_batch:
            return
        row_height = int(metadata.get("height", height) or 0)
        indexed += index_compact_name_batch(
            conn,
            compact_batch,
            rules,
            height=row_height,
            updated_at=now,
        )
        compact_batch.clear()

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
                pending = indexed + len(compact_batch)
                if limit is not None and pending >= limit:
                    continue
                line = raw_line.strip()
                if not line:
                    continue
                item = json.loads(line.decode("utf-8"))
                if "snapshot_meta" in item:
                    metadata.update(item["snapshot_meta"])
                    continue
                block_history = item.get("block_history")
                if isinstance(block_history, dict):
                    record_block_history(
                        conn,
                        height=int(block_history["height"]),
                        block_hash=str(block_history["block_hash"]),
                        changed_names=_string_list(block_history.get("changed_names")),
                        indexed_at=now,
                    )
                    continue
                compact_row = item.get("compact_name")
                if isinstance(compact_row, dict):
                    compact_batch.append(compact_row)
                    if len(compact_batch) >= batch_size:
                        flush_compact_batch()
                    continue
                flush_compact_batch()
                name_info = item.get("name_info") or {
                    key: value for key, value in item.items() if key != "resource"
                }
                resource = item.get("resource", {"records": []})
                row_height = int(metadata.get("height", height) or 0)
                index_one_name(conn, name_info, resource, rules, height=row_height, updated_at=now)
                indexed += 1

        flush_compact_batch()
        final_height = int(metadata.get("height", height) or 0)
        set_meta(conn, "last_indexed_height", str(final_height))
        set_meta(conn, "last_indexed_tip_hash", str(metadata.get("tip_hash", tip_hash)))
        set_meta(conn, "hsd_chain", str(metadata.get("chain", chain)))
        set_meta(conn, "hsd_version", str(metadata.get("hsd_version", hsd_version)))
        if metadata.get("source"):
            set_meta(conn, "source_hsd_export", str(metadata["source"]))
        if metadata.get("export_format"):
            set_meta(conn, "source_jsonl_format", str(metadata["export_format"]))
        set_meta(conn, "source_file_hash", digest.hexdigest())
        recompute_provider_summary(conn, rules.provider_types, now, rules.provider_patterns)
    return indexed


def index_compact_name_batch(
    conn,
    rows: Iterable[dict[str, Any]],
    rules: ProviderRules,
    *,
    height: int | None,
    updated_at: str,
) -> int:
    name_rows: list[tuple[Any, ...]] = []
    resource_rows: list[tuple[Any, ...]] = []
    for row in rows:
        name = normalize_name(str(row.get("name") or ""))
        if not name:
            continue
        ns_names = _normalized_string_list(row.get("ns_names"))
        glue4 = _string_list(row.get("glue4"))
        glue6 = _string_list(row.get("glue6"))
        synth4 = _string_list(row.get("synth4"))
        synth6 = _string_list(row.get("synth6"))
        ds_records = _dict_list(row.get("ds_records"))
        record_types = _record_type_list(row.get("record_types"))
        has_ds = bool(row.get("has_ds")) or bool(ds_records)
        has_txt = bool(row.get("has_txt"))
        malformed = bool(row.get("malformed"))
        provider_guess = rules.match_normalized_fields(
            name,
            ns_names=ns_names,
            glue4=glue4,
            glue6=glue6,
            synth4=synth4,
            synth6=synth6,
        )
        expired = bool(row.get("expired"))
        onchain_class = classify_onchain_fields(
            record_types=record_types,
            expired=expired,
            provider_guess=provider_guess,
            has_ds=has_ds,
            has_ns=bool(ns_names),
            has_glue=bool(glue4 or glue6),
            has_synth=bool(synth4 or synth6),
            malformed=malformed,
        )
        resource_hash = str(row.get("resource_hash") or _compact_row_hash(row))
        name_rows.append(
            (
                name,
                str(row.get("name_hash") or row.get("nameHash") or _fallback_name_hash(name)),
                row.get("state"),
                _maybe_int(row.get("renewal_height") or row.get("renewal")),
                int(expired),
                resource_hash,
                _json_string_list(record_types),
                onchain_class,
                provider_guess,
                height,
                updated_at,
            )
        )
        resource_rows.append(
            (
                name,
                _json_string_list(ns_names),
                _json_string_list(glue4),
                _json_string_list(glue6),
                _json_string_list(synth4),
                _json_string_list(synth6),
                _json_list(ds_records, sort_keys=True),
                int(has_ds),
                int(has_txt),
                int(row.get("raw_size") or 0),
                resource_hash,
            )
        )

    if name_rows:
        upsert_name_rows(conn, name_rows)
        upsert_resource_rows(conn, resource_rows)
    return len(name_rows)


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
        recompute_provider_summary(conn, rules.provider_types, now, rules.provider_patterns)
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
        recompute_provider_summary(conn, rules.provider_types, now, rules.provider_patterns)
    return result


def extract_changed_name_refs_from_block(
    block: dict[str, Any],
    *,
    name_by_hash: Callable[[str], str | None] | None = None,
) -> ChangedNameExtraction:
    """Extract changed names from detailed HSD block JSON.

    HSD covenant JSON stores raw names only for some actions. Other name
    actions carry the name hash, which must be resolved through getnamebyhash.
    """
    changed: set[str] = set()
    name_hashes: set[str] = set()
    unresolved_hashes: set[str] = set()
    name_covenant_count = 0
    non_dict_tx_count = 0
    for tx in block.get("tx", []) or []:
        if not isinstance(tx, dict):
            non_dict_tx_count += 1
            continue
        outputs = tx.get("outputs") or tx.get("vout") or []
        for output in outputs:
            if not isinstance(output, dict):
                continue
            covenant = output.get("covenant") or {}
            if not isinstance(covenant, dict):
                continue
            items = covenant.get("items", []) or []
            is_name_covenant = _is_name_covenant(covenant)
            if is_name_covenant:
                name_covenant_count += 1
            candidates = [
                covenant.get("name"),
                covenant.get("nameString"),
                output.get("name"),
            ]
            raw_name_index = _raw_name_item_index(covenant)
            if raw_name_index is not None and raw_name_index < len(items):
                candidates.append(_decode_covenant_name_item(items[raw_name_index]))

            for item in items:
                if isinstance(item, dict):
                    candidates.extend([item.get("name"), item.get("nameString")])
            found_plain_name = False
            for candidate in candidates:
                if isinstance(candidate, str) and candidate:
                    changed.add(normalize_name(candidate))
                    found_plain_name = True

            if not is_name_covenant:
                continue
            name_hash = _covenant_name_hash(items)
            if name_hash is None:
                continue
            name_hashes.add(name_hash)
            if found_plain_name:
                continue
            if name_by_hash is None:
                continue
            resolved = name_by_hash(name_hash)
            if resolved:
                changed.add(normalize_name(resolved))
            else:
                unresolved_hashes.add(name_hash)
    return ChangedNameExtraction(
        names=sorted(changed),
        name_hashes=sorted(name_hashes),
        unresolved_name_hashes=sorted(unresolved_hashes),
        name_covenant_count=name_covenant_count,
        non_dict_tx_count=non_dict_tx_count,
    )


def extract_changed_names_from_block(block: dict[str, Any]) -> list[str]:
    return extract_changed_name_refs_from_block(block).names


_NAME_COVENANT_ACTIONS = {
    "CLAIM",
    "OPEN",
    "BID",
    "REVEAL",
    "REDEEM",
    "REGISTER",
    "UPDATE",
    "RENEW",
    "TRANSFER",
    "FINALIZE",
    "REVOKE",
}
_NAME_COVENANT_TYPES = set(range(1, 12))
_RAW_NAME_ITEM_INDEX_BY_ACTION = {
    "CLAIM": 2,
    "OPEN": 2,
    "BID": 2,
    "FINALIZE": 2,
}
_RAW_NAME_ITEM_INDEX_BY_TYPE = {
    1: 2,
    2: 2,
    3: 2,
    10: 2,
}


def _is_name_covenant(covenant: dict[str, Any]) -> bool:
    action = str(covenant.get("action") or "").upper()
    if action in _NAME_COVENANT_ACTIONS:
        return True
    covenant_type = _maybe_int(covenant.get("type"))
    return covenant_type in _NAME_COVENANT_TYPES


def _raw_name_item_index(covenant: dict[str, Any]) -> int | None:
    action = str(covenant.get("action") or "").upper()
    if action in _RAW_NAME_ITEM_INDEX_BY_ACTION:
        return _RAW_NAME_ITEM_INDEX_BY_ACTION[action]
    covenant_type = _maybe_int(covenant.get("type"))
    return _RAW_NAME_ITEM_INDEX_BY_TYPE.get(covenant_type)


def _decode_covenant_name_item(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return bytes.fromhex(value).decode("latin-1")
    except ValueError:
        return None


def _covenant_name_hash(items: Any) -> str | None:
    if not isinstance(items, list) or not items:
        return None
    value = items[0]
    if not isinstance(value, str):
        return None
    normalized = value.lower()
    if len(normalized) != 64:
        return None
    try:
        bytes.fromhex(normalized)
    except ValueError:
        return None
    return normalized


def _summary_from_compact_row(name: str, row: dict[str, Any]) -> ResourceSummary:
    ds_records = _dict_list(row.get("ds_records"))
    record_types = _record_type_list(row.get("record_types"))
    return ResourceSummary(
        name=name,
        ns_names=[normalize_ns(value) for value in _string_list(row.get("ns_names"))],
        glue4=_string_list(row.get("glue4")),
        glue6=_string_list(row.get("glue6")),
        synth4=_string_list(row.get("synth4")),
        synth6=_string_list(row.get("synth6")),
        ds_records=sorted(ds_records, key=lambda item: json.dumps(item, sort_keys=True)),
        has_ds=bool(row.get("has_ds")) or bool(ds_records),
        has_txt=bool(row.get("has_txt")),
        raw_size=int(row.get("raw_size") or 0),
        resource_hash=str(row.get("resource_hash") or _compact_row_hash(row)),
        record_types=record_types,
        malformed=bool(row.get("malformed")),
    )


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


def _string_list(value: Any) -> list[str]:
    if not value or not isinstance(value, list):
        return []
    if len(value) == 1:
        item = value[0]
        if item is None:
            return []
        text = str(item).strip()
        return [text] if text else []
    result = {str(item).strip() for item in value if item is not None and str(item).strip()}
    return sorted(result)


def _normalized_string_list(value: Any) -> list[str]:
    return [normalize_ns(item) for item in _string_list(value)]


def _record_type_list(value: Any) -> list[str]:
    return sorted({str(item).upper() for item in _string_list(value)})


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _json_list(value: list[Any], *, sort_keys: bool = False) -> str:
    if not value:
        return EMPTY_JSON_ARRAY
    return json.dumps(value, sort_keys=sort_keys, separators=(",", ":"), ensure_ascii=True)


def _json_string_list(value: list[str]) -> str:
    if not value:
        return EMPTY_JSON_ARRAY
    if len(value) == 1 and _plain_json_string(value[0]):
        return f'["{value[0]}"]'
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def _plain_json_string(value: str) -> bool:
    return value.isascii() and value.isprintable() and '"' not in value and "\\" not in value


def _compact_row_hash(row: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _configure_bulk_import(conn) -> None:
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA cache_size = -200000")


def _set_provider_rule_meta(conn, rules: ProviderRules) -> None:
    for key, value in rules.provenance().items():
        set_meta(conn, key, str(value))

from __future__ import annotations

import json
from typing import Any


def dumps_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def dumps_pretty(value: Any) -> str:
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def loads_json_list(value: str | None) -> list:
    if not value:
        return []
    parsed = json.loads(value)
    if isinstance(parsed, list):
        return parsed
    return []


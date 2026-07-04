from __future__ import annotations

import base64
import itertools
import json
import os
import urllib.error
import urllib.request
from typing import Any


class HsdRpcError(RuntimeError):
    """Raised when an hsd JSON-RPC request fails."""


class HsdRpcClient:
    def __init__(self, url: str, api_key: str | None = None, timeout: int = 60):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._ids = itertools.count(1)

    @classmethod
    def from_env(cls) -> HsdRpcClient:
        return cls(
            os.environ.get("HSD_RPC_URL", "http://127.0.0.1:12037"),
            os.environ.get("HSD_API_KEY"),
            int(os.environ.get("HSD_RPC_TIMEOUT", "60")),
        )

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": next(self._ids),
            "method": method,
            "params": params or [],
        }
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if self.api_key:
            token = base64.b64encode(f"x:{self.api_key}".encode()).decode("ascii")
            request.add_header("Authorization", f"Basic {token}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise HsdRpcError(f"HSD RPC request failed for {method}: {exc}") from exc
        if data.get("error"):
            raise HsdRpcError(f"HSD RPC error for {method}: {data['error']}")
        return data.get("result")

    def get_blockchain_info(self) -> dict[str, Any]:
        return self.call("getblockchaininfo")

    def get_names(self) -> list[dict[str, Any]]:
        result = self.call("getnames")
        if not isinstance(result, list):
            raise HsdRpcError("getnames returned a non-list result")
        return result

    def get_name_resource(self, name: str) -> dict[str, Any]:
        result = self.call("getnameresource", [name])
        if result is None:
            return {"records": []}
        if not isinstance(result, dict):
            raise HsdRpcError(f"getnameresource returned non-object for {name}")
        return result

    def get_block_hash(self, height: int) -> str:
        result = self.call("getblockhash", [height])
        if not isinstance(result, str):
            raise HsdRpcError(f"getblockhash returned non-string for height {height}")
        return result

    def get_block_by_height(self, height: int, details: bool = True) -> dict[str, Any]:
        result = self.call("getblockbyheight", [height, True, details])
        if not isinstance(result, dict):
            raise HsdRpcError(f"getblockbyheight returned non-object for height {height}")
        return result

    def get_name_by_hash(self, name_hash: str) -> str | None:
        result = self.call("getnamebyhash", [name_hash])
        if result is None:
            return None
        if not isinstance(result, str):
            raise HsdRpcError(f"getnamebyhash returned non-string for hash {name_hash}")
        return result

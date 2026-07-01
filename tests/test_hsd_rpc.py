from hns_topology.hsd_rpc import HsdRpcClient


class CapturingHsdClient(HsdRpcClient):
    def __init__(self):
        super().__init__("http://127.0.0.1:12037")
        self.calls = []

    def call(self, method, params=None):
        self.calls.append((method, params or []))
        if method == "getblockbyheight":
            return {"hash": "block-hash", "tx": []}
        if method == "getnamebyhash":
            return "example"
        raise AssertionError(f"unexpected method: {method}")


def test_get_block_by_height_requests_detailed_transactions():
    client = CapturingHsdClient()

    assert client.get_block_by_height(123) == {"hash": "block-hash", "tx": []}
    assert client.calls == [("getblockbyheight", [123, True, True])]


def test_get_name_by_hash_returns_name():
    client = CapturingHsdClient()

    assert client.get_name_by_hash("00" * 32) == "example"
    assert client.calls == [("getnamebyhash", ["00" * 32])]

from hns_topology.hsd_rpc import HsdRpcClient
from hns_topology.hsd_status import evaluate_hsd_readiness, hsd_is_ready


def test_hsd_rpc_env_default_uses_mainnet_port(monkeypatch):
    monkeypatch.delenv("HSD_RPC_URL", raising=False)
    monkeypatch.delenv("HSD_API_KEY", raising=False)
    monkeypatch.delenv("HSD_RPC_TIMEOUT", raising=False)

    client = HsdRpcClient.from_env()

    assert client.url == "http://127.0.0.1:12037"


def test_hsd_readiness_accepts_synced_local_node():
    checks = evaluate_hsd_readiness(
        {
            "chain": "main",
            "blocks": 100,
            "headers": 101,
            "bestblockhash": "00ab",
            "initialblockdownload": False,
        },
        rpc_url="http://127.0.0.1:12037",
        max_block_lag=2,
    )

    assert hsd_is_ready(checks)


def test_hsd_readiness_rejects_remote_or_unsynced_node():
    checks = evaluate_hsd_readiness(
        {
            "chain": "main",
            "blocks": 100,
            "headers": 120,
            "bestblockhash": "00ab",
            "initialblockdownload": True,
        },
        rpc_url="http://203.0.113.10:12037",
        max_block_lag=2,
    )

    failed = {check.name for check in checks if not check.ok}
    assert not hsd_is_ready(checks)
    assert failed == {"rpc_local_only", "block_lag", "initial_block_download"}


def test_hsd_readiness_can_allow_remote_rpc_explicitly():
    checks = evaluate_hsd_readiness(
        {
            "chain": "main",
            "blocks": 100,
            "headers": 100,
            "bestblockhash": "00ab",
            "initialblockdownload": False,
        },
        rpc_url="http://203.0.113.10:12037",
        require_local_rpc=False,
    )

    assert hsd_is_ready(checks)


def test_hsd_readiness_rejects_shallow_mainnet_height():
    checks = evaluate_hsd_readiness(
        {
            "chain": "main",
            "blocks": 4578,
            "headers": 4578,
            "bestblockhash": "00ab",
        },
        rpc_url="http://127.0.0.1:12037",
        min_block_height=300000,
    )

    failed = {check.name for check in checks if not check.ok}
    assert not hsd_is_ready(checks)
    assert "minimum_block_height" in failed

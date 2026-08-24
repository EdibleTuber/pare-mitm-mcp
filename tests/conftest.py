import pytest
from pare_mitm_mcp.daemon.store import FlowStore, RuleStore
from pare_mitm_mcp.daemon.control import ControlServer


def seed(store: FlowStore) -> None:
    store.add({"ts": 1.0, "kind": "flow", "method": "GET", "host": "api.example.com",
               "path": "/ping", "scheme": "https", "status": 200,
               "content_type": "application/json", "resp_size": 2, "error": None,
               "req_headers": {"Host": "api.example.com"}, "req_body": "",
               "resp_headers": {"Content-Type": "application/json"}, "resp_body": "{}"})
    store.add({"ts": 2.0, "kind": "error", "method": None, "host": "pin.example.com",
               "path": "", "scheme": "https", "status": None, "content_type": None,
               "resp_size": 0, "error": "TLS handshake failed",
               "req_headers": {}, "req_body": "", "resp_headers": {}, "resp_body": ""})


@pytest.fixture
def control():
    store = FlowStore()
    rule_store = RuleStore()
    seed(store)
    srv = ControlServer(store, rule_store, host="127.0.0.1", port=0)  # port 0 = ephemeral
    srv.start()
    try:
        yield srv, store
    finally:
        srv.stop()

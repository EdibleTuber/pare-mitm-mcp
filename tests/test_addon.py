from types import SimpleNamespace
from pare_mitm_mcp.daemon.addon import (
    record_from_flow,
    record_from_error,
    record_from_tls_failure,
)
from pare_mitm_mcp.daemon.store import FlowStore


def _fake_flow():
    req = SimpleNamespace(method="POST", host="api.example.com", path="/login",
                          scheme="https", headers={"Host": "api.example.com"},
                          get_text=lambda strict=False: '{"u":"a"}')
    resp = SimpleNamespace(status_code=200, headers={"Content-Type": "application/json"},
                           get_text=lambda strict=False: '{"tok":"z"}',
                           raw_content=b'{"tok":"z"}')
    return SimpleNamespace(request=req, response=resp, error=None)


def test_record_from_flow_maps_fields():
    r = record_from_flow(_fake_flow())
    assert r["kind"] == "flow"
    assert r["method"] == "POST" and r["host"] == "api.example.com"
    assert r["status"] == 200 and r["content_type"] == "application/json"
    assert r["resp_body"] == '{"tok":"z"}'
    assert r["resp_size"] == len(b'{"tok":"z"}')


def test_record_from_error_is_error_kind():
    f = _fake_flow()
    f.response = None
    f.error = SimpleNamespace(msg="TLS handshake failed")
    r = record_from_error(f)
    assert r["kind"] == "error" and "TLS" in r["error"]
    assert r["status"] is None


def _fake_tls_data(*, sni="pinned.example.com", error="certificate verify failed",
                    server_address=("1.2.3.4", 443)):
    conn = SimpleNamespace(error=error, sni=sni, peername=("10.0.0.1", 54321))
    server = SimpleNamespace(address=server_address)
    client = SimpleNamespace(address=("10.0.0.1", 54321))
    context = SimpleNamespace(client=client, server=server)
    return SimpleNamespace(conn=conn, context=context)


_ERROR_RECORD_KEYS = {
    "ts", "kind", "method", "host", "path", "scheme", "status", "content_type",
    "resp_size", "error", "req_headers", "req_body", "resp_headers", "resp_body",
}


def test_record_from_tls_failure_client_side_pinning():
    data = _fake_tls_data(sni="pinned.example.com", error="certificate verify failed")
    r = record_from_tls_failure(data, "client")
    assert set(r.keys()) == _ERROR_RECORD_KEYS
    assert r["kind"] == "error"
    assert r["method"] is None
    assert r["status"] is None
    assert r["content_type"] is None
    assert r["resp_size"] == 0
    assert r["scheme"] == "https"
    assert r["path"] == ""
    assert r["req_headers"] == {} and r["resp_headers"] == {}
    assert r["req_body"] == "" and r["resp_body"] == ""
    assert r["host"] == "pinned.example.com"
    assert "client" in r["error"]
    assert "certificate verify failed" in r["error"]


def test_record_from_tls_failure_host_falls_back_to_server_address():
    data = _fake_tls_data(sni=None, server_address=("upstream.example.com", 443))
    r = record_from_tls_failure(data, "client")
    assert r["host"] == "upstream.example.com"


def test_record_from_tls_failure_degrades_gracefully_no_error_no_address():
    conn = SimpleNamespace(error=None, sni=None, peername=None)
    server = SimpleNamespace(address=None)
    client = SimpleNamespace(address=None)
    context = SimpleNamespace(client=client, server=server)
    data = SimpleNamespace(conn=conn, context=context)
    r = record_from_tls_failure(data, "client")
    assert r["host"] == ""
    assert r["kind"] == "error"
    assert isinstance(r["error"], str) and r["error"]


def test_record_from_tls_failure_missing_context_attrs_no_raise():
    # No context at all, no conn.error attribute either.
    conn = SimpleNamespace()
    data = SimpleNamespace(conn=conn, context=SimpleNamespace())
    r = record_from_tls_failure(data, "server")
    assert r["host"] == ""
    assert r["kind"] == "error"
    assert "server" in r["error"]


def test_record_from_tls_failure_server_side_distinguishable():
    data = _fake_tls_data(sni="upstream.example.com", error="handshake failure")
    client_r = record_from_tls_failure(data, "client")
    server_r = record_from_tls_failure(data, "server")
    assert "client" in client_r["error"]
    assert "server" in server_r["error"]
    assert client_r["error"] != server_r["error"]


def test_tls_failure_record_increments_store_tls_errors():
    store = FlowStore()
    data = _fake_tls_data()
    store.add(record_from_tls_failure(data, "client"))
    health = store.health()
    assert health["tls_errors"] == 1
    assert health["flows"] == 1

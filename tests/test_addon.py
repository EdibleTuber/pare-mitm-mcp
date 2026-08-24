from types import SimpleNamespace
from pare_mitm_mcp.daemon.addon import (
    PareAddon,
    record_from_flow,
    record_from_error,
    record_from_tls_failure,
)
from pare_mitm_mcp.daemon.store import FlowStore, InterceptionRule


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


def _fake_mutable_flow(req_body='{"u":"a","keep":"me"}', resp_body='{"tok":"z","keep":"me"}'):
    def _message(headers, body, status_code=None):
        state = {"text": body}
        msg = SimpleNamespace(
            headers=dict(headers),
            get_text=lambda strict=False: state["text"],
            set_text=lambda text: state.__setitem__("text", text),
            raw_content=body.encode(),
        )
        if status_code is not None:
            msg.status_code = status_code
        return msg

    req = _message({"Host": "api.example.com", "Content-Type": "application/json"}, req_body)
    req.method = "POST"
    req.host = "api.example.com"
    req.path = "/login"
    req.scheme = "https"

    resp = _message({"Content-Type": "application/json"}, resp_body, status_code=200)

    flow = SimpleNamespace(request=req, response=resp, error=None, killed=False)
    flow.kill = lambda: setattr(flow, "killed", True)
    return flow


def _addon_with_rule(rule: InterceptionRule) -> PareAddon:
    addon = PareAddon()
    addon.rule_store.add(rule)
    return addon


def test_response_body_modification_substitutes_match_not_whole_body():
    rule = InterceptionRule(rule_id="", action="MODIFY", scope="resp_body",
                             pattern=r'"tok":"[^"]*"', target="resp_body",
                             replacement='"tok":"REDACTED"')
    addon = _addon_with_rule(rule)
    flow = _fake_mutable_flow()

    addon.response(flow)

    assert flow.response.get_text() == '{"tok":"REDACTED","keep":"me"}'


def test_request_body_modification_substitutes_match_not_whole_body():
    rule = InterceptionRule(rule_id="", action="MODIFY", scope="req_body",
                             pattern=r'"u":"[^"]*"', target="req_body",
                             replacement='"u":"REDACTED"')
    addon = _addon_with_rule(rule)
    flow = _fake_mutable_flow()

    addon.request(flow)

    assert flow.request.get_text() == '{"u":"REDACTED","keep":"me"}'


def test_status_rule_with_non_numeric_replacement_does_not_crash_flow_processing():
    rule = InterceptionRule(rule_id="", action="MODIFY", scope="host",
                             pattern="api", target="status",
                             replacement="403 Forbidden")
    addon = _addon_with_rule(rule)
    flow = _fake_mutable_flow()

    addon.response(flow)  # must not raise

    assert addon.store.health()["flows"] == 1


def test_invalid_regex_rule_does_not_crash_request_processing():
    rule = InterceptionRule(rule_id="", action="MODIFY", scope="host",
                             pattern="(", target="req_headers",
                             header_name="X-Foo", replacement="bar")
    addon = _addon_with_rule(rule)
    flow = _fake_mutable_flow()

    addon.request(flow)  # must not raise

    assert flow.killed is False

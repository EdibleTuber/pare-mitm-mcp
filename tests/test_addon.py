from types import SimpleNamespace
from pare_mitm_mcp.daemon.addon import record_from_flow, record_from_error


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

import json
import urllib.request


def _get(url):
    with urllib.request.urlopen(url, timeout=2) as r:
        return json.loads(r.read().decode())


def test_health(control):
    srv, _ = control
    h = _get(f"{srv.url}/health")
    assert h["flows"] == 2 and h["tls_errors"] == 1


def test_flows_and_filters(control):
    srv, _ = control
    allf = _get(f"{srv.url}/flows")
    assert len(allf) == 2
    only = _get(f"{srv.url}/flows?host=api.example.com")
    assert len(only) == 1 and only[0]["host"] == "api.example.com"


def test_flow_detail_and_404(control):
    srv, _ = control
    rows = _get(f"{srv.url}/flows")
    fid = [r for r in rows if r["kind"] == "flow"][0]["id"]
    detail = _get(f"{srv.url}/flow/{fid}")
    assert detail["resp_body"] == "{}"
    import urllib.error
    try:
        _get(f"{srv.url}/flow/zzzz")
        assert False, "expected 404"
    except urllib.error.HTTPError as e:
        assert e.code == 404


def test_search(control):
    srv, _ = control
    hits = _get(f"{srv.url}/search?pattern=example.com&scope=url")
    assert len(hits) == 2

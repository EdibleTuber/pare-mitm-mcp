import json
import pytest
from pare_mitm_mcp import tools


@pytest.fixture
def wired(control, monkeypatch):
    srv, store = control
    # point the tools' client at the ephemeral control server
    monkeypatch.setattr(tools, "_client", lambda: __import__(
        "pare_mitm_mcp.client", fromlist=["DaemonClient"]).DaemonClient(srv.url))
    return srv, store


async def test_capture_health(wired):
    out = json.loads(await tools.capture_health())
    assert out.get("error") is not True
    assert out["reachable"] is True and out["flows"] == 2 and out["tls_errors"] == 1


async def test_list_flows_includes_error_rows(wired):
    out = json.loads(await tools.list_flows())
    assert out.get("error") is not True
    kinds = {r["kind"] for r in out["rows"]}
    assert "error" in kinds and "flow" in kinds


async def test_get_flow_detail(wired):
    rows = json.loads(await tools.list_flows())["rows"]
    fid = [r for r in rows if r["kind"] == "flow"][0]["id"]
    out = json.loads(await tools.get_flow(fid))
    assert out.get("error") is not True and out["flow"]["resp_body"] == "{}"


async def test_get_flow_missing_is_error(wired):
    out = json.loads(await tools.get_flow("zzzz"))
    assert out["error"] is True


async def test_search_flows(wired):
    out = json.loads(await tools.search_flows("example.com", "url"))
    assert out.get("error") is not True and len(out["hits"]) == 2


async def test_search_flows_bad_regex_returns_error_envelope(wired):
    out = json.loads(await tools.search_flows("("))
    assert out["error"] is True


async def test_list_flows_bad_status_filter_returns_error_envelope(wired):
    # a non-integer status the control server can't parse triggers a 400
    out = json.loads(await tools.list_flows(status="not-a-number"))
    assert out["error"] is True


async def test_daemon_down_returns_reachable_false_and_error_envelope(monkeypatch):
    # capture_health reports reachable:false (not an error) when the daemon is down
    from pare_mitm_mcp.client import DaemonClient
    monkeypatch.setattr(tools, "_client", lambda: DaemonClient("http://127.0.0.1:1", timeout=0.3))
    health = json.loads(await tools.capture_health())
    assert health["reachable"] is False
    # the data tools return the daemon-not-reachable error envelope
    listed = json.loads(await tools.list_flows())
    assert listed["error"] is True and "not reachable" in listed["summary"].lower()

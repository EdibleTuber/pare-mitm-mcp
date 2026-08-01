import pytest
from pare_mitm_mcp.client import DaemonClient, DaemonUnreachable


def test_client_health_and_flows(control):
    srv, _ = control
    c = DaemonClient(srv.url)
    assert c.health()["flows"] == 2
    assert len(c.flows(host="api.example.com")) == 1


def test_client_flow_detail_and_missing(control):
    srv, _ = control
    c = DaemonClient(srv.url)
    fid = [r for r in c.flows() if r["kind"] == "flow"][0]["id"]
    assert c.flow(fid)["resp_body"] == "{}"
    assert c.flow("zzzz") is None


def test_client_unreachable_raises():
    c = DaemonClient("http://127.0.0.1:1", timeout=0.3)  # nothing listening
    with pytest.raises(DaemonUnreachable):
        c.health()

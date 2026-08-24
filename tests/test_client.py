import pytest
from pare_mitm_mcp.client import DaemonClient, DaemonError, DaemonUnreachable


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


def test_client_search_bad_regex_raises_daemon_error(control):
    srv, _ = control
    c = DaemonClient(srv.url)
    with pytest.raises(DaemonError):
        c.search("(")


def test_client_add_modification_rule_succeeds(control):
    srv, _ = control
    c = DaemonClient(srv.url)
    rid = c.add_rule("modify", scope="host", pattern="foo",
                      target="req_headers", replacement="bar", header_name="X-Foo")
    assert rid.startswith("rule_")


def test_client_add_blocking_rule_succeeds(control):
    srv, _ = control
    c = DaemonClient(srv.url)
    rid = c.add_rule("block", scope="host", pattern="foo")
    assert rid.startswith("rule_")


def test_client_add_modification_rule_rejects_invalid_regex(control):
    srv, _ = control
    c = DaemonClient(srv.url)
    with pytest.raises(DaemonError):
        c.add_rule("modify", scope="host", pattern="(", target="req_headers",
                    header_name="X-Foo", replacement="bar")
    assert c.rules() == []


def test_client_add_blocking_rule_rejects_invalid_regex(control):
    srv, _ = control
    c = DaemonClient(srv.url)
    with pytest.raises(DaemonError):
        c.add_rule("block", scope="host", pattern="(")
    assert c.rules() == []
